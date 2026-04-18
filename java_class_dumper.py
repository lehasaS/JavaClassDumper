#!/usr/bin/env python3
"""
Parse .java imports, transform selected imports into .class paths,
and download those class files from a target base URL.

Example mapping:
  import com.application.utils.Debug;
  -> /classes/com/application/utils/Debug.class
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import re
import ssl
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, TypedDict
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

def banner():
    banner = r"""
      _                   ____ _               
     | | __ ___   ____ _ / ___| | __ _ ___ ___ 
  _  | |/ _` \ \ / / _` | |   | |/ _` / __/ __|
 | |_| | (_| |\ V / (_| | |___| | (_| \__ \__ \
  \___/ \__,_| \_/ \__,_|\____|_|\__,_|___/___/
 |  _ \ _   _ _ __ ___  _ __   ___ _ __        
 | | | | | | | '_ ` _ \| '_ \ / _ \ '__|       
 | |_| | |_| | | | | | | |_) |  __/ |          
 |____/ \__,_|_| |_| |_| .__/ \___|_|          
                       |_|               
                    by 0xHasi
                """
    return banner


IMPORT_RE = re.compile(r"^\s*import\s+(static\s+)?([A-Za-z_][\w$]*(?:\.[\w$*]+)+)\s*;\s*$")
INLINE_COMMENT_RE = re.compile(r"//.*$")
BLOCK_COMMENT_INLINE_RE = re.compile(r"/\*.*?\*/")
CFR_MISSING_HEADER_RE = re.compile(r"Could not load the following classes:")
CFR_MISSING_CLASS_RE = re.compile(r"^\s*\*\s+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)\s*$")
CLASS_NAME_RE = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$")

DEPLOYMENT_CLASS_TAGS = {
    "servlet-class",
    "filter-class",
    "listener-class",
    "ejb-class",
    "home",
    "remote",
    "local-home",
    "local",
    "service-endpoint",
    "run-as-principal-name",
}

DEFAULT_STANDARD_PREFIXES = [
    "java.",
    "javax.",
    "jakarta.",
    "sun.",
    "com.sun.",
    "org.w3c.",
    "org.xml.",
]

DEFAULT_WILDCARD_SUFFIX_GUESSES = [
    "Config",
    "Configuration",
    "Constants",
    "Util",
    "Utils",
    "Service",
    "Manager",
    "Controller",
    "Handler",
    "Factory",
    "Helper",
    "VersionInfo",
    "BuildInfo",
    "SecurityUtil",
    "AuthUtil",
]

USER_AGENT = "Mozilla/5.0 (compatible; ImportsClassFetcher/1.0; +security-assessment)"
COLOR_ENABLED = False


class Ansi:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[32m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"


def supports_color(no_color: bool = False) -> bool:
    if no_color or os.environ.get("NO_COLOR") is not None:
        return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def colorize(text: str, *codes: str) -> str:
    if not COLOR_ENABLED or not codes:
        return text
    return "".join(codes) + text + Ansi.RESET


def tag_info() -> str:
    return "[i]"


def tag_ok() -> str:
    return "[+]"


def tag_warn() -> str:
    return "[-]"


def tag_skip() -> str:
    return "[=]"

@dataclass
class DownloadResult:
    url: str
    status: Optional[int]
    error: Optional[str] = None


class FailedEntry(TypedDict):
    url: str
    error: str
    status: Optional[int]
    ts: str


@dataclass
class FetchReport:
    started_at: str
    java_root: str
    base_url: str
    class_root: str
    output_dir: str
    java_files_scanned: int = 0
    imports_found: int = 0
    imports_selected: int = 0
    wildcard_imports_skipped: int = 0
    wildcard_packages_seen: int = 0
    wildcard_classes_generated: int = 0
    resume_report_path: str = ""
    resume_scope_mismatch_ignored: bool = False
    resumed_preloaded_count: int = 0
    skipped_already_downloaded: int = 0
    resumed_failed_count: int = 0
    skipped_previous_failures: int = 0
    attempted_urls: List[str] = field(default_factory=list)
    downloaded_files: List[str] = field(default_factory=list)
    new_downloaded_files: List[str] = field(default_factory=list)
    failed_urls: List[FailedEntry] = field(default_factory=list)
    new_failed_urls: List[FailedEntry] = field(default_factory=list)
    selected_imports: List[str] = field(default_factory=list)
    auto_passes_completed: int = 0
    skipped_failed_this_run: int = 0
    decompile_enabled: bool = False
    cfr_jar_path: str = ""
    decompiled_dir: str = ""
    decompiled_inputs_count: int = 0
    decompile_runs: int = 0
    cfr_missing_classes_total: int = 0
    cfr_missing_classes_new: int = 0
    cfr_missing_classes_added: List[str] = field(default_factory=list)
    cfr_seed_classes_from_java_root: int = 0
    local_class_seed_count: int = 0
    descriptor_xml_scanned: int = 0
    descriptor_classes_seeded: int = 0
    decompiled_class_inputs: List[str] = field(default_factory=list)


def normalize_base_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid base URL: {base_url}")
    return base_url if base_url.endswith("/") else base_url + "/"


def parse_imports(java_text: str) -> List[Tuple[bool, str]]:
    out: List[Tuple[bool, str]] = []
    for line in java_text.splitlines():
        # Handle trailing comments on import lines.
        line = INLINE_COMMENT_RE.sub("", line)
        line = BLOCK_COMMENT_INLINE_RE.sub("", line)
        m = IMPORT_RE.match(line)
        if not m:
            continue
        is_static = bool(m.group(1))
        name = m.group(2).strip()
        out.append((is_static, name))
    return out


def is_standard(name: str, standard_prefixes: Sequence[str]) -> bool:
    return any(name.startswith(pfx) for pfx in standard_prefixes)


def in_include_prefixes(name: str, include_prefixes: Sequence[str]) -> bool:
    if not include_prefixes:
        return True
    return any(name.startswith(pfx) for pfx in include_prefixes)


def import_to_class_name(is_static: bool, import_name: str) -> Optional[str]:
    # Non-static wildcard imports (e.g., foo.bar.*) do not identify a class.
    if not is_static and import_name.endswith(".*"):
        return None

    if is_static:
        # import static foo.Bar.BAZ;  => foo.Bar
        # import static foo.Bar.*;    => foo.Bar
        if import_name.endswith(".*"):
            base = import_name[:-2]
        else:
            parts = import_name.split(".")
            if len(parts) < 2:
                return None
            base = ".".join(parts[:-1])
        if not base:
            return None
        return base

    # Regular class import
    if import_name.endswith(".*"):
        return None
    return import_name


def class_name_to_rel_paths(class_name: str, class_root: str) -> List[str]:
    """
    Return possible .class relative paths for a class reference.

    Handles:
    - top-level classes: a.b.Foo -> a/b/Foo.class
    - inner classes often imported as a.b.Outer.Inner -> a/b/Outer$Inner.class
    """
    root = class_root.strip("/")
    class_name = class_name.strip().strip(".")
    if not class_name:
        return []

    parts = [p for p in class_name.split(".") if p]
    if not parts:
        return []

    # Find first likely class segment (Java convention: starts uppercase).
    first_cls_idx = -1
    for i, seg in enumerate(parts):
        if seg[:1].isupper():
            first_cls_idx = i
            break

    # Fallback when conventions are not followed.
    if first_cls_idx < 0:
        first_cls_idx = max(0, len(parts) - 1)

    pkg_parts = parts[:first_cls_idx]
    cls_parts = parts[first_cls_idx:]
    if not cls_parts:
        cls_parts = [parts[-1]]
        pkg_parts = parts[:-1]

    candidates: Set[str] = set()

    # Dotted path interpretation (works for top-level imports).
    dotted_cls = "/".join(parts) + ".class"
    candidates.add(dotted_cls)

    # Inner-class interpretation: Outer$Inner$Nested.class
    if len(cls_parts) >= 2:
        inner_cls = "/".join(pkg_parts + [cls_parts[0] + "$" + "$".join(cls_parts[1:])]) + ".class"
        candidates.add(inner_cls)

    # If class already contains '$', preserve it directly.
    if "$" in class_name:
        candidates.add(class_name.replace(".", "/") + ".class")

    out = []
    for cls_rel in sorted(candidates):
        out.append(f"{root}/{cls_rel}" if root else cls_rel)
    return out


def fetch_url(url: str, timeout: float, ssl_context: ssl.SSLContext) -> DownloadResult:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=timeout, context=ssl_context) as resp:
            status = getattr(resp, "status", 200)
            if status != 200:
                return DownloadResult(url=url, status=status, error=f"HTTP {status}")
            return DownloadResult(url=resp.geturl(), status=status)
    except HTTPError as e:
        return DownloadResult(url=url, status=e.code, error=f"HTTP {e.code}")
    except URLError as e:
        return DownloadResult(url=url, status=None, error=f"URL error: {e.reason}")
    except Exception as e:
        return DownloadResult(url=url, status=None, error=f"Error: {e}")


def fetch_bytes(url: str, timeout: float, ssl_context: ssl.SSLContext) -> Tuple[Optional[bytes], DownloadResult]:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=timeout, context=ssl_context) as resp:
            status = getattr(resp, "status", 200)
            if status != 200:
                return None, DownloadResult(url=url, status=status, error=f"HTTP {status}")
            return resp.read(), DownloadResult(url=resp.geturl(), status=status)
    except HTTPError as e:
        return None, DownloadResult(url=url, status=e.code, error=f"HTTP {e.code}")
    except URLError as e:
        return None, DownloadResult(url=url, status=None, error=f"URL error: {e.reason}")
    except Exception as e:
        return None, DownloadResult(url=url, status=None, error=f"Error: {e}")


def should_retry_failure(res: DownloadResult) -> bool:
    if res.status in {408, 425, 429, 500, 502, 503, 504}:
        return True
    if res.status is None:
        err = (res.error or "").lower()
        transient_markers = ["timed out", "temporary", "temporarily", "connection reset", "connection aborted", "network is unreachable"]
        return any(m in err for m in transient_markers)
    return False


def is_hard_failure(status: Optional[int], error: str) -> bool:
    # Failures that are unlikely to become successful on immediate reruns.
    if status in {400, 401, 403, 404, 405, 410}:
        return True
    err = (error or "").lower()
    if "certificate verify failed" in err:
        return True
    return False


def fetch_bytes_with_retry(
    url: str,
    timeout: float,
    ssl_context: ssl.SSLContext,
    retries: int,
    retry_backoff: float,
) -> Tuple[Optional[bytes], DownloadResult]:
    attempts = max(1, retries + 1)
    last_data: Optional[bytes] = None
    last_res = DownloadResult(url=url, status=None, error="Unknown error")
    for i in range(attempts):
        data, res = fetch_bytes(url, timeout, ssl_context)
        if data is not None and res.status == 200:
            return data, res
        last_data, last_res = data, res
        if i < attempts - 1 and should_retry_failure(res):
            if retry_backoff > 0:
                time.sleep(retry_backoff * (2 ** i))
            continue
        break
    return last_data, last_res


def build_ssl_context(insecure: bool, ca_file: str) -> ssl.SSLContext:
    if insecure:
        return ssl._create_unverified_context()
    if ca_file:
        return ssl.create_default_context(cafile=ca_file)
    return ssl.create_default_context()


def collect_java_files(root: Path) -> List[Path]:
    if root.is_file() and root.suffix.lower() == ".java":
        return [root]
    if not root.exists():
        return []
    return sorted(p for p in root.rglob("*.java") if p.is_file())


def collect_class_files(root: Path) -> List[Path]:
    if root.is_file() and root.suffix.lower() == ".class":
        return [root]
    if not root.exists():
        return []
    return sorted(p for p in root.rglob("*.class") if p.is_file())


def local_tag_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def discover_classes_from_deployment_descriptors(root: Path, max_size_bytes: int = 8 * 1024 * 1024) -> Tuple[int, Set[str]]:
    out: Set[str] = set()
    scanned = 0
    if not root.exists():
        return scanned, out

    xml_files: List[Path] = []
    if root.is_file() and root.suffix.lower() == ".xml":
        xml_files = [root]
    elif root.is_dir():
        xml_files = sorted(p for p in root.rglob("*.xml") if p.is_file())

    for xml_file in xml_files:
        try:
            if xml_file.stat().st_size > max_size_bytes:
                continue
        except Exception:
            continue

        try:
            tree = ET.parse(xml_file)
        except Exception:
            continue
        scanned += 1
        root_elem = tree.getroot()
        for elem in root_elem.iter():
            tag = local_tag_name(str(elem.tag)).strip().lower()
            if tag not in DEPLOYMENT_CLASS_TAGS:
                continue
            text = (elem.text or "").strip()
            if not text:
                continue
            if not CLASS_NAME_RE.match(text):
                continue
            out.add(text)

    return scanned, out


def normalize_downloaded_entry(entry: str) -> Optional[str]:
    s = (entry or "").strip().replace("\\", "/")
    if not s:
        return None
    if s.startswith("mirror/"):
        s = s[len("mirror/") :]
    elif "/mirror/" in s:
        s = s.split("/mirror/", 1)[1]
    else:
        s = s.lstrip("/")
    if not s:
        return None
    return s


def load_report_doc(report_path: Path) -> Optional[Dict[str, Any]]:
    if not report_path.exists():
        return None
    try:
        doc = json.loads(report_path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None
    return doc


def norm_url_loose(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return ""
    try:
        p = urlparse(v)
        if p.scheme and p.netloc:
            path = p.path or "/"
            if not path.endswith("/"):
                path += "/"
            return f"{p.scheme}://{p.netloc}{path}"
    except Exception:
        pass
    return v.rstrip("/") + "/"


def resume_scope_matches(doc: Optional[Dict[str, Any]], base_url: str, class_root: str) -> bool:
    if not doc:
        return True
    old_base = norm_url_loose(str(doc.get("base_url", "")))
    old_root = str(doc.get("class_root", "")).strip()
    if old_base and old_base != norm_url_loose(base_url):
        return False
    if old_root and old_root != class_root:
        return False
    return True


def load_previously_downloaded_from_report(doc: Optional[Dict[str, Any]]) -> Set[str]:
    out: Set[str] = set()
    if not isinstance(doc, dict):
        return out
    files = doc.get("downloaded_files", [])
    if not isinstance(files, list):
        return out
    for entry in files:
        if not isinstance(entry, str):
            continue
        norm = normalize_downloaded_entry(entry)
        if norm:
            out.add(norm)
    return out


def load_previously_decompiled_inputs(doc: Optional[Dict[str, Any]]) -> Set[str]:
    out: Set[str] = set()
    if not isinstance(doc, dict):
        return out
    files = doc.get("decompiled_class_inputs", [])
    if not isinstance(files, list):
        return out
    for entry in files:
        if not isinstance(entry, str):
            continue
        norm = normalize_downloaded_entry(entry)
        if norm and norm.endswith(".class"):
            out.add(norm)
    return out


def load_existing_mirror_files(mirror_dir: Path) -> Set[str]:
    out: Set[str] = set()
    if not mirror_dir.exists():
        return out
    for p in mirror_dir.rglob("*"):
        if p.is_file():
            out.add(p.relative_to(mirror_dir).as_posix())
    return out


def rel_from_base_url(base_url: str, url: str) -> Optional[str]:
    try:
        b = urlparse(base_url)
        u = urlparse(url)
    except Exception:
        return None

    if not u.path:
        return None

    path = u.path.lstrip("/")
    if not path:
        return None

    # Prefer host+base-path-relative mapping when possible.
    if b.scheme and b.netloc and u.scheme and u.netloc and (b.scheme, b.netloc) == (u.scheme, u.netloc):
        bpath = b.path or "/"
        if not bpath.endswith("/"):
            bpath += "/"
        if u.path.startswith(bpath):
            rel = u.path[len(bpath) :].lstrip("/")
            return rel or None

    return path


def load_previously_failed_from_report(
    doc: Optional[Dict[str, Any]],
    base_url: str,
    failure_mode: str,
) -> Tuple[Set[str], Set[str], List[FailedEntry]]:
    failed_urls: Set[str] = set()
    failed_rel: Set[str] = set()
    entries: List[FailedEntry] = []

    if not isinstance(doc, dict):
        return failed_urls, failed_rel, entries

    failed = doc.get("failed_urls", [])
    if not isinstance(failed, list):
        return failed_urls, failed_rel, entries

    for item in failed:
        url = ""
        err = ""
        status: Optional[int] = None
        ts = ""
        if isinstance(item, dict):
            url = str(item.get("url", "")).strip()
            err = str(item.get("error", "")).strip()
            st = item.get("status", None)
            if isinstance(st, int):
                status = st
            ts = str(item.get("ts", "")).strip()
        elif isinstance(item, str):
            url = item.strip()
        if not url:
            continue
        if failure_mode == "hard" and not is_hard_failure(status, err):
            continue
        failed_urls.add(url)
        rel = rel_from_base_url(base_url, url)
        if rel:
            failed_rel.add(rel)
        entries.append({"url": url, "error": err, "status": status, "ts": ts})

    return failed_urls, failed_rel, entries


def merge_failed_entries(old_entries: Sequence[FailedEntry], new_entries: Sequence[FailedEntry]) -> List[FailedEntry]:
    by_url: Dict[str, FailedEntry] = {}
    for src in (old_entries, new_entries):
        for item in src:
            url = str(item.get("url", "")).strip()
            if not url:
                continue
            err = str(item.get("error", "")).strip()
            status_val = item.get("status", None)
            status: Optional[int] = status_val if isinstance(status_val, int) else None
            ts = str(item.get("ts", "")).strip()
            if url not in by_url:
                by_url[url] = {"url": url, "error": err, "status": status, "ts": ts}
            else:
                # Prefer richer/newer info.
                if err:
                    by_url[url]["error"] = err
                if status is not None:
                    by_url[url]["status"] = status
                if ts:
                    by_url[url]["ts"] = ts
    merged = [by_url[u] for u in sorted(by_url)]
    return merged


def run_cfr_decompile(
    cfr_jar_path: Path,
    class_files: Sequence[Path],
    decompiled_dir: Path,
    verbose: bool = False,
) -> Tuple[int, int]:
    ok = 0
    failed = 0
    decompiled_dir.mkdir(parents=True, exist_ok=True)
    for class_file in class_files:
        cmd = [
            "java",
            "-jar",
            str(cfr_jar_path),
            "--outputdir",
            str(decompiled_dir),
            str(class_file),
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode == 0:
                ok += 1
            else:
                failed += 1
                if verbose:
                    err = (proc.stderr or proc.stdout or "").strip().splitlines()
                    tail = err[-1] if err else f"exit {proc.returncode}"
                    print(colorize(f"{tag_warn()} CFR failed for {class_file.name}: {tail}", Ansi.RED, Ansi.BOLD))
        except FileNotFoundError:
            failed += 1
            if verbose:
                print(colorize(f"{tag_warn()} Java runtime not found for CFR decompilation", Ansi.RED, Ansi.BOLD))
            break
        except Exception as e:
            failed += 1
            if verbose:
                print(colorize(f"{tag_warn()} CFR exception for {class_file.name}: {e}", Ansi.RED, Ansi.BOLD))
    return ok, failed


def discover_missing_classes_from_cfr_headers(decompiled_dir: Path) -> Set[str]:
    out: Set[str] = set()
    if not decompiled_dir.exists():
        return out
    for java_file in decompiled_dir.rglob("*.java"):
        try:
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            continue

        in_missing = False
        for line in lines:
            if not in_missing and CFR_MISSING_HEADER_RE.search(line):
                in_missing = True
                continue

            if not in_missing:
                continue

            if line.strip().startswith("*/"):
                break

            m = CFR_MISSING_CLASS_RE.match(line)
            if not m:
                continue
            cls = m.group(1).strip().strip(".")
            if cls:
                out.add(cls)
    return out


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Extract .java imports and download corresponding .class files")
    default_threads = min(8, max(2, os.cpu_count() or 4))
    p.add_argument("--java-root", required=True, help="Path to .java file or directory containing .java files")
    p.add_argument("--base-url", required=True, help="Base URL, e.g. https://myapp.com/")
    p.add_argument(
        "--class-root",
        default=None,
        help="Remote class root prefix. Default is auto-inferred from base URL",
    )
    p.add_argument("--output-dir", default=None, help="Output directory (default: auto, near --java-root)")
    p.add_argument(
        "--include-prefix",
        action="append",
        default=[],
        help="Only include imports starting with this prefix (repeatable)",
    )
    p.add_argument(
        "--exclude-prefix",
        action="append",
        default=[],
        help="Exclude imports starting with this prefix (repeatable)",
    )
    p.add_argument("--timeout", type=float, default=12.0, help="HTTP timeout seconds")
    p.add_argument("--sleep", type=float, default=0.0, help="Delay between requests")
    p.add_argument("--threads", type=int, default=default_threads, help=f"Parallel download workers (default: {default_threads})")
    p.add_argument("--retries", type=int, default=2, help="Retry attempts for transient errors (default: 2)")
    p.add_argument("--retry-backoff", type=float, default=0.75, help="Exponential retry backoff base seconds")
    p.add_argument(
        "--decompile",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Run CFR decompilation and auto-queue missing classes from CFR headers (default: enabled)",
    )
    p.add_argument("--cfr-jar", default="cfr-0.152.jar", help="Path to CFR jar (default: cfr-0.152.jar)")
    p.add_argument(
        "--decompiled-dir",
        default="",
        help="Directory for CFR output (default: use --java-root when it already contains .java, else <output-dir>/decompiled)",
    )
    p.add_argument(
        "--seed-from-cfr-headers",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Seed class queue from existing CFR 'Could not load...' headers found under --java-root (default: enabled)",
    )
    p.add_argument(
        "--seed-from-descriptors",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Seed class queue from deployment descriptors (e.g., web.xml servlet-class) under --java-root (default: enabled)",
    )
    p.add_argument(
        "--seed-from-local-class-files",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="If .class files already exist under --java-root, decompile them first to discover missing dependencies (default: enabled)",
    )
    p.add_argument(
        "--max-auto-passes",
        type=int,
        default=8,
        help="Max auto expansion passes for download->decompile->dependency queue loop (default: 8)",
    )
    p.add_argument("--insecure", action="store_true", help="Disable TLS certificate/hostname verification")
    p.add_argument("--ca-file", default="", help="Custom CA bundle PEM")
    p.add_argument(
        "--resume-report",
        default="",
        help="Path to prior imports_fetch_report.json (default: <output-dir>/imports_fetch_report.json)",
    )
    p.add_argument("--no-resume", action="store_true", help="Do not preload previously-downloaded files")
    p.add_argument(
        "--skip-previous-failures",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="When resuming, skip imports whose URL/path previously failed (default: enabled)",
    )
    p.add_argument(
        "--skip-failure-mode",
        choices=["hard", "all"],
        default="hard",
        help="When skipping previous failures, skip only hard failures (default) or all previous failures",
    )
    p.add_argument(
        "--allow-resume-mismatch",
        action="store_true",
        help="Allow resume even if prior report base_url/class_root differs from current run",
    )
    p.add_argument(
        "--expand-wildcards",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Expand wildcard imports (pkg.*) using guessed class suffixes (default: enabled)",
    )
    p.add_argument(
        "--wildcard-suffix",
        action="append",
        default=[],
        help="Extra class suffix for wildcard expansion (repeatable)",
    )
    p.add_argument(
        "--new-mirror-run",
        action="store_true",
        help="Create a fresh timestamped mirror subfolder for this run",
    )
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors in output")
    p.add_argument("--verbose", action="store_true", help="Print progress")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    print(banner())
    args = build_arg_parser().parse_args(argv)
    global COLOR_ENABLED
    COLOR_ENABLED = supports_color(no_color=args.no_color)

    java_root = Path(args.java_root).resolve()
    if args.output_dir:
        output_dir = Path(args.output_dir).resolve()
    else:
        output_dir = java_root.parent.resolve() if java_root.exists() else Path.cwd().resolve()
    run_stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    if args.new_mirror_run:
        mirror_dir = output_dir / f"mirror-{run_stamp}"
    else:
        candidates: List[Path] = []
        if java_root.is_dir():
            n = java_root.name
            if "Decompiled" in n:
                candidates.append(java_root.with_name(n.replace("Decompiled", "Downloaded")))
            if "decompiled" in n:
                candidates.append(java_root.with_name(n.replace("decompiled", "downloaded")))
        candidates.extend([output_dir / "Downloaded", output_dir / "downloaded", output_dir / "mirror"])
        existing = next((p for p in candidates if p.exists() and p.is_dir()), None)
        mirror_dir = existing if existing is not None else candidates[-1]

    base_url = normalize_base_url(args.base_url)
    if args.class_root is not None and str(args.class_root).strip() != "":
        class_root = args.class_root if str(args.class_root).startswith("/") else "/" + str(args.class_root)
        class_root = class_root.rstrip("/")
    else:
        bpath = (urlparse(base_url).path or "/").lower()
        # Keep auto mode neutral: no hardcoded fallback to specific exposed roots.
        # If base URL already points at a classes path, use it as-is (class_root="").
        # Otherwise still default to class_root="" so callers can decide explicitly.
        if bpath.endswith("/web-inf/classes/") or bpath.endswith("/web-inf/classes") or bpath.endswith("/classes/") or bpath.endswith("/classes"):
            class_root = ""
        else:
            class_root = ""

    include_prefixes = [p.strip() for p in args.include_prefix if p.strip()]
    include_prefixes_explicit = len(include_prefixes) > 0

    exclude_prefixes = list(DEFAULT_STANDARD_PREFIXES)
    exclude_prefixes.extend(p.strip() for p in args.exclude_prefix if p.strip())
    wildcard_suffixes = [s.strip().strip(".") for s in args.wildcard_suffix if s.strip().strip(".")]
    if not wildcard_suffixes:
        wildcard_suffixes = list(DEFAULT_WILDCARD_SUFFIX_GUESSES)

    ssl_ctx = build_ssl_context(args.insecure, args.ca_file)

    report = FetchReport(
        started_at=datetime.now(timezone.utc).isoformat(),
        java_root=str(java_root),
        base_url=base_url,
        class_root=class_root,
        output_dir=str(output_dir),
    )

    default_report_name = "imports_fetch_report.json"
    report_path = Path(args.resume_report).resolve() if args.resume_report else (output_dir / default_report_name)
    report.resume_report_path = str(report_path)

    java_files = collect_java_files(java_root)
    local_class_files = collect_class_files(java_root) if args.seed_from_local_class_files else []
    report.java_files_scanned = len(java_files)

    selected_classes: Set[str] = set()
    nonstandard_classes_seen: Set[str] = set()
    wildcard_packages: Set[str] = set()

    for java_file in java_files:
        try:
            text = java_file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        imports = parse_imports(text)
        report.imports_found += len(imports)

        for is_static, import_name in imports:
            cls = import_to_class_name(is_static, import_name)
            if cls is None:
                if import_name.endswith(".*"):
                    report.wildcard_imports_skipped += 1
                    pkg = import_name[:-2]
                    if pkg and not is_standard(pkg, exclude_prefixes) and (
                        (not include_prefixes_explicit) or in_include_prefixes(pkg, include_prefixes)
                    ):
                        wildcard_packages.add(pkg)
                continue
            if is_standard(cls, exclude_prefixes):
                continue
            nonstandard_classes_seen.add(cls)
            if include_prefixes_explicit and not in_include_prefixes(cls, include_prefixes):
                continue
            selected_classes.add(cls)
    if not include_prefixes_explicit:
        selected_classes.update(nonstandard_classes_seen)

    # Optional wildcard expansion: pkg.* -> pkg.<guessedClass>
    if args.expand_wildcards and wildcard_packages:
        report.wildcard_packages_seen = len(wildcard_packages)
        known_tails = {c.split(".")[-1] for c in selected_classes if "." in c}
        suffix_candidates = sorted(set(wildcard_suffixes) | known_tails)
        before = len(selected_classes)
        for pkg in wildcard_packages:
            for suffix in suffix_candidates:
                selected_classes.add(f"{pkg}.{suffix}")
        report.wildcard_classes_generated = max(0, len(selected_classes) - before)

    if args.seed_from_descriptors:
        xml_scanned, descriptor_classes = discover_classes_from_deployment_descriptors(java_root)
        descriptor_classes = {c for c in descriptor_classes if not is_standard(c, exclude_prefixes)}
        report.descriptor_xml_scanned = xml_scanned
        if include_prefixes_explicit:
            descriptor_seed = {c for c in descriptor_classes if in_include_prefixes(c, include_prefixes)}
        else:
            descriptor_seed = set(descriptor_classes)
        if descriptor_seed:
            selected_classes.update(descriptor_seed)
            report.descriptor_classes_seeded = len(descriptor_seed)
            print(
                colorize(
                    f"{tag_info()} Seeded {len(descriptor_seed)} classes from deployment descriptors ({xml_scanned} XML scanned)",
                    Ansi.MAGENTA,
                    Ansi.BOLD,
                )
            )

    if args.seed_from_cfr_headers:
        seed_missing = discover_missing_classes_from_cfr_headers(java_root)
        seed_interesting = {c for c in seed_missing if not is_standard(c, exclude_prefixes)}
        seed_new = sorted(seed_interesting - selected_classes)
        if seed_new:
            selected_classes.update(seed_new)
            report.cfr_seed_classes_from_java_root = len(seed_new)
            print(
                colorize(
                    f"{tag_info()} Seeded {len(seed_new)} classes from existing CFR headers under --java-root",
                    Ansi.MAGENTA,
                    Ansi.BOLD,
                )
            )

    report.imports_selected = len(selected_classes)
    report.selected_imports = sorted(selected_classes)

    if args.verbose:
        print(colorize(f"{tag_info()} Java files scanned: {report.java_files_scanned}", Ansi.CYAN, Ansi.BOLD))
        print(colorize(f"{tag_info()} Imports found: {report.imports_found}", Ansi.CYAN, Ansi.BOLD))
        print(colorize(f"{tag_info()} Selected class imports: {report.imports_selected}", Ansi.CYAN, Ansi.BOLD))
        if args.expand_wildcards:
            print(colorize(f"{tag_info()} Wildcard packages: {report.wildcard_packages_seen}", Ansi.CYAN, Ansi.BOLD))
            print(colorize(f"{tag_info()} Wildcard classes generated: {report.wildcard_classes_generated}", Ansi.CYAN, Ansi.BOLD))

    downloaded_rel: Set[str] = set()
    previous_failed_urls: Set[str] = set()
    previous_failed_rel: Set[str] = set()
    previous_failed_entries: List[FailedEntry] = []
    processed_decompile_inputs: Set[str] = set()
    failed_rel_this_run: Set[str] = set()
    resume_doc: Optional[Dict[str, Any]] = None
    if not args.no_resume:
        resume_doc = load_report_doc(report_path)
        if resume_doc and not resume_scope_matches(resume_doc, base_url, class_root):
            if args.allow_resume_mismatch:
                if args.verbose:
                    print(colorize(f"{tag_warn()} resume scope mismatch allowed by flag", Ansi.YELLOW, Ansi.BOLD))
            else:
                report.resume_scope_mismatch_ignored = True
                if args.verbose:
                    print(colorize(f"{tag_warn()} resume scope mismatch, ignoring old report state", Ansi.YELLOW, Ansi.BOLD))
                resume_doc = None

        downloaded_rel.update(load_previously_downloaded_from_report(resume_doc))
        _, _, previous_failed_entries = load_previously_failed_from_report(resume_doc, base_url, "all")
        processed_decompile_inputs.update(load_previously_decompiled_inputs(resume_doc))
        if args.skip_previous_failures:
            previous_failed_urls, previous_failed_rel, _ = load_previously_failed_from_report(
                resume_doc, base_url, args.skip_failure_mode
            )
        downloaded_rel.update(load_existing_mirror_files(mirror_dir))

    report.resumed_preloaded_count = len(downloaded_rel)
    report.resumed_failed_count = len(previous_failed_entries)

    selected_classes_all: Set[str] = set(selected_classes)

    decompile_enabled = bool(args.decompile)
    if args.decompiled_dir:
        decompiled_dir = Path(args.decompiled_dir).resolve()
    else:
        decompiled_dir = java_root if java_root.is_dir() and len(java_files) > 0 else (output_dir / "decompiled")
    cfr_jar_path = Path(args.cfr_jar).expanduser().resolve()
    if decompile_enabled and not cfr_jar_path.exists():
        decompile_enabled = False
        print(colorize(f"{tag_warn()} CFR jar not found: {cfr_jar_path} (continuing without decompile)", Ansi.YELLOW, Ansi.BOLD))

    report.decompile_enabled = decompile_enabled
    report.cfr_jar_path = str(cfr_jar_path)
    report.decompiled_dir = str(decompiled_dir)

    if decompile_enabled and local_class_files:
        if args.verbose:
            print(
                colorize(
                    f"{tag_info()} Local class seed: decompiling {len(local_class_files)} existing class files under --java-root",
                    Ansi.CYAN,
                    Ansi.BOLD,
                )
            )
        report.decompile_runs += 1
        report.local_class_seed_count = len(local_class_files)
        ok, bad = run_cfr_decompile(cfr_jar_path, local_class_files, decompiled_dir, verbose=args.verbose)
        if args.verbose:
            print(colorize(f"{tag_info()} Local class seed CFR completed: ok={ok} failed={bad}", Ansi.CYAN, Ansi.BOLD))
        from_local_seed = discover_missing_classes_from_cfr_headers(decompiled_dir)
        from_local_seed = {c for c in from_local_seed if not is_standard(c, exclude_prefixes)}
        new_local_seed = sorted(from_local_seed - selected_classes_all)
        if new_local_seed:
            selected_classes_all.update(new_local_seed)
            report.cfr_missing_classes_new += len(new_local_seed)
            report.cfr_missing_classes_added.extend(new_local_seed)
            print(
                colorize(
                    f"{tag_info()} Local class seed discovered {len(new_local_seed)} dependency classes",
                    Ansi.MAGENTA,
                    Ansi.BOLD,
                )
            )

    if not selected_classes_all:
        print(colorize(f"{tag_warn()} No class candidates selected. Nothing to fetch.", Ansi.YELLOW, Ansi.BOLD))
        print(
            colorize(
                "Tip: use --seed-from-descriptors/--seed-from-cfr-headers/--seed-from-local-class-files or pass --include-prefix explicitly.",
                Ansi.CYAN,
                Ansi.BOLD,
            )
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        report.imports_selected = 0
        report.selected_imports = []
        report.failed_urls = merge_failed_entries(previous_failed_entries, report.new_failed_urls)
        report_path.write_text(json.dumps(report.__dict__, indent=2), encoding="utf-8")
        return 0

    def run_one(rel: str, url: str) -> Tuple[str, str, Optional[bytes], DownloadResult]:
        data, res = fetch_bytes_with_retry(
            url=url,
            timeout=args.timeout,
            ssl_context=ssl_ctx,
            retries=max(0, args.retries),
            retry_backoff=max(0.0, args.retry_backoff),
        )
        if args.sleep > 0:
            time.sleep(args.sleep)
        return rel, url, data, res

    threads = max(1, args.threads)
    max_passes = max(1, args.max_auto_passes)
    pass_idx = 0
    while pass_idx < max_passes:
        pass_idx += 1
        report.auto_passes_completed = pass_idx

        if args.verbose:
            print(colorize(f"\n{tag_info()} Auto pass {pass_idx}/{max_passes}", Ansi.MAGENTA, Ansi.BOLD))

        # Build unique candidate path map, accounting for inner-class path variants.
        candidate_rel_to_url: Dict[str, str] = {}
        for class_name in sorted(selected_classes_all):
            for rel in class_name_to_rel_paths(class_name, class_root):
                rel = rel.lstrip("/")
                if not rel:
                    continue
                candidate_rel_to_url.setdefault(rel, urljoin(base_url, rel))

        pending: List[Tuple[str, str]] = []
        for rel, url in sorted(candidate_rel_to_url.items()):
            if rel in downloaded_rel:
                report.skipped_already_downloaded += 1
                if args.verbose:
                    print(colorize(f"{tag_skip()} skip already-downloaded: {rel}", Ansi.YELLOW, Ansi.BOLD))
                continue

            if rel in failed_rel_this_run:
                report.skipped_failed_this_run += 1
                if args.verbose:
                    print(colorize(f"{tag_skip()} skip failed-this-run: {rel}", Ansi.YELLOW, Ansi.BOLD))
                continue

            if args.skip_previous_failures and (url in previous_failed_urls or rel in previous_failed_rel):
                report.skipped_previous_failures += 1
                if args.verbose:
                    print(colorize(f"{tag_skip()} skip previous-failure: {rel}", Ansi.YELLOW, Ansi.BOLD))
                continue

            pending.append((rel, url))
            report.attempted_urls.append(url)

        total_pending = len(pending)
        done_count = 0
        ok_count = 0
        fail_count = 0
        progress_line_len = 0

        def render_progress(final: bool = False) -> None:
            nonlocal progress_line_len
            if args.verbose or total_pending == 0:
                return
            line = f"{tag_info()} Progress {done_count}/{total_pending} | downloaded:{ok_count} failed:{fail_count}"
            padded = line.ljust(progress_line_len)
            sys.stdout.write("\r" + colorize(padded, Ansi.CYAN, Ansi.BOLD))
            sys.stdout.flush()
            progress_line_len = max(progress_line_len, len(line))
            if final:
                sys.stdout.write("\n")
                sys.stdout.flush()

        def handle_result(rel: str, url: str, data: Optional[bytes], res: DownloadResult) -> None:
            nonlocal done_count, ok_count, fail_count
            if rel in downloaded_rel:
                done_count += 1
                render_progress()
                return

            if data is None or res.status != 200:
                report.new_failed_urls.append(
                    {
                        "url": url,
                        "error": res.error or f"HTTP {res.status}",
                        "status": res.status,
                        "ts": datetime.now(timezone.utc).isoformat(),
                    }
                )
                failed_rel_this_run.add(rel)
                fail_count += 1
                done_count += 1
                if args.verbose:
                    print(colorize(f"{tag_warn()} {url} -> {res.error or res.status}", Ansi.RED, Ansi.BOLD))
                render_progress()
                return

            out_file = mirror_dir / rel
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_bytes(data)
            downloaded_rel.add(rel)
            # Dedup also by redirected final path when possible.
            final_rel = rel_from_base_url(base_url, res.url)
            if final_rel:
                downloaded_rel.add(final_rel)
            report.new_downloaded_files.append(str(out_file.relative_to(output_dir)))
            ok_count += 1
            done_count += 1

            if args.verbose:
                print(colorize(f"{tag_ok()} {rel}", Ansi.GREEN, Ansi.BOLD))
            render_progress()

        if total_pending > 0:
            print(colorize(f"{tag_info()} Fetch queue: {total_pending} candidates", Ansi.CYAN, Ansi.BOLD))

        if threads == 1:
            for rel, url in pending:
                r_rel, r_url, data, res = run_one(rel, url)
                handle_result(r_rel, r_url, data, res)
        else:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                fut_map = {ex.submit(run_one, rel, url): (rel, url) for rel, url in pending}
                for fut in as_completed(fut_map):
                    try:
                        r_rel, r_url, data, res = fut.result()
                    except Exception as e:
                        rel, url = fut_map[fut]
                        r_rel, r_url, data, res = rel, url, None, DownloadResult(
                            url=url, status=None, error=f"Worker error: {e}"
                        )
                    handle_result(r_rel, r_url, data, res)

        render_progress(final=True)

        # If decompile is disabled, stop after the first fetch pass.
        if not decompile_enabled:
            break

        # Decompile newly-seen class files and mine CFR missing-class headers.
        class_inputs_rel: List[str] = []
        for rel in sorted(downloaded_rel):
            if not rel.endswith(".class"):
                continue
            if rel in processed_decompile_inputs:
                continue
            if not (mirror_dir / rel).is_file():
                continue
            class_inputs_rel.append(rel)

        if class_inputs_rel:
            report.decompile_runs += 1
            if args.verbose:
                print(colorize(f"{tag_info()} CFR decompile queue: {len(class_inputs_rel)} class files", Ansi.CYAN, Ansi.BOLD))
            class_inputs_abs = [mirror_dir / rel for rel in class_inputs_rel]
            ok, bad = run_cfr_decompile(cfr_jar_path, class_inputs_abs, decompiled_dir, verbose=args.verbose)
            if args.verbose:
                print(colorize(f"{tag_info()} CFR completed: ok={ok} failed={bad}", Ansi.CYAN, Ansi.BOLD))
            processed_decompile_inputs.update(class_inputs_rel)
            report.decompiled_inputs_count = len(processed_decompile_inputs)

        missing_from_cfr = discover_missing_classes_from_cfr_headers(decompiled_dir)
        missing_interesting = {c for c in missing_from_cfr if not is_standard(c, exclude_prefixes)}
        report.cfr_missing_classes_total = len(missing_interesting)
        new_missing = sorted(missing_interesting - selected_classes_all)

        if new_missing:
            selected_classes_all.update(new_missing)
            report.cfr_missing_classes_new += len(new_missing)
            report.cfr_missing_classes_added.extend(new_missing)
            print(colorize(f"{tag_info()} CFR discovered {len(new_missing)} new class dependencies", Ansi.MAGENTA, Ansi.BOLD))
            if args.verbose:
                for c in new_missing[:50]:
                    print(colorize(f"{tag_ok()} dep {c}", Ansi.GREEN, Ansi.BOLD))
                if len(new_missing) > 50:
                    print(colorize(f"{tag_info()} ... and {len(new_missing) - 50} more", Ansi.CYAN, Ansi.BOLD))
            continue

        # No new classes from CFR; loop converged.
        break

    if pass_idx >= max_passes:
        print(colorize(f"{tag_warn()} reached max auto passes ({max_passes})", Ansi.YELLOW, Ansi.BOLD))

    report.imports_selected = len(selected_classes_all)
    report.selected_imports = sorted(selected_classes_all)

    mirror_prefix = mirror_dir.relative_to(output_dir).as_posix()
    report.downloaded_files = sorted(f"{mirror_prefix}/{rel}" for rel in downloaded_rel)
    report.decompiled_class_inputs = sorted(f"{mirror_prefix}/{rel}" for rel in processed_decompile_inputs)
    report.failed_urls = merge_failed_entries(previous_failed_entries, report.new_failed_urls)
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report.__dict__, indent=2), encoding="utf-8")

    print("\n" + colorize("Import-to-class fetch complete", Ansi.MAGENTA, Ansi.BOLD))
    print(colorize(f"Output dir: {output_dir}", Ansi.BOLD))
    print(colorize(f"Mirror dir: {mirror_dir}", Ansi.BOLD))
    print(colorize(f"Class root: {class_root or '/'}", Ansi.BOLD))
    print(colorize(f"Java files scanned: {report.java_files_scanned}", Ansi.CYAN, Ansi.BOLD))
    print(colorize(f"Descriptor XML scanned: {report.descriptor_xml_scanned}", Ansi.CYAN, Ansi.BOLD))
    print(colorize(f"Descriptor classes seeded: {report.descriptor_classes_seeded}", Ansi.CYAN, Ansi.BOLD))
    print(colorize(f"Local class seed count: {report.local_class_seed_count}", Ansi.CYAN, Ansi.BOLD))
    print(colorize(f"Selected imports: {report.imports_selected}", Ansi.CYAN, Ansi.BOLD))
    print(colorize(f"Auto passes completed: {report.auto_passes_completed}", Ansi.CYAN, Ansi.BOLD))
    print(colorize(f"Preloaded already-downloaded: {report.resumed_preloaded_count}", Ansi.YELLOW, Ansi.BOLD))
    print(colorize(f"Preloaded previous-failures: {report.resumed_failed_count}", Ansi.YELLOW, Ansi.BOLD))
    print(colorize(f"Seeded from CFR headers in java-root: {report.cfr_seed_classes_from_java_root}", Ansi.YELLOW, Ansi.BOLD))
    print(colorize(f"Skipped failed-this-run: {report.skipped_failed_this_run}", Ansi.YELLOW, Ansi.BOLD))
    print(colorize(f"Skipped already-downloaded: {report.skipped_already_downloaded}", Ansi.YELLOW, Ansi.BOLD))
    print(colorize(f"Skipped previous-failures: {report.skipped_previous_failures}", Ansi.YELLOW, Ansi.BOLD))
    print(colorize(f"Threads: {threads}", Ansi.CYAN, Ansi.BOLD))
    print(colorize(f"CFR decompile enabled: {report.decompile_enabled}", Ansi.CYAN, Ansi.BOLD))
    if report.decompile_enabled:
        print(colorize(f"CFR jar: {report.cfr_jar_path}", Ansi.CYAN, Ansi.BOLD))
        print(colorize(f"Decompiled dir: {report.decompiled_dir}", Ansi.CYAN, Ansi.BOLD))
        print(colorize(f"Decompile runs: {report.decompile_runs}", Ansi.CYAN, Ansi.BOLD))
        print(colorize(f"Decompiled class inputs (cumulative): {report.decompiled_inputs_count}", Ansi.CYAN, Ansi.BOLD))
        print(colorize(f"CFR missing classes total: {report.cfr_missing_classes_total}", Ansi.CYAN, Ansi.BOLD))
        print(colorize(f"CFR newly-added classes this run: {report.cfr_missing_classes_new}", Ansi.CYAN, Ansi.BOLD))
    print(colorize(f"Newly downloaded class files: {len(report.new_downloaded_files)}", Ansi.GREEN, Ansi.BOLD))
    print(colorize(f"Total downloaded class files (cumulative): {len(report.downloaded_files)}", Ansi.GREEN, Ansi.BOLD))
    print(colorize(f"New failed fetches this run: {len(report.new_failed_urls)}", Ansi.RED, Ansi.BOLD))
    print(colorize(f"Failed fetches (cumulative): {len(report.failed_urls)}", Ansi.RED, Ansi.BOLD))
    print(colorize(f"Report: {report_path}", Ansi.BOLD))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
