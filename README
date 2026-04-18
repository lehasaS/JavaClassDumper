# Java Class Dumper

Have you ever found a Java web app exposing class files (for example under `.../WEB-INF/classes/`)?

If you can discover one class path, you can often recover many more by chaining:
- Imports from decompiled sources,
- Deployment descriptors (`web.xml`, etc.),
- Unresolved dependency hints from decompiler output.

`java_class_dumper.py` automates that recovery loop.

## What This Tool Does
`java_class_dumper.py` is a generic class-recovery pipeline for Java application source-disclosure investigations.

It combines:
- Import parsing from `.java` sources,
- `.class` path reconstruction,
- HTTP download with retry/resume,
- CFR decompilation,
- Iterative dependency expansion from CFR headers (`Could not load the following classes`).

The goal is to eliminate repetitive manual loops:
1. Download classes,
2. Decompile,
3. Inspect missing classes,
4. Rerun with new targets.

## Pipeline Overview
Per run, the tool can:
1. Parse imports from `--java-root`.
2. Seed class queue from deployment descriptors (`web.xml`, etc.).
3. Seed class queue from existing CFR headers under `--java-root`.
4. Optionally decompile local `.class` files under `--java-root` and seed from discovered dependencies.
5. Download unresolved `.class` files from `--base-url`.
6. Decompile newly downloaded classes with CFR.
7. Parse CFR missing-class headers and queue new classes.
8. Repeat until convergence or `--max-auto-passes`.

## Requirements
- Python 3.9+
- Java runtime (`java`) in PATH
- [CFR](https://github.com/leibnitz27/cfr) Java Decompiler
- Network access to target class URL root

## Setup
```bash
# 1) Enter the tool directory
cd JavaClassDumper

# 2) (Recommended) create and activate a virtualenv
python3 -m venv .venv
source .venv/bin/activate

# 3) Install dependencies (currently stdlib-only; keeps workflow consistent)
pip install -r requirements.txt

# 4) Install the tool in editable mode (adds `java-class-dumper` CLI entrypoint)
# `--no-build-isolation` helps in offline/restricted environments.
pip install -e . --no-build-isolation

# 5) Verify
java-class-dumper --help
```

Notes:
- Keep your CFR jar accessible and pass it with `--cfr-jar /path/to/cfr.jar`.
- If you prefer direct execution, you can still run `python3 java_class_dumper.py ...`.

## Safety / Scope
- Use only on systems you are authorized to assess.
- This tool is for defensive artifact recovery and analysis workflows.

## Basic Usage
```bash
python3 java_class_dumper.py \
  --java-root <path/to/decompiled/java/root> \
  --base-url https://vulnerable.application.com/WEB-INF/classes/ \
  --cfr-jar /path/to/cfr.jar
```

## Existing Dump Workflow
If you already have decompiled source (example folder name):

```bash
python3 java_class_dumper.py \
  --java-root Vulnerable-App-Decompiled-Source/ \
  --base-url https://vulnerable.application.com/WEB-INF/classes/ \
  --cfr-jar cfr.jar \
  --verbose
```

This works even when no prior `imports_fetch_report.json` exists.

## Output & Merge Behavior
Default behavior is merge-friendly:
- `--output-dir` default is auto-inferred near `--java-root`.
- For `*Decompiled` roots, the tool reuses sibling `*Downloaded` if present.
- Otherwise it reuses `Downloaded`, `downloaded`, or `mirror` under output root.
- New mirror folder is only forced with `--new-mirror-run`.

## Class Root Behavior
`--class-root` is optional.

When omitted, the default stays neutral (`/`) and does not assume product-specific disclosure paths.

Examples:
- `https://vulnerable.application.com/WEB-INF/classes/` + default class root -> `com/vulnerable/Application.class`
- `https://vulnerable.application.com/custom/path/` + explicit `--class-root /bea_wls_internal/classes` -> `/bea_wls_internal/classes/com/vulnerable/Application.class`

## Seeding Sources
### 1) Imports from `.java`
- Parses `import ...;`
- Handles static imports and optional wildcard expansion (`--expand-wildcards`)

### 2) Deployment descriptors (`--seed-from-descriptors`)
Parses XML under `--java-root` and extracts classes from tags like:
- `servlet-class`
- `filter-class`
- `listener-class`
- `ejb-class`
- `home`, `remote`, `local-home`, `local`, `service-endpoint`

### 3) CFR headers (`--seed-from-cfr-headers`)
Parses:
- `Could not load the following classes:`

### 4) Existing local `.class` files (`--seed-from-local-class-files`)
If `.class` files already exist under `--java-root`, they are decompiled first to discover additional missing classes.

## Filtering Behavior
### Standard namespace exclusion (default)
The following are excluded by default:
- `java.`
- `javax.`
- `jakarta.`
- `sun.`
- `com.sun.`
- `org.w3c.`
- `org.xml.`

Add more with `--exclude-prefix`.

### Include-prefix handling
- If `--include-prefix` is provided, it is enforced.
- If `--include-prefix` is not provided, the tool uses all non-standard imports.

## Resume / State
By default, the tool resumes from:
- existing mirror files,
- previous `imports_fetch_report.json` (if present).

Disable resume with `--no-resume`.

Failure handling:
- skip previous failures by default (`--skip-previous-failures`)
- mode: `hard` (default) or `all`

## Decompilation Behavior
Decompilation is enabled by default (`--decompile`).

Per pass:
- newly downloaded classes are decompiled,
- CFR headers are mined for unresolved classes,
- unresolved classes are queued for next pass.

Set expansion limit with `--max-auto-passes` (default `8`).

## Important Flags
- `--java-root`
- `--base-url`
- `--class-root`
- `--output-dir`
- `--include-prefix`
- `--exclude-prefix`
- `--decompile / --no-decompile`
- `--cfr-jar`
- `--decompiled-dir`
- `--seed-from-cfr-headers / --no-seed-from-cfr-headers`
- `--seed-from-descriptors / --no-seed-from-descriptors`
- `--seed-from-local-class-files / --no-seed-from-local-class-files`
- `--threads`
- `--insecure`
- `--verbose`

## Practical Recipes
### 1. Descriptor-led bootstrap (`web.xml`-led)
```bash
python3 java_class_dumper.py \
  --java-root Vulnerable-App-Decompiled-Source/ \
  --base-url https://vulnerable.application.com/WEB-INF/classes/ \
  --seed-from-descriptors \
  --seed-from-cfr-headers \
  --seed-from-local-class-files \
  --cfr-jar cfr.jar \
  --verbose
```

### 2. Restrict to known package families
```bash
python3 java_class_dumper.py \
  --java-root Vulnerable-App-Decompiled-Source/ \
  --base-url https://vulnerable.application.com/WEB-INF/classes/ \
  --include-prefix com.vulnerable.application. \
  --include-prefix org.vendor.product. \
  --cfr-jar cfr.jar
```

### 3. No decompilation (download only)
```bash
python3 java_class_dumper.py \
  --java-root Vulnerable-App-Decompiled-Source/ \
  --base-url https://vulnerable.application.com/WEB-INF/classes/ \
  --no-decompile
```

### 4. Force fresh mirror folder
```bash
python3 java_class_dumper.py \
  --java-root Vulnerable-App-Decompiled-Source/ \
  --base-url https://vulnerable.application.com/WEB-INF/classes/ \
  --new-mirror-run
```

## Report File
Default report path:
- `<output-dir>/imports_fetch_report.json`

Counters include:
- selected imports/classes
- auto pass count
- downloaded files
- failures
- CFR-discovered class counts
- descriptor/CFR/local seed counters

## Troubleshooting
### `Selected imports: 0`
- Verify `--java-root` actually contains parseable `.java` and/or descriptors.
- If using `--include-prefix`, check it is not overly narrow.
- Ensure seeding flags are enabled as needed.

### TLS certificate errors
- Prefer correct hostname/cert chain.
- For controlled lab testing with mismatched certs: `--insecure`.

### CFR not running
- Ensure Java is installed.
- Verify `--cfr-jar` path.

### Wrong remote paths
- Validate `--base-url` / `--class-root` combination.
- Prefer explicit `--class-root` when disclosure path is known.

## Notes
- Colors are enabled in TTY by default; disable with `--no-color`.
- Use `--verbose` for detailed pass-by-pass diagnostics.
