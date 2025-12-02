# Atomic YAML → Markdown Converter (Python)

This folder includes a small Python utility (`atomic_yaml_to_md.py`) that converts **Atomic Red Team** technique YAML files (e.g., `atomics/T1007/T1007.yaml`) into a **readable Markdown** document similar to the upstream Atomic Red Team MD format.

## Why this exists

In the upstream project, Markdown pages are typically generated from the YAML definitions as part of the documentation workflow. In some restricted corporate environments, the original Ruby/Gem-based generation pipeline may not be available (e.g., tooling blocked by policy).  
This script provides a **policy-friendly alternative** using Python.

> Note: This script **only transforms content** (YAML → Markdown). It does **not** execute any Atomic tests or commands.

## What it does

Given an Atomic YAML file, it generates a Markdown file containing:

- Technique title (Technique ID + display name)
- Table of contents linking to each Atomic Test
- Per-test sections with:
  - Description
  - Supported platforms
  - `auto_generated_guid`
  - Inputs table (if `input_arguments` exist)
  - Attack commands code block (mapped to the right language fence)
  - Cleanup commands code block (if present)
- Optional MITRE ATT&CK “Description from ATT&CK” block (see options below)

## Requirements

- Python 3.x
- PyYAML

Install dependency:

```powershell
python -m pip install pyyaml
```
Optional (only if you want to fetch MITRE descriptions automatically):

```powershell
python -m pip install requests beautifulsoup4
```

## Usage

### 1) Convert a single YAML file (side-by-side output)

From the repository root:

```powershell
python .\atomic_yaml_to_md.py .\atomics\T1007\T1007.yaml
```

This writes:
- atomics/T1007/T1007.md

### 2) Write output to a specific path

```
python .\atomic_yaml_to_md.py .\atomics\T1007\T1007.yaml --out .\generated-md\T1007.md
```

### 3) Add the ATT&CK description (offline)

If your environment cannot fetch external pages, you can provide the ATT&CK description as plain text.
- Create a text file (e.g., attack_desc_T1007.txt) containing the description.
- Run:
```
python .\atomic_yaml_to_md.py .\atomics\T1007\T1007.yaml --attack-desc-file .\attack_desc_T1007.txt
```

### 4) Fetch the ATT&CK description automatically (optional)

If your network policy allows access to MITRE:

```
python .\atomic_yaml_to_md.py .\atomics\T1007\T1007.yaml --fetch-mitre
```

If fetching fails (proxy / blocked network), the script will still generate Markdown without the description.

## Notes / Limitations

- The script aims to produce Markdown that is close to the upstream Atomic Red Team style, but minor formatting differences may exist across techniques.
- The MITRE “Description from ATT&CK” section is not present in the YAML; it must be supplied (offline file) or fetched (online).
- This utility is designed for documentation and review workflows only—no atomic execution is performed.

## Recommended repo structure

Place the script at the repository root for convenience:

```
atomic-red-team/
  atomics/
  atomic_yaml_to_md.py
  README.md
```

Then run:

```
python .\atomic_yaml_to_md.py .\atomics\T1007\T1007.yaml
```
