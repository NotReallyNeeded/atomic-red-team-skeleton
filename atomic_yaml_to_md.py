#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml  # PyYAML
except ImportError as e:
    raise SystemExit("Missing dependency: PyYAML\nInstall: python -m pip install pyyaml") from e


TECH_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)


def slugify_github_anchor(s: str) -> str:
    """
    Approximate GitHub's heading anchor behavior for ASCII headings.
    Matches the style seen in Atomic Red Team MD.
    """
    s = s.strip().lower()
    # remove special chars except spaces/hyphens
    s = re.sub(r"[^\w\s-]", "", s)
    s = s.replace(".", "")  # net.exe -> netexe
    s = re.sub(r"\s+", "-", s)
    s = re.sub(r"-+", "-", s)
    return s


def md_escape_inline(s: Any) -> str:
    if s is None:
        return ""
    return str(s).strip()


def md_escape_table(s: Any) -> str:
    # in their table, backslash is HTML-escaped
    if s is None:
        return ""
    return html.escape(str(s).strip()).replace("\\", "&#92;")


def code_fence_lang(executor_name: str) -> str:
    name = (executor_name or "").strip().lower()
    if name in {"command_prompt", "cmd"}:
        return "cmd"
    if name in {"powershell", "pwsh"}:
        return "powershell"
    if name in {"bash"}:
        return "bash"
    if name in {"sh"}:
        return "sh"
    return "text"


def fmt_supported_platforms(platforms: List[str]) -> str:
    # Example shows "Windows", "Linux", "macOS"
    if not platforms:
        return ""
    def titlecase(p: str) -> str:
        p = p.strip()
        if p.lower() == "macos":
            return "macOS"
        return p[:1].upper() + p[1:]
    return ", ".join(titlecase(p) for p in platforms)


def read_attack_desc_from_file(p: Path) -> str:
    return p.read_text(encoding="utf-8").strip()


def fetch_mitre_description(tech_id: str, timeout: int = 15) -> Optional[str]:
    """
    Optional: fetch description from MITRE ATT&CK technique page.
    Requires 'requests' + 'beautifulsoup4'.
    If blocked in corporate network, use --attack-desc-file instead.
    """
    try:
        import requests
        from bs4 import BeautifulSoup
    except Exception:
        return None

    url = f"https://attack.mitre.org/techniques/{tech_id}/"
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        r.raise_for_status()
    except Exception:
        return None

    soup = BeautifulSoup(r.text, "html.parser")

    # ATT&CK pages often have a "description-body" section; fallback to first content paragraph.
    desc = ""
    # try more specific selectors first
    body = soup.select_one("#description") or soup.select_one("div.description-body")
    if body:
        text = body.get_text("\n", strip=True)
        desc = text
    else:
        # fallback: first paragraphs under main content
        main = soup.select_one("main") or soup
        ps = main.select("p")
        if ps:
            desc = "\n\n".join(p.get_text(" ", strip=True) for p in ps[:2])

    return desc.strip() if desc else None


def build_markdown(doc: Dict[str, Any], attack_desc: Optional[str] = None) -> str:
    tech = md_escape_inline(doc.get("attack_technique", ""))
    display = md_escape_inline(doc.get("display_name", doc.get("name", "")))

    lines: List[str] = []
    lines.append(f"# {tech} - {display}")

    # MITRE Description section
    lines.append(f"## [Description from ATT&CK](https://attack.mitre.org/techniques/{tech})")
    lines.append("<blockquote>")
    lines.append("")
    if attack_desc:
        # keep formatting similar; no markdown italics etc
        lines.append(attack_desc.strip())
    else:
        lines.append("")  # keep empty blockquote if not provided
    lines.append("")
    lines.append("</blockquote>")
    lines.append("")
    lines.append("## Atomic Tests")
    lines.append("")

    tests: List[Dict[str, Any]] = doc.get("atomic_tests") or []

    # TOC list like "- [Atomic Test #1 - Name](#anchor)"
    for idx, t in enumerate(tests, start=1):
        name = md_escape_inline(t.get("name", f"Atomic Test #{idx}"))
        heading = f"Atomic Test #{idx} - {name}"
        anchor = slugify_github_anchor(heading)
        lines.append(f"- [Atomic Test #{idx} - {name}](#{anchor})")
        lines.append("")
    lines.append("")
    lines.append("<br/>")
    lines.append("")

    # Each atomic test section
    for idx, t in enumerate(tests, start=1):
        name = md_escape_inline(t.get("name", f"Atomic Test #{idx}"))
        desc = t.get("description") or ""
        platforms = t.get("supported_platforms") or []
        guid = md_escape_inline(t.get("auto_generated_guid", ""))

        lines.append(f"## Atomic Test #{idx} - {name}")
        if desc:
            lines.append(md_escape_inline(desc))
            lines.append("")
        if platforms:
            lines.append(f"**Supported Platforms:** {fmt_supported_platforms(platforms)}")
            lines.append("")
        if guid:
            lines.append(f"**auto_generated_guid:** {guid}")
            lines.append("")
        lines.append("")
        lines.append("")
        lines.append("")
        lines.append("")

        # Inputs (if any)
        input_args = t.get("input_arguments") or {}
        if isinstance(input_args, dict) and input_args:
            lines.append("#### Inputs:")
            lines.append("| Name | Description | Type | Default Value |")
            lines.append("|------|-------------|------|---------------|")
            for k, v in input_args.items():
                v = v or {}
                lines.append(
                    f"| {md_escape_inline(k)} | {md_escape_inline(v.get('description'))} | "
                    f"{md_escape_inline(v.get('type'))} | {md_escape_table(v.get('default'))}|"
                )
            lines.append("")
            lines.append("")

        # Executor section
        ex = t.get("executor") or {}
        ex_name = md_escape_inline(ex.get("name", "")) if isinstance(ex, dict) else ""
        elev = ex.get("elevation_required", None) if isinstance(ex, dict) else None

        # header line like: "#### Attack Commands: Run with `command_prompt`!  Elevation Required ..."
        elev_txt = "  Elevation Required (e.g. root or admin) " if elev is True else ""
        if ex_name:
            lines.append(f"#### Attack Commands: Run with `{ex_name}`!{elev_txt}")
            lines.append("")
        else:
            lines.append("#### Attack Commands:")
            lines.append("")

        # Commands
        cmd = ex.get("command") if isinstance(ex, dict) else None
        if cmd:
            lang = code_fence_lang(ex_name)
            lines.append(f"```{lang}")
            lines.append(md_escape_inline(cmd))
            lines.append("```")
            lines.append("")

        # Cleanup
        cleanup = ex.get("cleanup_command") if isinstance(ex, dict) else None
        if cleanup:
            lines.append("#### Cleanup Commands:")
            lines.append(f"```{code_fence_lang(ex_name)}")
            lines.append(md_escape_inline(cleanup))
            lines.append("```")
            lines.append("")
            lines.append("")

        lines.append("")
        lines.append("<br/>")
        lines.append("<br/>")
        lines.append("")

    lines.append("<br/>")
    return "\n".join(lines).rstrip() + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("yaml_file", help="Path to Txxxx.yaml")
    ap.add_argument("--out", help="Output .md path (default: same folder, same name .md)")
    ap.add_argument("--attack-desc-file", help="Text file containing ATT&CK description to embed")
    ap.add_argument("--fetch-mitre", action="store_true", help="Try fetching ATT&CK description from MITRE (optional)")
    args = ap.parse_args()

    ypath = Path(args.yaml_file).resolve()
    doc = yaml.safe_load(ypath.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise SystemExit("YAML did not parse into an object.")

    tech = md_escape_inline(doc.get("attack_technique", ""))
    attack_desc = None

    if args.attack_desc_file:
        attack_desc = read_attack_desc_from_file(Path(args.attack_desc_file))
    elif args.fetch_mitre and tech:
        attack_desc = fetch_mitre_description(tech)

    md = build_markdown(doc, attack_desc=attack_desc)

    out = Path(args.out).resolve() if args.out else ypath.with_suffix(".md")
    out.write_text(md, encoding="utf-8")
    print(f"Wrote: {out}")


if __name__ == "__main__":
    main()
