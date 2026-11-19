#!/usr/bin/env python3
"""Dependency vulnerability scan against OSV.dev using the exact resolved Maven coordinates.

Usage:
    ./gradlew :app:dependencies --configuration releaseRuntimeClasspath > build/deps-release.txt
    python3 tools/osv_scan.py build/deps-release.txt [more-config-dumps...] --out docs/DEPENDENCY_REPORT.md

Only public library coordinates (group:artifact:version) are sent to https://api.osv.dev. Nothing about
the app's users or source is transmitted. Exit status is 1 if any vulnerability is found.
"""
import argparse
import datetime
import json
import re
import sys
import urllib.request

OSV = "https://api.osv.dev/v1"
LINE = re.compile(r"[+\\]--- ([\w.\-]+):([\w.\-]+):([^\s]+)(?: -> ([^\s]+))?(?: \(.*\))?$")


def parse(path):
    found = {}
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            m = LINE.search(raw.rstrip())
            if not m:
                continue
            group, artifact, requested, resolved = m.groups()
            version = resolved or requested
            if version.startswith("{") or "strictly" in version:
                continue
            found[(group, artifact, version)] = True
    return sorted(found)


def post(url, payload):
    req = urllib.request.Request(url, json.dumps(payload).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def get(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return json.load(r)


def severity(vuln):
    sev = vuln.get("database_specific", {}).get("severity")
    if sev:
        return sev
    for s in vuln.get("severity", []):
        return s.get("score", "unknown")
    return "unknown"


def fixed_versions(vuln, name):
    out = set()
    for aff in vuln.get("affected", []):
        if aff.get("package", {}).get("name") != name:
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    out.add(ev["fixed"])
    return sorted(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dumps", nargs="+")
    ap.add_argument("--out", default="docs/DEPENDENCY_REPORT.md")
    args = ap.parse_args()

    deps = sorted({d for p in args.dumps for d in parse(p)})
    if not deps:
        sys.exit("no dependencies parsed; pass the output of `gradlew :app:dependencies`")

    queries = [{"package": {"name": f"{g}:{a}", "ecosystem": "Maven"}, "version": v} for g, a, v in deps]
    hits = {}
    for i in range(0, len(queries), 500):
        res = post(f"{OSV}/querybatch", {"queries": queries[i:i + 500]})
        for dep, r in zip(deps[i:i + 500], res["results"]):
            ids = [v["id"] for v in r.get("vulns", [])]
            if ids:
                hits[dep] = ids

    details = {}
    for ids in hits.values():
        for vid in ids:
            if vid not in details:
                details[vid] = get(f"{OSV}/vulns/{vid}")

    lines = [
        "# Dependency vulnerability report",
        "",
        f"Generated {datetime.date.today().isoformat()} by `tools/osv_scan.py` against OSV.dev "
        "(aggregates GitHub Security Advisories, NVD-linked advisories and OSV-native sources) using the exact "
        "versions Gradle resolved.",
        "",
        f"- Artifacts scanned: **{len(deps)}**",
        f"- Artifacts with known vulnerabilities: **{len(hits)}**",
        f"- Distinct advisories: **{len(details)}**",
        "",
    ]
    if hits:
        lines += ["## Findings", "", "| Artifact | Version | Advisory | Severity | Fixed in | Summary |", "|---|---|---|---|---|---|"]
        for (g, a, v), ids in sorted(hits.items()):
            for vid in ids:
                d = details[vid]
                lines.append(
                    f"| {g}:{a} | {v} | {vid} | {severity(d)} | {', '.join(fixed_versions(d, f'{g}:{a}')) or 'n/a'} | "
                    f"{d.get('summary', '').replace('|', '/')[:110]} |"
                )
    else:
        lines += ["## Findings", "", "No known vulnerabilities were reported for the scanned artifacts."]
    lines += ["", "## Scanned artifacts", ""] + [f"- {g}:{a}:{v}" for g, a, v in deps]
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"scanned {len(deps)} artifacts; {len(hits)} with advisories; report -> {args.out}")
    sys.exit(1 if hits else 0)


if __name__ == "__main__":
    main()
