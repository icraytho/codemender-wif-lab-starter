import json
import sys
import os

if len(sys.argv) < 2:
    print("Usage: python3 cm_triage.py <path_to_report.json>")
    sys.exit(1)

report_path = sys.argv[1]
try:
    with open(report_path, 'r') as f:
        data = json.load(f)
except Exception as e:
    print(f"Error reading report: {e}")
    sys.exit(1)

# Assuming data is a list of findings or dict with 'findings'
findings = data.get('findings', []) if isinstance(data, dict) else data
if not isinstance(findings, list):
    findings = []

severities = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
max_sev_value = 0
max_sev_name = "NONE"
fix_ids = []

for finding in findings:
    sev = finding.get('severity', 'LOW').upper()
    fid = finding.get('id', '')
    if fid:
        fix_ids.append(fid)
    if severities.get(sev, 0) > max_sev_value:
        max_sev_value = severities.get(sev, 0)
        max_sev_name = sev

with open(os.environ.get('GITHUB_OUTPUT', 'output.txt'), 'a') as f:
    f.write(f"fix_ids={' '.join(fix_ids)}\n")
    f.write(f"max_severity={max_sev_name}\n")

print(f"Triage complete. Max severity: {max_sev_name}")
print(f"Findings: {len(findings)}")
