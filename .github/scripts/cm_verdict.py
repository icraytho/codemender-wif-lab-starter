import json
import os
import sys

# Statuses that mean "cm looked at this again and does not believe it".
# Anything else, including an inconclusive or missing status, is treated as
# still worth fixing. Verification staying silent is not the same as
# verification saying no.
BLOCKING = {"DISMISSED", "EXPLOIT_FAILED"}

if len(sys.argv) < 3:
    print("Usage: python3 cm_verdict.py <path_to_report.json> <finding_id>")
    sys.exit(1)

report_path, finding_id = sys.argv[1], sys.argv[2]

try:
    with open(report_path, 'r') as f:
        data = json.load(f)
except Exception as e:
    print(f"Error reading report: {e}")
    data = []

findings = data.get('findings', []) if isinstance(data, dict) else data
if not isinstance(findings, list): findings = []

match = None
for finding in findings:
    # Handle both lowercase (custom json) and uppercase (cm schema) keys
    fid = finding.get('FindingID') or finding.get('id') or ''
    # cm accepts an ID prefix, so the report may carry the full UUID even
    # though we verified using a shorter form.
    if fid == finding_id or fid.startswith(finding_id) or finding_id.startswith(fid):
        match = finding
        break

if match is None:
    status = "NOT_FOUND"
    confidence = ""
else:
    status = (match.get('Status') or match.get('status') or '').upper() or "UNKNOWN"
    confidence = match.get('Confidence', match.get('confidence', ''))

blocked = status in BLOCKING
fix_id = "" if blocked else finding_id

with open(os.environ.get('GITHUB_OUTPUT', 'output.txt'), 'a') as f:
    f.write(f"verdict={status}\n")
    f.write(f"fix_id={fix_id}\n")

print(f"Finding:    {finding_id}")
print(f"Status:     {status}" + (f" (confidence: {confidence}%)" if confidence != "" else ""))

if blocked:
    print("Verdict:    not exploitable. Skipping remediation for this finding.")
elif status == "NOT_FOUND":
    print("Verdict:    finding missing from the report. Proceeding with remediation anyway.")
elif status == "VERIFIED":
    print("Verdict:    confirmed exploitable. Proceeding with remediation.")
else:
    print("Verdict:    inconclusive. Proceeding with remediation.")
