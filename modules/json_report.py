import json
import os
from datetime import datetime


def generate_json_report(
    system_info,
    user_info,
    findings,
    risk_summary,
    risk_score
):

    os.makedirs("reports", exist_ok=True)

    report = {
        "tool": "Linux PrivEsc Auditor",
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "system_info": system_info,
        "user_info": user_info,
        "risk_summary": risk_summary,
        "risk_score": risk_score,
        "findings": findings
    }

    filename = "reports/security_report.json"

    with open(filename, "w") as file:
        json.dump(report, file, indent=4)

    return filename
