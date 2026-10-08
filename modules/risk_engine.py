SEVERITY_SCORE = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0
}


def calculate_risk(findings):
    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    total_score = 0

    for finding in findings:
        severity = finding.get("severity", "INFO").upper()

        if severity in summary:
            summary[severity] += 1
            total_score += SEVERITY_SCORE[severity]

    return summary, total_score
