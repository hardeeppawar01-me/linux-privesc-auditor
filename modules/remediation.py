def add_recommendation(finding):

    finding_type = finding.get("type", "").upper()
    title = finding.get("finding", "").lower()
    reason = finding.get("reason", "").lower()

    recommendation = "Review this finding and apply least-privilege security controls."

    if "sudo" in finding_type or "sudo" in title:
        recommendation = (
            "Review sudo permissions and remove unnecessary "
            "privileged commands or unrestricted access."
        )

    elif "suid" in finding_type or "suid" in title:
        recommendation = (
            "Verify whether the SUID binary is required. "
            "Remove the SUID permission if it is unnecessary."
        )

    elif "capability" in finding_type:
        recommendation = (
            "Review the Linux capability and remove it if the "
            "application does not require the associated privilege."
        )

    elif "cron" in finding_type or "cron" in reason:
        recommendation = (
            "Ensure cron configuration and scheduled scripts "
            "are writable only by trusted privileged users."
        )

    elif "writable" in finding_type or "writable" in reason:
        recommendation = (
            "Restrict write permissions and ensure privileged "
            "files are not writable by untrusted users."
        )

    finding["recommendation"] = recommendation

    return finding


def add_recommendations(findings):

    updated_findings = []

    for finding in findings:

        updated_findings.append(
            add_recommendation(finding)
        )

    return updated_findings
