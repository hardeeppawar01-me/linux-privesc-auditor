from datetime import datetime
import os


def generate_report(
    system_info,
    user_info,
    findings,
    risk_summary,
    risk_score
):

    os.makedirs("reports", exist_ok=True)

    filename = "reports/security_report.html"

    critical = risk_summary.get("CRITICAL", 0)
    high = risk_summary.get("HIGH", 0)
    medium = risk_summary.get("MEDIUM", 0)
    low = risk_summary.get("LOW", 0)

    findings_html = ""

    if findings:

        for finding in findings:

            severity = finding.get(
                "severity",
                "INFO"
            )

            title = (
                finding.get("finding")
                or finding.get("type")
                or "Security Finding"
            )

            details = (
                finding.get("details")
                or finding.get("reason")
                or ""
            )

            path = (
                finding.get("file")
                or finding.get("path")
                or ""
            )

            recommendation = finding.get(
                "recommendation",
                "Review this finding and apply appropriate security controls."
            )

            findings_html += f"""
            <div class="finding">

                <h3>{severity} — {title}</h3>

                <p>
                    <strong>Details:</strong>
                    {details}
                </p>

                <p>
                    <strong>Location:</strong>
                    {path}
                </p>

                <p>
                    <strong>Recommendation:</strong>
                    {recommendation}
                </p>

            </div>
            """

    else:

        findings_html = """
        <div class="clean">
            No security findings were detected.
        </div>
        """

    html = f"""
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<title>Linux PrivEsc Auditor Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin: 0;
    background: #f4f6f8;
    color: #222;
}}

header {{
    background: #111827;
    color: white;
    padding: 30px;
}}

header h1 {{
    margin: 0;
}}

.container {{
    max-width: 1100px;
    margin: 30px auto;
    padding: 0 20px;
}}

.cards {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 15px;
}}

.card {{
    background: white;
    padding: 20px;
    border-radius: 10px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
}}

.card h2 {{
    margin: 0;
    font-size: 30px;
}}

.section {{
    background: white;
    padding: 25px;
    margin-top: 25px;
    border-radius: 10px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
}}

.finding {{
    border-left: 5px solid #dc2626;
    background: #fafafa;
    padding: 15px;
    margin: 15px 0;
}}

.finding h3 {{
    margin-top: 0;
}}

.finding p {{
    line-height: 1.5;
}}

.clean {{
    padding: 20px;
    background: #ecfdf5;
    border-radius: 8px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

td, th {{
    padding: 10px;
    border-bottom: 1px solid #ddd;
    text-align: left;
}}

</style>

</head>

<body>

<header>

<h1>Linux PrivEsc Auditor</h1>

<p>
Privilege Escalation Security Assessment Report
</p>

</header>

<div class="container">

<div class="section">

<h2>Assessment Information</h2>

<table>

<tr>
<th>Hostname</th>
<td>{system_info.get("Hostname", "Unknown")}</td>
</tr>

<tr>
<th>User</th>
<td>{user_info.get("Username", "Unknown")}</td>
</tr>

<tr>
<th>Operating System</th>
<td>{system_info.get("OS", "Unknown")}</td>
</tr>

<tr>
<th>OS Release</th>
<td>{system_info.get("OS Release", "Unknown")}</td>
</tr>

<tr>
<th>Architecture</th>
<td>{system_info.get("Architecture", "Unknown")}</td>
</tr>

<tr>
<th>Scan Time</th>
<td>
{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
</td>
</tr>

</table>

</div>


<div class="section">

<h2>Risk Summary</h2>

<div class="cards">

<div class="card">
<h2>{critical}</h2>
<p>Critical</p>
</div>

<div class="card">
<h2>{high}</h2>
<p>High</p>
</div>

<div class="card">
<h2>{medium}</h2>
<p>Medium</p>
</div>

<div class="card">
<h2>{low}</h2>
<p>Low</p>
</div>

</div>

<p>
<strong>Total Risk Score:</strong>
{risk_score}
</p>

</div>


<div class="section">

<h2>Security Findings</h2>

{findings_html}

</div>


<div class="section">

<h2>About This Tool</h2>

<p>
Linux PrivEsc Auditor identifies potentially dangerous
Linux configurations that may contribute to privilege
escalation risk.
</p>

<p>
The tool performs security auditing and does not
automatically exploit detected weaknesses.
</p>

</div>

</div>

</body>

</html>
"""

    with open(filename, "w") as report:
        report.write(html)

    return filename
