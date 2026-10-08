import argparse

from modules.system_info import get_system_info
from modules.users import get_user_info
from modules.sudo_check import check_sudo
from modules.suid_check import check_suid_sgid
from modules.capabilities import check_capabilities
from modules.cron_check import check_cron
from modules.writable_check import check_writable_files
from modules.risk_engine import calculate_risk
from modules.report_generator import generate_report
from modules.json_report import generate_json_report
from modules.remediation import add_recommendations


def main():

    parser = argparse.ArgumentParser(
        description="Linux Privilege Escalation Security Auditor"
    )

    parser.add_argument(
        "--html",
        action="store_true",
        help="Generate HTML security report"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Generate JSON security report"
    )

    args = parser.parse_args()

    print("\n======================================")
    print("      Linux PrivEsc Auditor")
    print("======================================")

    print("\n[+] Collecting system information...")

    system_info = get_system_info()

    print("[+] Collecting user information...")

    user_info = get_user_info()

    all_findings = []

    print("[+] Checking sudo permissions...")

    sudo_results = check_sudo()
    all_findings.extend(sudo_results["findings"])

    print("[+] Checking SUID/SGID binaries...")

    suid_results = check_suid_sgid()
    all_findings.extend(suid_results["findings"])

    print("[+] Checking Linux capabilities...")

    capabilities = check_capabilities()
    all_findings.extend(capabilities)

    print("[+] Checking cron configuration...")

    cron_findings = check_cron()
    all_findings.extend(cron_findings)

    print("[+] Checking writable files...")

    writable_findings = check_writable_files()
    all_findings.extend(writable_findings)
    all_findings = add_recommendations(all_findings)

    summary, total_score = calculate_risk(all_findings)

    print("\n======================================")
    print("             RISK SUMMARY")
    print("======================================")

    print(f"Critical : {summary['CRITICAL']}")
    print(f"High     : {summary['HIGH']}")
    print(f"Medium   : {summary['MEDIUM']}")
    print(f"Low      : {summary['LOW']}")
    print(f"Risk Score: {total_score}")

    print("\n[+] Linux capabilities found:")

    if capabilities:

        for capability in capabilities:
            print(f"    {capability}")

    else:

        print("    None found")

    if args.html:

        report_file = generate_report(
            system_info,
            user_info,
            all_findings,
            summary,
            total_score
        )

        print(f"\n[+] HTML report generated: {report_file}")

    if args.json:

        json_file = generate_json_report(
            system_info,
            user_info,
            all_findings,
            summary,
            total_score
        )

        print(f"[+] JSON report generated: {json_file}")

    if not args.html and not args.json:

        print("\n[+] Scan completed.")
        print("[+] Use --html to generate an HTML report.")
        print("[+] Use --json to generate a JSON report.")


if __name__ == "__main__":
    main()
