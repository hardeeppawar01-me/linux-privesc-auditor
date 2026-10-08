import subprocess


def check_sudo():
    try:
        result = subprocess.run(
            ["sudo", "-l"],
            capture_output=True,
            text=True
        )

        output = result.stdout + result.stderr

        findings = []

        # Check for unrestricted sudo access
        if "ALL=(ALL:ALL) ALL" in output or "ALL=(ALL) ALL" in output:
            findings.append({
                "severity": "HIGH",
                "finding": "User has unrestricted sudo access",
                "details": "The user can execute commands as root."
            })

        # Check for NOPASSWD
        if "NOPASSWD" in output:
            findings.append({
                "severity": "HIGH",
                "finding": "NOPASSWD sudo rule detected",
                "details": "Some commands may be executed with sudo without a password."
            })

        return {
            "raw_output": output,
            "findings": findings
        }

    except Exception as e:
        return {
            "raw_output": "",
            "findings": [{
                "severity": "INFO",
                "finding": "Unable to check sudo permissions",
                "details": str(e)
            }]
        }
