import subprocess
import os


def check_suid_sgid():
    findings = []

    try:
        # Find SUID files
        suid_result = subprocess.run(
            ["find", "/", "-perm", "-4000", "-type", "f"],
            capture_output=True,
            text=True
        )

        suid_files = suid_result.stdout.strip().splitlines()

        # Find SGID files
        sgid_result = subprocess.run(
            ["find", "/", "-perm", "-2000", "-type", "f"],
            capture_output=True,
            text=True
        )

        sgid_files = sgid_result.stdout.strip().splitlines()

        # Analyze SUID files
        for file_path in suid_files:

            try:
                file_stat = os.stat(file_path)

                owner_uid = file_stat.st_uid
                permissions = oct(file_stat.st_mode & 0o7777)

                # Root-owned SUID file
                if owner_uid == 0:
                    findings.append({
                        "severity": "INFO",
                        "type": "SUID",
                        "file": file_path,
                        "reason": "SUID file owned by root",
                        "permissions": permissions
                    })

            except (PermissionError, FileNotFoundError):
                continue

        return {
            "suid_files": suid_files,
            "sgid_files": sgid_files,
            "findings": findings
        }

    except Exception as e:
        return {
            "suid_files": [],
            "sgid_files": [],
            "findings": [],
            "error": str(e)
        }
