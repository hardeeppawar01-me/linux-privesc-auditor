import os


CHECK_PATHS = [
    "/etc",
    "/opt",
    "/usr/local/bin",
    "/var/www",
    "/tmp"
]


def check_writable_files():
    findings = []

    for base_path in CHECK_PATHS:

        if not os.path.exists(base_path):
            continue

        for root, dirs, files in os.walk(base_path):

            # Skip locations that generate excessive noise
            dirs[:] = [
                d for d in dirs
                if d not in {"cache", "log"}
            ]

            for filename in files:

                file_path = os.path.join(root, filename)

                try:
                    mode = os.stat(file_path).st_mode

                    # World-writable file
                    if mode & 0o002:

                        findings.append({
                            "severity": "MEDIUM",
                            "path": file_path,
                            "reason": "File is writable by everyone"
                        })

                except (PermissionError, FileNotFoundError):
                    continue

    return findings
