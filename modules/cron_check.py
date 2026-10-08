import os


CRON_PATHS = [
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly"
]


def check_cron():
    findings = []

    for path in CRON_PATHS:

        if not os.path.exists(path):
            continue

        # If it's a file
        if os.path.isfile(path):

            if os.access(path, os.W_OK):
                findings.append({
                    "severity": "HIGH",
                    "path": path,
                    "reason": "Cron configuration is writable"
                })

        # If it's a directory
        elif os.path.isdir(path):

            try:
                for root, dirs, files in os.walk(path):

                    for filename in files:
                        file_path = os.path.join(root, filename)

                        if os.access(file_path, os.W_OK):
                            findings.append({
                                "severity": "HIGH",
                                "path": file_path,
                                "reason": "Cron file is writable"
                            })

            except PermissionError:
                continue

    return findings
