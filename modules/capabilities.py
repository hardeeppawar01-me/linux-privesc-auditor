import subprocess


def check_capabilities():
    findings = []

    try:
        result = subprocess.run(
            ["getcap", "-r", "/"],
            capture_output=True,
            text=True
        )

        capability_lines = result.stdout.strip().splitlines()

        for line in capability_lines:
            if not line.strip():
                continue

            parts = line.split(" ", 1)

            if len(parts) != 2:
                continue

            file_path = parts[0]
            capabilities = parts[1]

            findings.append({
                "file": file_path,
                "capabilities": capabilities
            })

        return findings

    except FileNotFoundError:
        return [{
            "error": "getcap is not installed."
        }]

    except Exception as e:
        return [{
            "error": str(e)
        }]
