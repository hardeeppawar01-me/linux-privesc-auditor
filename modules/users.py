import os
import subprocess


def get_user_info():
    username = os.getlogin()

    try:
        groups = subprocess.check_output(
            ["id", "-nG", username],
            text=True
        ).strip().split()
    except subprocess.CalledProcessError:
        groups = []

    return {
        "Username": username,
        "Groups": groups
    }
