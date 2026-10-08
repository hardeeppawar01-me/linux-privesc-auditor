import platform
import os


def get_system_info():
    info = {
        "OS": platform.system(),
        "OS Release": platform.release(),
        "Architecture": platform.machine(),
        "Hostname": platform.node(),
        "User": os.getlogin()
    }

    return info
