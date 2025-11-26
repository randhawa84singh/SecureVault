import subprocess
import uuid
import re

# ====================================================
# MAC Address (reliable)
# ====================================================

def get_mac():
    mac = uuid.getnode()
    return f"{mac:012x}"

# ====================================================
# System UUID (best replacement for CPU ID on ARM)
# ====================================================

def get_system_uuid():
    try:
        output = subprocess.check_output(
            ["powershell", "-Command", "(Get-CimInstance Win32_ComputerSystemProduct).UUID"],
            stderr=subprocess.DEVNULL
        )
        return output.decode().strip()
    except:
        return "UUID_FAIL"

# ====================================================
# Disk Serial
# ====================================================

def get_disk_serial():
    try:
        output = subprocess.check_output(
            ["powershell", "-Command", "(Get-PhysicalDisk).SerialNumber"],
            stderr=subprocess.DEVNULL
        )
        lines = [l.strip() for l in output.decode().split("\n") if l.strip()]
        return lines[0] if lines else "DISK_NOT_FOUND"
    except:
        return "DISK_FAIL"


# ====================================================
# PRINT EVERYTHING
# ====================================================

if __name__ == "__main__":
    print("=== MACHINE IDENTIFIERS ===")
    print(f"MAC Address      : {get_mac()}")
    print(f"System UUID      : {get_system_uuid()}")
    print(f"Disk Serial      : {get_disk_serial()}")
