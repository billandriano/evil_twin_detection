import subprocess
import re
from collections import defaultdict

def scan_networks():
    # Run the netsh wlan command to get network data
    result = subprocess.check_output(['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'], encoding='utf-8')
    return result

def parse_output(output):
    networks = defaultdict(set)
    current_ssid = None

    # Regex patterns
    ssid_pattern = re.compile(r"^\s*SSID\s+\d+\s+:\s+(.*)")
    bssid_pattern = re.compile(r"^\s*BSSID\s+\d+\s+:\s+([0-9a-fA-F:-]{17})")

    for line in output.splitlines():
        ssid_match = ssid_pattern.match(line)
        bssid_match = bssid_pattern.match(line)

        if ssid_match:
            current_ssid = ssid_match.group(1).strip()
        elif bssid_match and current_ssid:
            bssid = bssid_match.group(1).strip().lower()
            networks[current_ssid].add(bssid)

    return networks

def detect_evil_twins(networks):
    print("\n[*] Analysis complete.\n")
    for ssid, bssids in networks.items():
        if len(bssids) > 1:
            if ssid!="Thales_Guest":
                print(f"[!!] Potential Evil Twin Detected for SSID '{ssid}'")
            for bssid in bssids:
               if ssid!="Thales_Guest":
                   print(f"     - BSSID: {bssid}")
        else:
            print(f"[OK] SSID '{ssid}' has only one BSSID.")

if __name__ == "__main__":
    print("[*] Scanning nearby Wi-Fi networks...")
    output = scan_networks()
    networks = parse_output(output)
    detect_evil_twins(networks)
