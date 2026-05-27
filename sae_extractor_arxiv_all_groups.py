#!/usr/bin/env python3
"""
================================================================================
WPA3-SAE Parameter Extractor (Direct RAM/Log Parsing)
================================================================================
Bypasses Monitor-Mode/Tx-Capture limitations by directly parsing the internal
cryptographic debug logs (-dd) of wpa_supplicant.
FEATURES:
- Non-blocking I/O using select() for maximum stability
- Shows the fake password used for each attempt
- Outputs results immediately when a group reaches PAIRS_PER_GROUP
- Locks channel for faster extraction
================================================================================
"""
import os, sys, time, string, random, select, subprocess

# ======================= CONFIGURATION =======================
MANAGED_IFACE = "wlanX" # Your normal Wi-Fi interface
TARGET_SSID = "Your_WiFi_Name"
TARGET_BSSID = "AA:BB:CC:DD:EE:11".lower()
TARGET_CHANNEL = "X"    # Channel of the target network
PAIRS_PER_GROUP = 20
MAX_ATTEMPTS = 10       # Skip if AP doesn't support the group
# =============================================================

SAE_GROUPS = [19, 20, 21, 22, 23, 24]
collected = {g: {"scalars": [], "finites": []} for g in SAE_GROUPS}

def clean_wpa_state():
    os.system("killall wpa_supplicant 2>/dev/null")
    os.system(f"rm -rf /var/run/wpa_supplicant/{MANAGED_IFACE} 2>/dev/null")
    
    os.system(f"ip link set {MANAGED_IFACE} down 2>/dev/null")
    time.sleep(0.1)
    
    res = subprocess.run(
        ["iw", "dev", MANAGED_IFACE, "set", "channel", str(TARGET_CHANNEL)],
        capture_output=True, text=True
    )
    
    os.system(f"ip link set {MANAGED_IFACE} up 2>/dev/null")

def main():
    if os.geteuid() != 0:
        sys.exit("[!] Root privileges required (sudo).")

    print("[*] WPA3-SAE Extractor (Bulletproof Non-Blocking Mode)")
    print(f"[*] Target: {TARGET_SSID} ({TARGET_BSSID}) on Channel {TARGET_CHANNEL}")
    print(f"[*] Mode: Immediate output per group | Pairs/Group: {PAIRS_PER_GROUP}")
    clean_wpa_state()

    for group_id in SAE_GROUPS:
        print(f"\n[*] ==========================================")
        print(f"[*] Extracting Group {group_id}...")
        print(f"[*] ==========================================")

        attempt = 1
        while len(collected[group_id]["scalars"]) < PAIRS_PER_GROUP:
            if attempt > MAX_ATTEMPTS:
                print(f"[-] Max attempts reached. Target AP likely does NOT support Group {group_id}. Skipping...")
                break

            password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
            count = len(collected[group_id]["scalars"])
            print(f"[*] Attempt {attempt}/{MAX_ATTEMPTS} -> Currently {count}/{PAIRS_PER_GROUP} pairs collected. (Using fake PW: {password})")

            # WPA Supplicant Configuration
            conf = f"""ctrl_interface=/var/run/wpa_supplicant
sae_groups={group_id}
network={{
    ssid="{TARGET_SSID}"
    scan_ssid=1
    bssid={TARGET_BSSID}
    sae_password="{password}"
    key_mgmt=SAE
    proto=RSN
    ieee80211w=2
}}"""
            with open("/tmp/temp_extract.conf", "w") as f:
                f.write(conf)

            # Run wpa_supplicant in debug mode and capture its console output
            cmd = ["wpa_supplicant", "-i", MANAGED_IFACE, "-c", "/tmp/temp_extract.conf", "-dd"]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

            scalar, elem_x, elem_y, elem_ffc = "", "", "", ""
            found_in_this_run = False
            start_time = time.time()

            # --- BULLETPROOF NON-BLOCKING READ LOOP ---
            while True:

                if time.time() - start_time > 8:
                    break

                reads, _, _ = select.select([proc.stdout], [], [], 0.5)

                if reads:

                    line = proc.stdout.readline()

                    if not line: 
                        break

                    if "SAE: own commit-scalar - hexdump" in line:
                        scalar = line.split("):")[1].strip().replace(" ", "")
                    elif "SAE: own commit-element(x) - hexdump" in line:
                        elem_x = line.split("):")[1].strip().replace(" ", "")
                    elif "SAE: own commit-element(y) - hexdump" in line:
                        elem_y = line.split("):")[1].strip().replace(" ", "")
                    elif "SAE: own commit-element - hexdump" in line: # For MODP groups (FFC)
                        elem_ffc = line.split("):")[1].strip().replace(" ", "")

                    # Stop parsing once we have all necessary parts for a commit
                    if scalar and ((elem_x and elem_y) or elem_ffc):
                        # Combine X and Y coordinates for ECC groups
                        finite = elem_x + elem_y if (elem_x and elem_y) else elem_ffc
                        if scalar not in collected[group_id]["scalars"]:
                            collected[group_id]["scalars"].append(scalar)
                            collected[group_id]["finites"].append(finite)
                            found_in_this_run = True
                            print(f"[+] ✅ Fast-Extract Success: Pair {len(collected[group_id]['scalars'])}/{PAIRS_PER_GROUP} extracted! (Triggered by fake PW: {password})")
                        break # Break the stdout-loop, we have what we need

            proc.terminate()
            proc.wait()
            clean_wpa_state()

            if found_in_this_run:
                # Reset attempts counter if we are successfully collecting data
                attempt = 1
            else:
                attempt += 1

        # --- GROUP COMPLETED: OUTPUT RESULTS IMMEDIATELY ---
        print(f"\n[*] Group {group_id} extraction finished. ({len(collected[group_id]['scalars'])} pairs)")
        print("="*80)
        print(f"SAE_SCALARS_GROUP_{group_id}_HEX = [")
        for s in collected[group_id]["scalars"]:
            print(f"    '{s}',")
        print("]")
        print(f"SAE_FINITES_GROUP_{group_id}_HEX = [")
        for f in collected[group_id]["finites"]:
            print(f"    '{f}',")
        print("]")
        print("="*80 + "\n")

    if os.path.exists("/tmp/temp_extract.conf"):
        os.remove("/tmp/temp_extract.conf")
    os.system("systemctl restart NetworkManager 2>/dev/null")

if __name__ == "__main__":
    main()
