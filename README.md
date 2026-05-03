# WPA3-SAE DoS Research Suite

An open‑source research suite for evaluating the resilience of WPA3‑SAE implementations against Denial‑of‑Service attacks.  
Based on the scientific paper:  
**"How is your Wi‑Fi connection today? DoS attacks on WPA3‑SAE"**  
Efstratios Chatzoglou, Georgios Kambourakis, Constantinos Kolias  
*Journal of Information Security and Applications*, 64 (2022) 103058

---

## Recommended Hardware

For the best results when conducting the WPA3‑SAE DoS attacks described in the paper, have two Wi‑Fi adapters at hand:

**Injection adapter**  
   - **Alfa AWUS036ACH** (802.11ac, Realtek RTL8812AU chipset)  
     This was the attacker’s primary adapter in the paper. It was used to fire the large bursts of spoofed SAE Commit and Auth frames (frame injection).  
   - Any other adapter built on the **Realtek RTL8812AU chipset** will also do. The key requirement is reliable packet injection in monitor mode.

---

## 📦 What’s Inside

| Script | Purpose |
|:---|:---|
| `sae_extractor.py` | Automatically extracts 20 valid SAE parameter pairs (Scalar + Finite) via simulated failed authentications. |
| `WPA3‑SAE_DoS_Orchestrator_20_list.py` | **Stealth‑optimised** orchestrator – rotates 20 unique SAE payloads to bypass WIDS/WIPS fingerprinting. |
| `orchestator_master_en.py` | **Scientifically accurate** orchestrator – implements the paper’s exact two‑phase methodology, vendor‑specific cases I–XIII, and PMF amplification for reproducible experiments. |

---

## 🔀 Which Orchestrator Should You Use?

| Feature | `WPA3‑SAE_DoS_Orchestrator_20_list.py` | `orchestator_master_en.py` |
|:---|:---|:---|
| **Primary Goal** | Operational stealth & WIDS bypass | Academic reproducibility & exact paper alignment |
| **SAE Payloads** | Rotates 20 unique pairs per packet | Rotates 20 unique **paired** Scalars & Finites per band (anti‑fingerprinting) |
| **Radio Confusion** | Single‑phase, generic cross‑band logic | **Two‑phase** (≈300 stress bursts → ≈200 target bursts) |
| **PMF Amplification** | Not integrated | Integrated as **Phase 3** after AP stress peak |
| **Vendor Cases** | Abstracted into unified attack types | Explicit Cases I–XIII (Broadcom/Qualcomm/MediaTek) |
| **Channel Scanner** | Yes (robust channel detection) | Yes (identical scanner logic) |
| **Best For** | Red‑team assessments, live environments | Academic research, vendor validation, controlled labs |

---

## ⚡ The "20-List" Advantage

Early implementations of WPA3 DoS attacks sent the exact same cryptographic payload over and over again (single Scalar/Finite element). While these early DoS scripts sent identical payloads that simple WIPS/Firewall rules could easily fingerprint and drop before processing, this suite rotates 20 unique payloads to mimic a highly realistic, distributed burst of connection attempts.

Note: The WPA3 Anti-Clogging Mechanism (ACM) itself only relies on connection thresholds and token exchanges—it does not perform payload anomaly detection. However, rotating valid payloads ensures the attack traffic remains indistinguishable from legitimate devices, proactively bypassing potential heuristic WIDS/WIPS filters that monitor for static, repeated elliptic curve points.

**This orchestrator implements a 20-List Rotation:** 
By extracting 20 unique SAE parameter pairs (using 20 different fake passwords) and randomly rotating them for every single packet sent, the attack bypasses payload-fingerprinting. The router views every incoming packet as a completely new, legitimate connection attempt from a unique client, forcing it to allocate RAM and CPU cycles for each request, ultimately leading to device exhaustion.

## ⚙️ Prerequisites

| Component | Version / Note |
|:---|:---|
| Operating System | Kali Linux or Ubuntu (recommended) |
| Python | 3.8 or newer |
| External Package | Scapy (`pip install scapy`) |
| Privileges | **root** (sudo) |
| Wi‑Fi Adapter | At least one supporting Monitor Mode + Packet Injection |
| Aircrack‑ng Suite | For the optional channel scanner (`airodump-ng`) |
| wpa_supplicant | For the SAE extractor (usually pre‑installed) |

---

## 🚀 Step‑by‑Step Usage Guide

### Step 1: Clone the Repository

```bash
git clone https://github.com/Nuseo1/WPA3-SAE-DoS-Research-Suite.git
cd WPA3-SAE-DoS-Research-Suite
pip install scapy
```

### Step 2: Extract SAE Parameters

1. Put one adapter into **Managed Mode** (for connection attempts).  
2. Put a second adapter into **Monitor Mode** (for sniffing).  
3. Edit `sae_extractor.py`:

```python
MANAGED_IFACE = "wlan1"           # Normal adapter (Managed Mode)
MONITOR_IFACE = "wlan0mon"       # Monitor‑Mode adapter
TARGET_SSID = "Your_SSID"
TARGET_BSSID = "AA:BB:CC:DD:EE:11".lower()
TARGET_CHANNEL = "11"
NUM_PAIRS = 20
```

4. Run the extractor:

```bash
sudo python3 sae_extractor.py
```

The process will take several minutes—it performs 20 separate connection attempts with random passwords. At the end you will receive two Python lists: **`SAE_SCALAR_HEX_LIST`** and **`SAE_FINITE_HEX_LIST`**.

### Step 3: Configure the Orchestrator

#### 🔸 For `WPA3-SAE_DoS_Orchestrator_20_list.py` (stealth)

1. Copy the extracted lists into the corresponding blocks.  
2. Set `TARGET_BSSID_*` and the manual channels.  
3. Fill `ADAPTER_KONFIGURATION` with your desired attacks, e.g.:

```python
ADAPTER_KONFIGURATION = {
    "wlan0mon": {"band": "2.4GHz", "angriff": "double_decker"},
    "wlan1mon": {"band": "5GHz",  "angriff": "cookie_guzzler"}
}
```

#### 🔸 For `orchestator_master_en.py` (scientific)

1. Insert the extracted arrays into `SAE_SCALAR_2_4_HEX_LIST`, `SAE_FINITE_2_4_HEX_LIST`, `SAE_SCALAR_5_HEX_LIST`, and `SAE_FINITE_5_HEX_LIST`.  
2. Set `TARGET_BSSID_*` and the manual channels.  
3. **Critical for Radio Confusion:** Enter the actual client MACs into the band‑specific lists:

```python
TARGET_STA_MACS_5GHZ_SPECIAL  = ["Client_MAC_1", "Client_MAC_2"]  # Clients currently on 5 GHz
TARGET_STA_MACS_2_4GHZ_SPECIAL = ["Client_MAC_3"]                # Clients currently on 2.4 GHz
```

4. Configure `ADAPTER_KONFIGURATION` with exact case names, e.g.:

```python
ADAPTER_KONFIGURATION = {
    "wlan0mon": {"band": "2.4GHz", "angriff": "case6_radio_confusion"},
    "wlan1mon": {"band": "5GHz",  "angriff": "case6_radio_confusion_reverse"}
}
```

### Step 4: Launch the Attack

```bash
# Stealth‑optimised attack
sudo python3 WPA3-SAE_DoS_Orchestrator_20_list.py

# Scientifically accurate attack
sudo python3 orchestator_master_en.py
```

Stop with **Ctrl + C** – resources will be cleaned up automatically.

---

## ⚔️ Available Attacks

### 🌐 Generic WPA3 Attacks (Paper Section 4)

| Attack | 20‑List | Master | Description |
|:---|:---:|:---:|:---|
| `cookie_guzzler` | ✅ | ✅ | Cookie Guzzler (Variant I) – same MAC per burst |
| `omnivore` | ✅ | – | Memory Omnivore – ACM below threshold |
| `muted` | ✅ | – | Muted Peer – ACM‑based flooding |
| `hasty` | ✅ | – | Hasty Peer – Commit+Confirm mixed |
| `double_decker` | ✅ | – | Omnivore + Muted combined |
| `bad_algo` | – | ✅ | Invalid authentication algorithm |
| `bad_seq` | – | ✅ | Invalid sequence number |
| `bad_status_code` | – | ✅ | Invalid status code |
| `empty_frame_confirm` | – | ✅ | Empty SAE Confirm frame |

### 🏗️ Vendor‑Specific Attacks (Paper Section 6)

| Attack | 20‑List | Master | Affected Chipsets |
|:---|:---:|:---:|:---|
| `case1_denial_of_internet` | – | ✅ | Broadcom |
| `case2_bad_auth_algo_broadcom` | – | ✅ | Broadcom |
| `case3_bad_status_code` | – | ✅ | Broadcom |
| `case4_bad_send_confirm` | – | ✅ | Broadcom |
| `case5_empty_frame` | – | ✅ | Broadcom |
| `case6_radio_confusion` | – | ✅ | Broadcom (crashes 5 GHz) |
| `case6_radio_confusion_reverse` | – | ✅ | Broadcom (crashes 2.4 GHz) |
| `case7_back_to_the_future` | – | ✅ | Broadcom (WPA2↔WPA3) |
| `case8_bad_auth_algo_qualcomm` | – | ✅ | Qualcomm |
| `case9_bad_sequence_number` | – | ✅ | Qualcomm |
| `case10a_bad_auth_body_empty` | – | ✅ | Qualcomm |
| `case10b_bad_auth_body_payload` | – | ✅ | Qualcomm |
| `case11_seq_status_fuzz` | – | ✅ | Qualcomm |
| `case12_bursty_auth` | – | ✅ | MediaTek |
| `case13_radio_confusion_mediatek` | – | ✅ | MediaTek (crashes 2.4 GHz) |
| `case13_radio_confusion_mediatek_reverse` | – | ✅ | MediaTek (crashes 5 GHz) |
| `back_to_the_future` | ✅ | – | WPA2 AP overload with WPA3 packets |
| `amplification` | ✅ | – | ESS‑wide amplification |
| `open_auth` | ✅ | – | Open auth request flooding |

### 🛡️ Client‑Direct Attacks

| Attack | 20‑List | Master | Description |
|:---|:---:|:---:|:---|
| `deauth_flood` | ✅ | ✅ | Standard deauth flood |
| `pmf_deauth_exploit` | – | ✅ | SA Query timeout trigger (Paper Section 5) |
| `malformed_msg1` | – | ✅ | Malformed MSG1 of the 4‑way handshake |

---

## 📊 Scientific Notes

* `orchestator_master_en.py` implements **burst‑mode timing** (`inter=0.0001`, 128 frames/burst) exactly as described in Section 3.3 of the paper.  
* Radio Confusion follows the **two‑phase sequence** from Section 6.6:  
  – ~300 bursts on the opposite band to stress the driver,  
  – followed by ~200 bursts on the target band.  
* PMF amplification (Section 5) is triggered automatically after the stress peak, sending 1–2 rounds of ~60 unprotected deauth frames per client to force immediate disconnection via SA Query timeout.  
* **Cryptographic Pair Integrity:** Every Scalar is always sent together with its mathematically matching Finite Field Element. The implementation couples the two lists through index‑parallel filtering (`zip()`) so that only complete, valid pairs are injected – identical to what a legitimate client would produce.  
* All attack functions use **Scapy’s Raw‑layer encapsulation** and strictly adhere to IEEE 802.11‑2020 §12.4.4.2 payload formatting.  
* An optional channel scanner ensures that attack processes automatically follow the target channel if the access point changes channels.

---

## 📚 References

* Chatzoglou, E., Kambourakis, G., & Kolias, C. (2022). *How is your Wi‑Fi connection today? DoS attacks on WPA3‑SAE*. Journal of Information Security and Applications, 64, 103058.  
* IEEE Std 802.11‑2020, Part 11: Wireless LAN MAC and PHY Specifications.  
* RFC 7664: Dragonfly Key Exchange.

---

## 🤝 Contributing

Contributions are welcome – please open an issue or submit a pull request. Make sure your code follows the same scientific standards (IEEE‑compliant payloads, paired SAE parameters, reproducible timing).

---

## 📄 License

This project is licensed under the MIT License.

---

## ⚠️ Disclaimer

This software is intended **exclusively** for educational and research purposes as well as authorised security assessments. Only run these scripts against networks you own or for which you have explicit written permission. The authors accept no responsibility for misuse.
