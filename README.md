# WPA3-SAE DoS Research Suite

Welcome to the WPA3-SAE DoS Research Suite. This repository contains a Python-based framework designed to evaluate the robustness of WPA3 implementations against Denial-of-Service (DoS) attacks. It is directly based on the methodologies described in the 2022 academic paper: *"How is your Wi-Fi connection today? DoS attacks on WPA3-SAE"*.

⚠️ **DISCLAIMER:** This project is strictly for educational purposes and authorized security research. Only execute these scripts against networks you own or have explicit, documented permission to test. The authors are not responsible for any misuse.

## 📖 Overview
The WPA3-SAE (Simultaneous Authentication of Equals) handshake was designed to prevent offline dictionary attacks, but the complex cryptography involved in calculating the Password Element (PWE) makes the router's CPU and memory highly vulnerable to exhaustion attacks.

This suite contains **three core tools**:
1. `sae_extractor.py`: Automates the extraction of valid cryptographic payloads (Scalars & Finite Field Elements).
2. `WPA3-SAE_DoS_Orchestrator_20_list.py`: The **stealth-optimized** orchestrator that rotates 20 unique SAE payloads to bypass WIDS/WIPS fingerprinting.
3. `orchestator_master_en.py`: The **scientifically accurate** orchestrator that implements the paper's exact two-phase methodology, vendor-specific cases (I–XIII), and PMF amplification for reproducible research.

## 🔀 Which Orchestrator Should You Use?
| Feature | `WPA3-SAE_DoS_Orchestrator_20_list.py` | `orchestator_master_en.py` |
|:---|:---|:---|
| **Primary Goal** | Operational stealth & WIDS bypass | Academic reproducibility & exact paper alignment |
| **SAE Payloads** | Rotates 20 unique pairs per packet | Uses single, validated pair per band |
| **Radio Confusion** | Single-phase, generic cross-band logic | **Two-phase** (≈300 stress bursts → ≈200 target bursts) |
| **PMF Amplification** | Not integrated | Integrated as **Phase 3** after AP stress peak |
| **Vendor Cases** | Abstracted into unified attack types | Explicit Cases I–XIII (Broadcom/Qualcomm/MediaTek) |
| **Best For** | Red-team assessments, live environments | Academic research, vendor validation, controlled labs |

## 🛠️ Prerequisites
- A Linux environment (Kali Linux or Ubuntu recommended)
- Python 3.x with `scapy` installed (`pip install scapy`)
- Root (`sudo`) privileges
- At least one Wi-Fi adapter supporting Monitor Mode and Packet Injection (e.g., ALFA AWUS036ACM)
- `aircrack-ng` suite (for `airodump-ng` scanning)

## 🚀 Step-by-Step Usage Guide

### Phase 1: Extracting SAE Parameters
*(Required for both orchestrators)*
1. Put your managed adapter in Managed Mode and your sniffing adapter in Monitor Mode.
2. Run the extractor: `sudo python3 sae_extractor.py`
3. The script will attempt 20 connections with random passwords and output two Python arrays: `SAE_SCALAR_HEX_LIST` and `SAE_FINITE_HEX_LIST`.

### Phase 2: Configuring the Orchestrator

#### 🔹 For `WPA3-SAE_DoS_Orchestrator_20_list.py`
1. Copy the extracted arrays into the corresponding `SAE_*_HEX_LIST` blocks.
2. Set `TARGET_BSSID_*` and `MANUELLER_KANAL_*`.
3. Configure `ADAPTER_KONFIGURATION` with your desired attack (e.g., `"double_decker"`, `"omnivore"`, `"radio_confusion"`).

#### 🔹 For `orchestator_master_en.py`
1. Paste the **first valid pair** from your extraction into:
   ```python
   SAE_SCALAR_2_4_HEX = '...'
   SAE_FINITE_2_4_HEX = '...'
   SAE_SCALAR_5_HEX = '...'
   SAE_FINITE_5_HEX = '...'
   ```
2. Set `TARGET_BSSID_*` and manual channels.
3. **Critical for Radio Confusion**: Fill the band-specific MAC lists:
   ```python
   TARGET_STA_MACS_5GHZ_SPECIAL = ["Client_MAC_1", "Client_MAC_2"]  # For crashing 5GHz
   TARGET_STA_MACS_2_4GHZ_SPECIAL = ["Client_MAC_3"]                # For crashing 2.4GHz
   ```
4. Configure `ADAPTER_KONFIGURATION` using exact case names (e.g., `"case6_radio_confusion"`, `"case6_radio_confusion_reverse"`, `"cookie_guzzler"`).

### Phase 3: Launching the Attack
```bash
# For stealth-optimized attacks
sudo python3 WPA3-SAE_DoS_Orchestrator_20_list.py

# For scientifically aligned, paper-exact attacks
sudo python3 orchestator_master_en.py
```

## ⚔️ Available Attacks

### 🌐 WPA3-Specific Attacks (Modern)
| Script | Attacks |
|:---|:---|
| `20_list.py` | `omnivore`, `muted`, `hasty`, `double_decker`, `cookie_guzzler` |
| `orchestator_master_en.py` | `cookie_guzzler`, `bad_algo`, `bad_seq`, `bad_status_code`, `empty_frame_confirm` |

### 🏗️ Vendor-Specific & Cross-Band Attacks
| Script | Attacks |
|:---|:---|
| `20_list.py` | `radio_confusion` (generic), `back_to_the_future`, `amplification`, `open_auth` |
| `orchestator_master_en.py` | Cases I–XIII (Broadcom/Qualcomm/MediaTek), Two-Phase Radio Confusion, PMF Deauth Trigger, Malformed MSG1 |

### 🛡️ Client Direct Attacks
- `deauth_flood`: Standard IEEE 802.11 deauthentication (both scripts)
- `pmf_deauth_exploit`: Triggers SA Query timeout by sending spoofed unprotected deauth frames (master script only)

## 📊 Scientific Notes
- The `orchestator_master_en.py` implements **burst-mode timing** (`inter=0.0001`, 128 frames/burst) exactly as described in Section 3.3 of the paper.
- Radio Confusion follows the **two-phase sequence** from Section 6.6: ~300 bursts on the opposite band to stress the driver, followed by ~200 bursts on the target band.
- PMF amplification (Section 5) is triggered automatically after the stress peak, sending 1–2 rounds of ~60 unprotected deauth frames per STA to force immediate disconnection via SA Query timeout.
- Both scripts enforce strict IEEE 802.11-2020 §12.4.4.2 payload validation (`\x13\x00` + 32B Scalar + 64B Finite) and atomic process management for reproducible experiments.

## 📚 References
- Chatzoglou, E., Kambourakis, G., & Kolias, C. (2022). *How is your Wi-Fi connection today? DoS attacks on WPA3-SAE*. Journal of Information Security and Applications, 64, 103058.
- IEEE Std 802.11-2020, Part 11: Wireless LAN MAC and PHY Specifications.
- RFC 7664: Dragonfly Key Exchange.
