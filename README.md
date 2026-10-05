# Automated Threat Intelligence & Infrastructure Reconnaissance CLI Tool

A lightweight, modular Python-based reconnaissance tool engineered to automate infrastructure fingerprinting, threat intelligence gathering, and attack surface discovery for network artifacts (IP addresses).

---

## Key Technical Features
* **Automated Threat Intelligence:** Queries geolocation parameters, ISP routing, ASN metadata, and hosting infrastructure via external REST APIs.
* **Attack Surface Reconnaissance:** Conducts non-intrusive socket-level port scanning to identify exposed high-risk network services (e.g., SSH, HTTP, HTTPS, Web Proxies).
* **Terminal Data Visualization:** Renders structured, terminal-native security reports leveraging `rich` console panels and tabular data presentation.

---

## Installation & Prerequisites

```bash
# Clone the repository
git clone https://github.com/smlklk12/recon-threat-intel-cli.git
cd recon-threat-intel-cli

# Install dependencies
sudo apt update
sudo apt install -y python3-requests python3-rich
```

---

## Usage

Execute the tool by providing a target IPv4 address:

```bash
python3 recon_intel.py <TARGET_IP>
```

**Example:**
```bash
python3 recon_intel.py 1.1.1.1
```

---

## Verification Evidence

### CLI Intelligence Output & Port Discovery:
<img width="621" height="334" alt="imge" src="https://github.com/user-attachments/assets/3087bd39-3666-444e-a9f8-d4d05595abd7" />
