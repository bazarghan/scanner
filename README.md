<h1 align="center">
  Advanced Multi-Threaded Network Scanner
</h1>

<p align="center">
  <strong>A high-performance Python TUI tool for deep network diagnostics, IP scanning, Server Name Indication (SNI) proxy evaluation, and DNS Tunneling scoring.</strong>
</p>

---

## 🚀 Overview

This scanner is designed for rigorous networking tests, combining high-speed concurrency, memory-efficient LCGs (Linear Congruential Generators) for IP randomization, and an interactive CLI heavily powered by the `Rich` framework. 

It handles fetching ASNs seamlessly directly via APIs, organizes target configurations intelligently via local folders, and maps active server configurations instantaneously back to their owner frameworks (e.g. tracking generic targets matching Cloudflare endpoints).

## ⚡ Features

### 1. 🌐 IP Target & Port Scanner
* **Mass Range Support:** Input millions of IPs via CIDRs, IP intervals (e.g., `192.168.0.1-192.168.0.100`), single IPs, or load massive dynamically fetched blocks.
* **Smart LCG Randomization:** Search IP spaces randomly to discover active servers faster without needing to sequential scan thousands of dead IPs. Wait times drop efficiently.
* **Live Connectivity Checking:** Connects simultaneously across 500+ threads using concurrent sockets to extract delays natively inside Python.

### 2. 🌍 ASN & Country Native Fetching
Directly fetches the entirety of a Country Code's (e.g., `IR`, `US`) IPv4 registry or an ASN's (e.g., `AS15169`) announced paths via native RIPE stat APIs.
Automatically deposits these lists into `custom_ranges/` decoupled safely from your primary `ip_ranges/` logic.

### 3. 🔍 Advanced SNI Target Scanner
Validate domains explicitly against network firewalls checking proxy capacity:
* Accepts massive domain sets (e.g., 1000+ extracted configurations).
* Processes seamlessly inside the concurrent queue handling raw IP extraction.
* Multi-faceted connectivity scoring: Performs simultaneous checks returning precise latency mappings across **DNS Resolutions**, explicit **ICMP Pings**, Raw **TCP connections** to port 443, and successfully wrapped **TLS Handshakes** specifying target SNI servers!

### 4. 🕳️ DNS Tunneling Evaluation
Validates isolated DNS resolution hosts looking for UDP/TCP anomalies, raw Record recursions (`TXT`, `NULL`, `EDNS0` sizes) applying complex heuristic algorithms evaluating them out of a `/100` susceptibility score!

### 5. 📂 Interactive Smart Navigation
Forget remembering paths, file extensions, or manual typing limits.
Drop a text file into your active system folder (`ip_ranges`, `custom_ranges`, `sni`, `port_ranges`). The terminal will dynamically spin it up identically into an easily accessible numeric menu list! Simply pass `1` or `1, 3` into the interface prompts dynamically.

## 🛠 Prerequisites & Installation

**System Requirements**
- `Python 3.9+` (Recommended)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/bazarghan/scanner.git
   cd scanner
   ```

2. **Install core Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   *(Required packages: `rich`, `tqdm`, `dnspython`)*

## 💡 Quick Start Structure

Keep all your datasets natively segmented inside respective folders. 

```
scanner/
├── scanner.py          <-- Main Executable
├── requirements.txt 
│
├── ip_ranges/          <-- Populate with root target origins (e.g., cloudflare.txt)
├── custom_ranges/      <-- System downloads ASN/Country prefixes here automatically!
├── port_ranges/        <-- Drop configuration texts (e.g., standard_ports.txt containing '80,443')
├── sni/                <-- Provide massive lists of testing domains (e.g., popular.txt)
│
└── results/            <-- Dynamically created folder saving timestamped JSON/TXT matrices
```

## 🎮 Execution
Launch the GUI and browse the menu interactions effortlessly:
```bash
python scanner.py
```
