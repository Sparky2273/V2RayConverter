<div align="center">

<h1>⚡ V2Ray Converter</h1>

<p><strong>A free, open-source desktop tool to convert V2Ray / Xray proxy configs between URI format and full JSON format — instantly, offline, and with a clean GUI.</strong></p>

<p>
  <img src="https://img.shields.io/badge/version-1.0.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/python-3.8%2B-yellow?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/GUI-PyQt6-purple?style=flat-square" alt="PyQt6">
  <img src="https://img.shields.io/badge/offline-100%25-brightgreen?style=flat-square" alt="Offline">
  <img src="https://img.shields.io/badge/single--file-yes-orange?style=flat-square" alt="Single File">
</p>

<p>
  <a href="#-quick-start-windows-exe">⚡ Quick Start (EXE)</a> ·
  <a href="#-supported-protocols--transports">Protocols</a> ·
  <a href="#-features">Features</a> ·
  <a href="#-run-from-source">Run from Source</a> ·
  <a href="#-how-to-use">How to Use</a> ·
  <a href="#-troubleshooting">Troubleshooting</a>
</p>

</div>

---

## 📖 Table of Contents

- [What Is This?](#-what-is-this)
- [Supported Protocols & Transports](#-supported-protocols--transports)
- [Features](#-features)
- [Quick Start — Windows EXE](#-quick-start-windows-exe)
- [Run from Source](#-run-from-source)
- [How to Use](#-how-to-use)
- [Conversion Examples](#-conversion-examples)
- [Troubleshooting](#-troubleshooting)
- [FAQ](#-faq)
- [Contact & Support](#-contact--support)
- [License](#-license)

---

## 🔍 What Is This?

**V2Ray Converter** is a desktop application that converts proxy configurations for [V2Ray](https://www.v2ray.com/) and [Xray-core](https://github.com/XTLS/Xray-core) between two formats:

- **URI / Share Link** — compact one-line format used for sharing configs (e.g. `vless://...`, `vmess://...`, `trojan://...`, `ss://...`)
- **JSON Config** — the full V2Ray/Xray JSON configuration file format used by the clients directly

You can convert **either direction**:

```
vless://uuid@server:443?...#MyNode   ←→   { "outbounds": [ { "protocol": "vless", ... } ] }
```

**Who is this for?**
- Anyone using V2Ray, Xray, or compatible clients (v2rayN, v2rayNG, Nekoray, Hiddify, etc.)
- People who receive share links and need the full JSON config, or vice versa
- Network administrators and developers working with proxy configurations
- Users in countries with internet filtering who need to configure their clients manually

Everything runs **100% locally** — no internet connection, no server, no data sent anywhere.

---

## 🔌 Supported Protocols & Transports

### Protocols

| Protocol | URI → JSON | JSON → URI |
|---|---|---|
| **VLESS** | ✅ | ✅ |
| **VMess** | ✅ | ✅ |
| **Trojan** | ✅ | ✅ |
| **Shadowsocks (SS)** | ✅ | ✅ |

### Transports (Network Types)

| Transport | Aliases Recognized |
|---|---|
| **WebSocket** | `ws`, `websocket` |
| **TCP / RAW** | `tcp`, `raw` |
| **HTTP/2** | `h2`, `http` |
| **gRPC** | `grpc` |
| **XHTTP / SplitHTTP** | `xhttp`, `splithttp` |
| **HTTPUpgrade** | `httpupgrade` |
| **mKCP** | `kcp`, `mkcp` |
| **QUIC** | `quic` |

### Security / TLS Options

| Option | Supported |
|---|---|
| TLS | ✅ SNI, fingerprint, ALPN, allowInsecure |
| REALITY | ✅ pbk, sid, spx, fingerprint, SNI |
| No TLS | ✅ |
| Flow (xtls-rprx-vision) | ✅ |

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔄 **Bidirectional** | Convert JSON → URI **or** URI → JSON — both directions fully supported |
| 🤖 **Auto-Detect** | Automatically figures out which direction to convert — no manual selection needed |
| 📦 **Batch Mode** | Paste multiple URIs or JSON configs at once — all converted in one click |
| 🎨 **Light / Dark Theme** | Toggle between light and dark UI themes with one click |
| 📋 **Clipboard Integration** | Paste from clipboard with one button; copy output with one button |
| 📂 **File Load & Save** | Load configs from `.json` or `.txt` files; save output to file |
| 🖱️ **Drag & Drop** | Drag a config file directly onto the window to load it |
| 🔗 **Chained Conversion** | "Use as Input" button moves output back to input for chained conversions |
| 📊 **Live Log Panel** | Timestamped log of every operation with color-coded INFO / SUCCESS / ERROR |
| 🧵 **Non-Blocking** | Conversion runs in a background QThread — the UI never freezes on large batches |
| 💾 **Saves Preferences** | Remembers your last theme, window size, and mode choice between sessions |
| 🧪 **Sample Config** | Built-in "Insert Sample" to test the tool immediately |
| 📦 **Single File** | Entire app is one Python file — easy to audit, share, and run |

---

## ⚡ Quick Start (Windows EXE)

No Python installation needed.

1. Go to the [**Releases**](../../releases) page of this repository.
2. Download `V2RayConverter.exe`.
3. Double-click it — the app opens immediately. No installation, no setup.
4. Paste your V2Ray URI or JSON config into the input box and click **⚡ Convert**.

> The app is fully portable — you can run it from any folder or a USB drive.

---

## 🐍 Run from Source

Run the script directly with Python if you prefer not to use the EXE.

### Requirements

- Python 3.8 or newer — [https://www.python.org/downloads/](https://www.python.org/downloads/)
  - Windows: tick ✅ **"Add Python to PATH"** during installation
- PyQt6 (the only non-standard dependency)

### Step 1 — Get the Script

Download `V2RayConverter_V1.py` from this repository (click the file → click the download icon), or clone:

```bash
git clone https://github.com/YOUR_USERNAME/V2RayConverter.git
cd V2RayConverter
```

### Step 2 — Install Dependencies

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install PyQt6
```

### Step 3 — Run

```bash
python V2RayConverter_V1.py
```

The app window opens immediately.

---

## 📖 How to Use

### Basic Conversion

1. **Paste your input** into the left/top panel:
   - A V2Ray URI like `vless://...` or `vmess://...`
   - A full JSON config (the contents of a `config.json` file)
   - Multiple URIs or configs at once (one per line or separated by blank lines)

2. **Choose conversion direction** (optional):
   - **Auto** — the app detects which direction automatically *(recommended)*
   - **→ JSON** — forces URI-to-JSON conversion
   - **→ URI** — forces JSON-to-URI conversion

3. **Click ⚡ Convert**

4. The result appears in the output panel on the right. You can:
   - Click **Copy** to copy the output to your clipboard
   - Click **Save** to save it to a file
   - Click **Use as Input** to feed the output back in for a chained conversion

### Loading from a File

- Click **Load File** and browse to a `.json` or `.txt` file
- Or **drag and drop** a file anywhere onto the app window

### Batch Conversion

Paste multiple items at once — for example, paste 10 VLESS URIs (one per line). The app converts all of them and shows results separated with labels.

### Theme Toggle

Click the **☀️ / 🌙** button in the top-right corner to switch between light and dark themes.

---

## 📋 Conversion Examples

### VLESS URI → JSON

**Input:**
```
vless://12345678-abcd-abcd-abcd-123456789abc@example.com:443?encryption=none&security=tls&type=ws&host=example.com&path=%2Fws&sni=example.com&fp=chrome#My-Node
```

**Output:** Full V2Ray/Xray JSON config with `inbounds`, `outbounds`, `dns`, and `routing` sections — ready to use directly in your client.

---

### VMess URI → JSON

**Input:**
```
vmess://eyJ2IjoiMiIsInBzIjoiTXlOb2RlIiwiYWRkIjoiZXhhbXBsZS5jb20iLCJwb3J0IjoiNDQzIiwiaWQiOiIxMjM0NTY3OC1hYmNkLWFiY2QtYWJjZC0xMjM0NTY3ODlhYmMiLCJhaWQiOiIwIiwic2N5IjoiYXV0byIsIm5ldCI6IndzIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiZXhhbXBsZS5jb20iLCJwYXRoIjoiL3dzIiwidGxzIjoidGxzIiwic25pIjoiZXhhbXBsZS5jb20iLCJhbHBuIjoiIiwiZnAiOiIifQ==
```

**Output:** Full JSON config with all VMess settings expanded and readable.

---

### JSON → VLESS URI

**Input:** Paste a full V2Ray JSON config with a VLESS outbound.

**Output:**
```
vless://12345678-abcd-abcd-abcd-123456789abc@example.com:443?encryption=none&security=tls&type=ws&host=example.com&path=%2Fws&sni=example.com#proxy
```

---

## 🔧 Troubleshooting

**App does not open / crashes immediately**
→ Make sure you are on Windows 10 or newer.
→ Try running from source with Python to see the error message (see [Run from Source](#-run-from-source)).

**"No module named PyQt6" when running the script**
→ Run `pip install PyQt6` and try again.
→ Make sure you are running the correct Python (try `python3 -m pip install PyQt6`).

**Conversion gives an error**
→ Check your input is a valid V2Ray URI (starts with `vless://`, `vmess://`, `trojan://`, or `ss://`) or a valid V2Ray JSON config.
→ Try the **Insert Sample** option from the menu to test with a known-good input.

**VMess URI output does not match my client's format**
→ Different clients sometimes produce slightly different VMess URI encodings. The output here follows the standard v2 format used by most clients (v2rayN, Nekoray, etc.).

**The window is blank / shows no content**
→ Try resizing the window. On some systems with display scaling, the layout may need a resize to render correctly.

---

## ❓ FAQ

**Q: Does this send my configs anywhere?**
A: No. Everything runs locally on your machine. No network connections are made. Your configs never leave your computer.

**Q: Can I use this on Linux or macOS?**
A: Yes — run from source with Python. The Windows EXE is Windows-only, but the Python script works on all platforms.

**Q: What V2Ray clients are compatible with the JSON output?**
A: The output follows the standard V2Ray/Xray JSON config format, compatible with v2rayN (Windows), v2rayNG (Android), Nekoray, Hiddify, and any client that uses a standard V2Ray/Xray core.

**Q: What is the `v2ray_converter_config.json` file?**
A: The app saves your preferences (theme, window size, last mode) to this file in the same folder. It is safe to delete — the app will recreate it with defaults.

**Q: Can it handle configs with REALITY security?**
A: Yes. REALITY parameters (`pbk`, `sid`, `spx`, fingerprint, SNI) are fully supported in both directions.

---

## 🔧 Related Tools

- [MasterHttpRelayVPN](https://github.com/Sparky2273/MasterHttpRelayVPN) — VPN client
  that bypasses censorship using Google Apps Script relay

---

## 📬 Contact & Support

- **Telegram:** [@Sparky2273](https://t.me/Sparky2273)
- **Email:** mhashemi6699@gmail.com
- **Bug Reports & Suggestions:** [Open a GitHub Issue](../../issues)

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

You are free to use, copy, modify, merge, publish, distribute, and share this software freely.

---

<div align="center">

**Made with ❤️ by SPARKS**

*Simple tools for a free internet.*

</div>
