# PhantomLdr

![Status](https://img.shields.io/badge/status-stable-green?style=flat-square)
![Python](https://img.shields.io/badge/python-3.x-blue?style=flat-square)

**PhantomLdr** is a binary stager tool designed for red team operators and malware analysts. It embeds raw shellcode into benign-looking files using a 4-byte marker, simulating payload delivery and file manipulation techniques observed in advanced persistent threats (APT).

> ⚠️ **Disclaimer:** This tool is for **educational and authorized security research only**. Use it in **isolated environments** or during **authorized penetration testing engagements**. The developer assumes no responsibility for misuse.

---

## 🎯 Use Case

PhantomLdr is ideal for:

- Red Team payload staging simulations
- Malware evasion and forensic evasion research
- Detection rule testing (EDR, AV, YARA)
- Malware reverse engineering training labs

---

## ✨ Features

- Embeds arbitrary shellcode into any non-sensitive file
- Avoids tampering with sensitive/critical extensions (e.g., `.exe`, `.dll`)
- Custom 4-byte ASCII marker for locating payload in post-processing

---

## ⚙️ Requirements

- Python 3.x
- [pyfiglet](https://pypi.org/project/pyfiglet/)

Install dependencies:

```bash
pip install pyfiglet
```
