# check_bundle_size.py
import os
import sys
import re
import base64
import binascii

MAX_DELTA_MB = 3
REPO_INFO = "repo_info.txt"

# Regex for GitHub tokens (ghp_, gho_)
TOKEN_REGEX = re.compile(r"(gh[po]_)")

# Regex for suspicious network calls (fetch/xhr to external domains)
NETWORK_REGEX = re.compile(r"(fetch|XMLHttpRequest)\([^)]*https?:\/\/", re.IGNORECASE)

# ANSI colors
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def bytes_to_mb(size):
    return round(size / (1024 * 1024), 2)


def setup():
    bundle_path = input(f"{Colors.OKBLUE}Enter the path to your bundle.js (default: dist/bundle.js): {Colors.ENDC}").strip()
    if not bundle_path:
        bundle_path = "dist/bundle.js"

    if not os.path.exists(bundle_path):
        print(f"{Colors.FAIL}Error: No bundle file found at '{bundle_path}'. Exiting.{Colors.ENDC}")
        sys.exit(1)

    return bundle_path


def scan_for_filesize(bundle_path):
    size = os.path.getsize(bundle_path)
    size_mb = bytes_to_mb(size)
    print(f"\n{Colors.HEADER}Bundle file: {bundle_path}{Colors.ENDC}  {Colors.OKGREEN}✔{Colors.ENDC}")
    print(f"{Colors.HEADER}Current bundle size: {size_mb} MB{Colors.ENDC} {Colors.OKGREEN}✔{Colors.ENDC}\n")

    if os.path.exists(bundle_path):
        with open(bundle_path, "r") as f:
            old_size = float(f.read().strip())
        delta = size_mb - old_size
        if delta > MAX_DELTA_MB:
            print(f"{Colors.WARNING}Warning: Bundle size increased by {delta:.2f} MB since last check (limit {MAX_DELTA_MB} MB).{Colors.ENDC}")
        else:
            print(f"{Colors.OKGREEN}Bundle size growth is within acceptable limit (+{delta:.2f} MB).{Colors.ENDC}")
    else:
        print(f"{Colors.OKBLUE}No previous baseline found. Creating baseline for future comparisons.{Colors.ENDC}")

    with open(bundle_path, "w") as f:
        f.write(str(size_mb))


def scan_for_tokens(bundle_path):
    with open(bundle_path, "r", errors="ignore") as f:
        text = f.read()

    findings = False

    tokens = TOKEN_REGEX.findall(text)
    if tokens:
        findings = True
        print(f"\n{Colors.WARNING}Potential GitHub token prefixes detected in the bundle:{Colors.ENDC}")
        for t in tokens:
            print(f"  Detected prefix: {Colors.FAIL}{t}{Colors.ENDC}")

    suspicious_calls = NETWORK_REGEX.findall(text)
    if suspicious_calls:
        findings = True
        print(f"\n{Colors.WARNING}Suspicious network calls detected (may indicate data exfiltration):{Colors.ENDC}")
        for call in suspicious_calls:
            print(f"  Call type: {Colors.FAIL}{call}{Colors.ENDC}")

    b64_strings = re.findall(r"[A-Za-z0-9+/=]{30,}", text)
    for s in b64_strings:
        try:
            decoded = base64.b64decode(s).decode("utf-8", errors="ignore")
            if TOKEN_REGEX.search(decoded):
                findings = True
                print(f"\n{Colors.FAIL}Token prefix detected in base64-encoded string.{Colors.ENDC}")
        except Exception:
            continue

    hex_strings = re.findall(r"(?:[0-9a-fA-F]{2}){10,}", text)
    for s in hex_strings:
        try:
            decoded = bytes.fromhex(s).decode("utf-8", errors="ignore")
            if TOKEN_REGEX.search(decoded):
                findings = True
                print(f"\n{Colors.FAIL}Token prefix detected in hex-encoded string.{Colors.ENDC}")
        except (binascii.Error, ValueError):
            continue

    if not findings:
        print(f"\n{Colors.OKGREEN}No obvious GitHub token access patterns or suspicious network calls detected.{Colors.ENDC}")


def main():
    if os.path.exists(REPO_INFO):
        with open(REPO_INFO, "r") as f:
            content = f.read().strip()
            if content:
                bundle_path = content
            else:
                input(f"{Colors.OKBLUE}Initial setup required. Press Enter to continue...{Colors.ENDC}")
                bundle_path = setup()
                with open(REPO_INFO, "w") as wf:
                    wf.write(bundle_path)
    else:
        input(f"{Colors.OKBLUE}Initial setup required. Press Enter to continue...{Colors.ENDC}")
        bundle_path = setup()
        with open(REPO_INFO, "w") as wf:
            wf.write(bundle_path)

    scan_for_filesize(bundle_path)
    scan_for_tokens(bundle_path)


if __name__ == "__main__":
    main()
