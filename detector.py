import os
import sys
import re
import base64
import binascii

MAX_DELTA_MB = 3
REPO_INFO = "repo_info.txt"
WHITELIST_FILE = "whitelist.txt"

# Regex for GitHub tokens (ghp_, gho_).
TOKEN_REGEX = re.compile(r"(gh[po]_)")

# Regex for suspicious network calls.
NETWORK_REGEX = re.compile(r"(?:fetch|XMLHttpRequest)\([^)]*?(https?:\/\/[^\s\"')]+)", re.IGNORECASE)

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


def load_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        return set()
    with open(WHITELIST_FILE, "r") as f:
        return set(line.strip() for line in f if line.strip())


def save_whitelist(whitelist):
    with open(WHITELIST_FILE, "w") as f:
        for url in sorted(whitelist):
            f.write(url + "\n")


def scan_for_tokens(bundle_path, strict_mode=False):
    with open(bundle_path, "r", errors="ignore") as f:
        text = f.read()

    findings = False
    whitelist = load_whitelist()

    # Check for gh tokens.
    tokens = TOKEN_REGEX.findall(text)
    if tokens:
        findings = True
        print(f"\n{Colors.WARNING}Potential GitHub token prefixes detected in the bundle:{Colors.ENDC}")
        for t in tokens:
            print(f"  Detected prefix: {Colors.FAIL}{t}{Colors.ENDC}")

    # Check for suspicious calls.
    suspicious_calls = NETWORK_REGEX.findall(text)
    if suspicious_calls:
        print(f"\n{Colors.WARNING}Network calls detected:{Colors.ENDC}")
        for url in suspicious_calls:
            if url not in whitelist:
                findings = True
                if strict_mode:
                    print(f"  {Colors.FAIL}Unwhitelisted URL detected (strict mode): {url}{Colors.ENDC}")
                    sys.exit(1)
                else:
                    print(f"  {Colors.FAIL}Unwhitelisted URL detected: {url}{Colors.ENDC}")
                    choice = input(f"Do you want to add this URL to the whitelist? (y/n): ").strip().lower()
                    if choice == "y":
                        whitelist.add(url)
                        save_whitelist(whitelist)
                        print(f"{Colors.OKGREEN}Added {url} to whitelist.{Colors.ENDC}")
            else:
                print(f"  {Colors.OKGREEN}Whitelisted URL allowed: {url}{Colors.ENDC}")

    # Check for suspicious b64 strings.
    b64_strings = re.findall(r"[A-Za-z0-9+/=]{30,}", text)
    for s in b64_strings:
        try:
            decoded = base64.b64decode(s).decode("utf-8", errors="ignore")
            if TOKEN_REGEX.search(decoded):
                findings = True
                print(f"\n{Colors.FAIL}Token prefix detected in base64-encoded string.{Colors.ENDC}")
        except Exception:
            continue

    # Check for suspicious hex strings
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
        print(f"\n{Colors.OKGREEN}No obvious GitHub tokens or unapproved network calls detected.{Colors.ENDC}")


def main():
    strict_mode = "--strict" in sys.argv

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

    scan_for_tokens(bundle_path, strict_mode)


if __name__ == "__main__":
    main()
