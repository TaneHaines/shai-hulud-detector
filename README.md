# Shai-Hulud Checker

**Shai-Hulud Checker** is a Python tool to monitor and inspect JavaScript files in your project. It reports whether malware has potentially been injected. The tool cam detect potential security issues such as exposed GitHub token prefixes (ghp_, gho_) and suspicious network calls.  

---

## Features
- Security Scanning
  - Checks for access to Raw IP Addresses and Common Crypto Extensions.
  - Detects GitHub token prefixes (ghp_, gho_) in the bundle
  - Checks for suspicious network calls (fetch() / XMLHttpRequest) that may exfiltrate data
  - Scans for base64 or hex-encoded token prefixes

---

## Usage

1. Run the tool:

python3 detector.py

2. On first run, it will ask for the path to your js file
3. The script will automatically store this path in repo_info.txt for future runs  
---

## Notes

- This tool does not decode full tokens, it only checks for the presence of token prefixes (ghp_, gho_).
- Use this tool as part of your CI/CD pipeline to prevent accidental token exposure and maintain bundle size discipline.
- If change in path for bundle.js, please delete the repo_info.txt file and run the file again.
- This tool can be used for uncompiled malware other than Shai-Hulud as well.

