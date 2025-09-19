# Shai-Hulud Checker

**Shai-Hulud Checker** is a Python tool to monitor and inspect JavaScript bundle.js files in your project to see if Shai-Hulud has been injected. It helps maintain manageable bundle sizes and detect potential security issues such as exposed GitHub token prefixes (ghp_, gho_) and suspicious network calls.  

---

## Features

- File Size Monitoring
  - Tracks current bundle size in MB
  - Compares with a baseline to detect excessive growth
  - Warns if the bundle grows too much between checks

- Security Scanning
  - Detects GitHub token prefixes (ghp_, gho_) in the bundle
  - Checks for suspicious network calls (fetch() / XMLHttpRequest) that may exfiltrate data
  - Scans for base64 or hex-encoded token prefixes

- Persistent Configuration
  - Remembers the last used bundle.js path in a file for convenience

- Readable and Color-Coded Output
  - Neutral colors for file info and bundle size
  - Warnings in yellow, errors in red, successful checks in green  

---

## Usage

1. Run the tool:

python check_bundle_size.py

2. On first run, it will ask for the path to your bundle.js file
3. The script will automatically store this path in repo_info.txt for future runs  

---

### Example Output

Bundle file: dist/bundle.js
Current bundle size: 3.45 MB
Bundle size growth is within acceptable limit (+0.12 MB)
No obvious GitHub token access patterns or suspicious network calls detected  

If any warnings are detected:

Warning: Bundle size increased by 4.2 MB since last check (limit 3 MB)
Potential GitHub token prefixes detected in the bundle:
  Detected prefix: ghp_
Suspicious network calls detected (may indicate data exfiltration):
  Call type: fetch  

---

## Configuration

- MAX_DELTA_MB — Maximum allowed bundle size growth (default: 3 MB, Shai-Hulud Size)
- REPO_INFO — Stores last used bundle path (repo_info.txt)  

---

## Notes

- This tool does not decode full tokens, it only checks for the presence of token prefixes (ghp_, gho_).
- Use this tool as part of your CI/CD pipeline to prevent accidental token exposure and maintain bundle size discipline.
- If change in path for bundle.js, please delete the repo_info.txt file and run the file again.
- This tool can be used for uncompiled malware other than Shai-Hulud as well.

