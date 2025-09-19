#!/usr/bin/env python3
"""
Constants for Shai-Hulud Scanner
"""

import re

# Known malicious bundle.js hash from Shai-Hulud worm
BUNDLE_HASH = "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"

# Suspicious postinstall script patterns
SUSPICIOUS_POSTINSTALL = re.compile(r"(node\s+bundle\.js|trufflehog|webhook\.site|exfiltrat)", re.IGNORECASE)

# Suspicious IOCs (Indicators of Compromise)
SUSPICIOUS_IOCS = re.compile(r"(webhook\.site|bb8ca5f6-4175-45d2-b042-fc9ebb8170b7|shai-hulud|trufflehog)", re.IGNORECASE)

# Scanner version
VERSION = "1.1.0"

# Default affected list URL
DEFAULT_BADLIST_URL = "https://raw.githubusercontent.com/Amruth-SV/shai-hulud-scanner/main/affected-packages.json"

# Timeout for HTTP requests (seconds)
HTTP_TIMEOUT = 10

# Maximum file size to scan (bytes)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
