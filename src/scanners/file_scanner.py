#!/usr/bin/env python3
"""
File scanner for Shai-Hulud Scanner
"""

import hashlib
import json
import os
import re
from pathlib import Path
from glob import glob
from ..constants import BUNDLE_HASH, SUSPICIOUS_POSTINSTALL, SUSPICIOUS_IOCS, MAX_FILE_SIZE
from ..utils.logger import log

def scan_files(directory, is_json=False):
    """
    Scans files for bundle.js hash and suspicious scripts/IOCs.
    
    Args:
        directory (str): Project directory
        is_json (bool): JSON mode
    
    Returns:
        dict: Results with suspiciousFiles and suspiciousScripts
    """
    results = {'suspiciousFiles': [], 'suspiciousScripts': []}
    node_modules = Path(directory) / 'node_modules'
    
    if not node_modules.exists():
        # Silently return - UI will handle this
        return results
    
    # Scan bundle.js hash
    js_files = glob(str(node_modules / '**/bundle.js'), recursive=True)
    for file_path in js_files:
        try:
            file_path_obj = Path(file_path)
            if file_path_obj.stat().st_size > MAX_FILE_SIZE:
                continue  # Skip very large files
            
            with open(file_path, 'rb') as f:
                content = f.read()
            
            file_hash = hashlib.sha256(content).hexdigest()
            if file_hash == BUNDLE_HASH:
                issue = {
                    'type': 'bundle.js',
                    'path': file_path,
                    'hash': file_hash
                }
                results['suspiciousFiles'].append(issue)
                # Silently add to results - UI will handle display
        except (OSError, IOError):
            # Skip unreadable files
            continue
    
    # Scan package.json for scripts and IOCs
    pkg_files = glob(str(node_modules / '**/package.json'), recursive=True)
    for file_path in pkg_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                pkg = json.load(f)
            
            has_issue = False
            
            # Check postinstall scripts
            scripts = pkg.get('scripts', {})
            postinstall = scripts.get('postinstall', '')
            if postinstall and SUSPICIOUS_POSTINSTALL.search(postinstall):
                results['suspiciousScripts'].append({
                    'path': file_path,
                    'script': postinstall
                })
                has_issue = True
                # Silently add to results - UI will handle display
            
            # Check for suspicious IOCs in package content
            content = json.dumps(pkg)
            ioc_match = SUSPICIOUS_IOCS.search(content)
            if ioc_match:
                results['suspiciousFiles'].append({
                    'type': 'IOC',
                    'path': file_path,
                    'details': ioc_match.group(0),
                    'packageName': pkg.get('name', 'unknown')
                })
                has_issue = True
                # Silently add to results - UI will handle display
            
            # Additional check for actual GitHub tokens (not just any ghp_ pattern)
            token_pattern = re.compile(r'ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}')
            token_matches = token_pattern.findall(content)
            if token_matches:
                # Only flag if it's not in a comment or documentation field
                is_in_documentation = (
                    'description' in content and 'example' in content or
                    'readme' in content or
                    'documentation' in content
                )
                
                if not is_in_documentation:
                    results['suspiciousFiles'].append({
                        'type': 'GitHub-Token',
                        'path': file_path,
                        'details': 'Potential GitHub token detected',
                        'packageName': pkg.get('name', 'unknown')
                    })
                    has_issue = True
                    # Silently add to results - UI will handle display
            
            if has_issue and not is_json:
                pass  # Already logged
                
        except (json.JSONDecodeError, OSError, IOError):
            # Skip invalid JSON or unreadable files
            continue
    
    return results
