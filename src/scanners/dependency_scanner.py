#!/usr/bin/env python3
"""
Dependency scanner for Shai-Hulud Scanner
"""

import json
import os
from pathlib import Path
from ..utils.lockfile_parser import parse_lockfile, clean_version
from ..utils.logger import log

def scan_dependencies(directory, bad_packages, is_json=False):
    """
    Scans dependencies for bad packages.
    
    Args:
        directory (str): Project directory
        bad_packages (dict): Badlist dictionary
        is_json (bool): JSON mode
    
    Returns:
        dict: Results with badDeps and totalScanned
    """
    results = {'badDeps': [], 'totalScanned': 0}
    
    # Parse package.json
    dependencies = {}
    try:
        pkg_path = Path(directory) / 'package.json'
        with open(pkg_path, 'r', encoding='utf-8') as f:
            pkg = json.load(f)
        
        # Merge dependencies and devDependencies
        dependencies.update(pkg.get('dependencies', {}))
        dependencies.update(pkg.get('devDependencies', {}))
    except (FileNotFoundError, json.JSONDecodeError):
        if not is_json:
            log.error('No package.json found.')
        return results
    
    # Count direct dependencies
    direct_deps_count = len(dependencies)
    
    # Check direct dependencies
    for name, version in dependencies.items():
        cleaned_version = clean_version(version)
        if name in bad_packages and cleaned_version in bad_packages[name]:
            results['badDeps'].append({'name': name, 'version': cleaned_version})
    
    # Check lockfile (ALL packages, not just those in package.json)
    lockfile_deps = parse_lockfile(directory)
    unique_lockfile_deps = set()
    
    for dep in lockfile_deps:
        name = dep['name']
        version = dep['version']
        unique_lockfile_deps.add(name)
        
        if name in bad_packages and version in bad_packages[name]:
            # Always add vulnerable packages from lockfile, regardless of package.json
            if not any(d['name'] == name and d['version'] == version for d in results['badDeps']):
                results['badDeps'].append({'name': name, 'version': version})
    
    # Total scanned = direct deps + unique lockfile deps (transitive)
    results['totalScanned'] = max(direct_deps_count, len(unique_lockfile_deps))
    
    # Only show detailed output in verbose mode or JSON
    if results['badDeps'] and not is_json:
        # Results will be shown in the main UI, keep quiet here
        pass
    
    return results
