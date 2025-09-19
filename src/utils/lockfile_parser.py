#!/usr/bin/env python3
"""
Lockfile parsing utilities for different package managers
"""

import json
import os
import re
from pathlib import Path
import yaml
from .logger import log

def parse_lockfile(directory):
    """
    Parse lockfiles for npm, Yarn, and PNPM to extract dependencies
    Returns list of {name, version} dictionaries
    """
    dependencies = []
    dir_path = Path(directory)
    
    # Try npm package-lock.json
    npm_lock = dir_path / 'package-lock.json'
    if npm_lock.exists():
        dependencies.extend(parse_npm_lockfile(npm_lock))
    
    # Try Yarn yarn.lock
    yarn_lock = dir_path / 'yarn.lock'
    if yarn_lock.exists():
        dependencies.extend(parse_yarn_lockfile(yarn_lock))
    
    # Try PNPM pnpm-lock.yaml
    pnpm_lock = dir_path / 'pnpm-lock.yaml'
    if pnpm_lock.exists():
        dependencies.extend(parse_pnpm_lockfile(pnpm_lock))
    
    return dependencies

def parse_npm_lockfile(lockfile_path):
    """Parse npm package-lock.json"""
    dependencies = []
    
    try:
        with open(lockfile_path, 'r', encoding='utf-8') as f:
            lock_data = json.load(f)
        
        # Handle different package-lock.json formats
        if 'packages' in lock_data:
            # npm v7+ format
            for package_path, package_info in lock_data['packages'].items():
                if package_path == '':  # Skip root package
                    continue
                
                name = package_path.split('node_modules/')[-1]
                version = package_info.get('version', '0.0.0')
                
                if name and version:
                    dependencies.append({'name': name, 'version': version})
        
        elif 'dependencies' in lock_data:
            # npm v6 format
            dependencies.extend(extract_npm_v6_deps(lock_data['dependencies']))
        
    except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
        log.debug(f"Failed to parse npm lockfile {lockfile_path}: {e}")
    
    return dependencies

def extract_npm_v6_deps(deps_dict):
    """Recursively extract dependencies from npm v6 format"""
    dependencies = []
    
    for name, info in deps_dict.items():
        version = info.get('version', '0.0.0')
        dependencies.append({'name': name, 'version': version})
        
        # Recursively process nested dependencies
        if 'dependencies' in info:
            dependencies.extend(extract_npm_v6_deps(info['dependencies']))
    
    return dependencies

def parse_yarn_lockfile(lockfile_path):
    """Parse Yarn yarn.lock file"""
    dependencies = []
    
    try:
        with open(lockfile_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Yarn lockfile format: "package@version", "package@^version":
        # Use regex to extract package names and versions
        pattern = r'^"?([^@\s]+)@[^"]*"?:\s*\n(?:\s+.*\n)*?\s+version\s+"([^"]+)"'
        matches = re.findall(pattern, content, re.MULTILINE)
        
        for name, version in matches:
            dependencies.append({'name': name, 'version': version})
    
    except (FileNotFoundError, Exception) as e:
        log.debug(f"Failed to parse Yarn lockfile {lockfile_path}: {e}")
    
    return dependencies

def parse_pnpm_lockfile(lockfile_path):
    """Parse PNPM pnpm-lock.yaml file"""
    dependencies = []
    
    try:
        with open(lockfile_path, 'r', encoding='utf-8') as f:
            lock_data = yaml.safe_load(f)
        
        # PNPM stores dependencies in 'packages' section
        packages = lock_data.get('packages', {})
        
        for package_spec, package_info in packages.items():
            # Package spec format: /package/version or /package/version_hash
            if package_spec.startswith('/'):
                parts = package_spec[1:].split('/')
                if len(parts) >= 2:
                    name = '/'.join(parts[:-1])
                    version_part = parts[-1]
                    # Extract version (remove hash if present)
                    version = version_part.split('_')[0]
                    
                    dependencies.append({'name': name, 'version': version})
    
    except (yaml.YAMLError, FileNotFoundError, KeyError) as e:
        log.debug(f"Failed to parse PNPM lockfile {lockfile_path}: {e}")
    
    return dependencies

def clean_version(version):
    """Clean version string by removing prefixes like ^, ~, etc."""
    return re.sub(r'^[^\d]+', '', version)
