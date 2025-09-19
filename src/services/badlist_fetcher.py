#!/usr/bin/env python3
"""
Affected list fetcher service for Shai-Hulud Scanner
"""

import json
import os
import requests
from pathlib import Path
from ..constants import DEFAULT_BADLIST_URL, HTTP_TIMEOUT
from ..utils.logger import log

CACHE_FILENAME = "affected-packages-cache.json"

def fetch_remote_affected_list(url=DEFAULT_BADLIST_URL):
    """
    Fetches fresh affected list from remote URL every time the tool runs.
    Returns affected list dictionary
    """
    try:
        response = requests.get(url, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        
        affected_list = response.json()
        
        # Validate structure
        if not isinstance(affected_list, dict):
            raise ValueError("Invalid affected list format")
        
        package_count = len([k for k in affected_list.keys() if not k.startswith('_')])
        log.info(f"Fetched latest affected-packages.json from remote ({package_count} packages).")
        
        return affected_list
        
    except requests.exceptions.RequestException as e:
        raise Exception(f"Network error: {e}")
    except json.JSONDecodeError as e:
        raise Exception(f"Failed to parse remote affected-packages.json: {e}")
    except Exception as e:
        raise Exception(f"Failed to fetch remote affected list: {e}")

def load_cached_badlist():
    """
    Loads cached badlist from current directory if it exists.
    Returns affected list dictionary or None if cache doesn't exist or is invalid.
    """
    cache_path = Path.cwd() / CACHE_FILENAME
    
    if not cache_path.exists():
        return None
    
    try:
        with open(cache_path, 'r', encoding='utf-8') as f:
            cached_list = json.load(f)
        
        # Validate structure
        if not isinstance(cached_list, dict):
            return None
        
        package_count = len([k for k in cached_list.keys() if not k.startswith('_')])
        log.info(f"📦 Using cached affected-packages.json ({package_count} packages).")
        
        return cached_list
        
    except (json.JSONDecodeError, IOError):
        return None

def save_cached_badlist(affected_list):
    """
    Saves affected list to cache file in current directory.
    """
    cache_path = Path.cwd() / CACHE_FILENAME
    
    try:
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(affected_list, f, indent=2)
        log.debug(f"Cached affected list to {cache_path}")
    except IOError as e:
        log.warn(f"Failed to cache affected list: {e}")

def get_badlist():
    """
    Gets affected list by checking cache first, then fetching fresh data if needed.
    Returns affected list dictionary
    """
    # First check if we have a cached version
    cached_list = load_cached_badlist()
    if cached_list is not None:
        return cached_list
    
    try:
        # Fetch fresh data and cache it
        affected_list = fetch_remote_affected_list()
        save_cached_badlist(affected_list)
        return affected_list
        
    except Exception as error:
        # Only use local fallback file if remote fetch fails and no cache exists
        log.warn(f"Remote fetch failed: {error}")
        log.info("Falling back to local affected-packages.json...")
        
        try:
            # Look for local affected list file
            script_dir = Path(__file__).parent.parent.parent
            local_affected_list_path = script_dir / 'affected-packages.json'
            
            with open(local_affected_list_path, 'r', encoding='utf-8') as f:
                local_affected_list = json.load(f)
            
            package_count = len([k for k in local_affected_list.keys() if not k.startswith('_')])
            log.info(f"📦 Using local affected-packages.json ({package_count} packages).")
            
            return local_affected_list
            
        except (FileNotFoundError, json.JSONDecodeError) as e:
            log.error("Failed to load local affected-packages.json. Cannot proceed without threat intelligence.")
            raise Exception("No affected list available - ensure affected-packages.json exists and is readable")
