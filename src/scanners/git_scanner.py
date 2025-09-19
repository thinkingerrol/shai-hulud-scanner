#!/usr/bin/env python3
"""
Git scanner for Shai-Hulud Scanner
"""

import os
import re
import subprocess
from pathlib import Path
from ..utils.logger import log

def scan_git_repository(directory, is_json=False):
    """
    Scans local git repository for Shai-Hulud indicators without GitHub API
    
    Args:
        directory (str): Project directory
        is_json (bool): JSON output mode
    
    Returns:
        dict: Scan results with gitIssues
    """
    results = {'gitIssues': []}
    
    # Check if it's a git repository
    git_dir = Path(directory) / '.git'
    if not git_dir.exists():
        # Silently return - UI will handle this
        return results
    
    try:
        # Check for suspicious branches
        try:
            result = subprocess.run(
                ['git', 'branch', '-a'],
                cwd=directory,
                capture_output=True,
                text=True,
                check=True
            )
            branches = [
                b.strip().replace('*', '').strip()
                for b in result.stdout.split('\n')
                if b.strip()
            ]
        except subprocess.CalledProcessError:
            branches = []
        
        suspicious_branches = []
        for branch in branches:
            lower_branch = branch.lower()
            if (
                'shai-hulud' in lower_branch or
                'exfiltrate' in lower_branch or
                'malware' in lower_branch or
                'backdoor' in lower_branch or
                # Only flag migration if it's specifically suspicious, not legitimate migrations
                ('migration' in lower_branch and (
                    'shai' in lower_branch or
                    'hulud' in lower_branch or
                    'worm' in lower_branch or
                    'malicious' in lower_branch
                ))
            ):
                suspicious_branches.append(branch)
        
        if suspicious_branches:
            results['gitIssues'].append({
                'type': 'suspicious-branch',
                'branches': suspicious_branches,
                'reason': 'Branch names match Shai-Hulud patterns'
            })
            # Silently add to results - UI will handle display
        
        # Check recent commits for suspicious patterns
        try:
            result = subprocess.run(
                ['git', 'log', '--oneline', '-20'],
                cwd=directory,
                capture_output=True,
                text=True,
                check=True
            )
            recent_commits = result.stdout
        except subprocess.CalledProcessError:
            recent_commits = ""
        
        suspicious_commit_patterns = [
            re.compile(r'shai-hulud', re.IGNORECASE),
            re.compile(r'add.*bundle\.js', re.IGNORECASE),  # Only flag if actually adding bundle.js
            re.compile(r'postinstall.*malicious', re.IGNORECASE),
            re.compile(r'trufflehog', re.IGNORECASE),
            re.compile(r'webhook\.site', re.IGNORECASE),
            re.compile(r'exfiltrat', re.IGNORECASE),
            re.compile(r'malicious.*package', re.IGNORECASE),
            re.compile(r'backdoor', re.IGNORECASE)
        ]
        
        suspicious_commits = []
        for commit in recent_commits.split('\n'):
            for pattern in suspicious_commit_patterns:
                if pattern.search(commit):
                    suspicious_commits.append(commit.strip())
                    break
        
        if suspicious_commits:
            # Remove duplicates while preserving order
            unique_commits = []
            seen = set()
            for commit in suspicious_commits:
                if commit not in seen:
                    unique_commits.append(commit)
                    seen.add(commit)
            
            results['gitIssues'].append({
                'type': 'suspicious-commits',
                'commits': unique_commits,
                'reason': 'Commit messages contain suspicious patterns'
            })
            # Silently add to results - UI will handle display
        
        # Check for suspicious files in git history
        try:
            result = subprocess.run(
                ['git', 'log', '--name-only', '--pretty=format:', '--since=30 days ago'],
                cwd=directory,
                capture_output=True,
                text=True,
                check=True
            )
            added_files = result.stdout
        except subprocess.CalledProcessError:
            added_files = ""
        
        suspicious_files = []
        for file_name in added_files.split('\n'):
            file_name = file_name.strip()
            if not file_name:
                continue
            
            lower_file = file_name.lower()
            if (
                'bundle.js' in lower_file or
                'shai-hulud' in lower_file or
                'malware' in lower_file or
                'backdoor' in lower_file or
                # Only flag specific suspicious file patterns
                ('postinstall' in lower_file and '.js' in lower_file)
            ):
                suspicious_files.append(file_name)
        
        if suspicious_files:
            # Remove duplicates while preserving order
            unique_files = []
            seen = set()
            for file_name in suspicious_files:
                if file_name not in seen:
                    unique_files.append(file_name)
                    seen.add(file_name)
            
            results['gitIssues'].append({
                'type': 'suspicious-files-added',
                'files': unique_files,
                'reason': 'Suspicious files added in recent commits'
            })
            if not is_json:
                log.warn('Suspicious files added recently:')
                for file_name in unique_files:
                    log.gray(f"  {file_name}")
        
        # Check remote URLs for suspicious patterns
        try:
            result = subprocess.run(
                ['git', 'remote', '-v'],
                cwd=directory,
                capture_output=True,
                text=True,
                check=True
            )
            remotes = result.stdout
            
            suspicious_remotes = [
                line for line in remotes.split('\n')
                if line and ('Shai-Hulud' in line or 'shai-hulud' in line)
            ]
            
            if suspicious_remotes:
                results['gitIssues'].append({
                    'type': 'suspicious-remote',
                    'remotes': suspicious_remotes,
                    'reason': 'Git remotes point to suspicious repositories'
                })
                if not is_json:
                    log.warn('Suspicious git remotes found')
        except subprocess.CalledProcessError:
            # Skip if no remotes
            pass
        
        # Check for unsigned commits (only warn if there are other suspicious indicators)
        try:
            result = subprocess.run(
                ['git', 'log', '--pretty=format:%H %G?', '-10'],
                cwd=directory,
                capture_output=True,
                text=True,
                check=True
            )
            unsigned_commits = result.stdout
            
            has_unsigned_recent = any(
                'N' in line or 'U' in line
                for line in unsigned_commits.split('\n')
                if line
            )
            
            # Only flag unsigned commits if there are other suspicious findings
            if has_unsigned_recent and results['gitIssues']:
                results['gitIssues'].append({
                    'type': 'unsigned-commits',
                    'reason': 'Unsigned commits detected alongside other suspicious indicators'
                })
                if not is_json:
                    log.warn('Recent commits are not GPG signed (combined with other suspicious activity)')
        except subprocess.CalledProcessError:
            # Skip if GPG not configured
            pass
    
    except Exception as error:
        if not is_json:
            log.warn(f"Git scan failed: {error}")
        results['gitError'] = str(error)
    
    # Results will be displayed in the main UI
    return results
