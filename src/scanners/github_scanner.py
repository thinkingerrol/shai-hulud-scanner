#!/usr/bin/env python3
"""
GitHub scanner for Shai-Hulud Scanner
"""

import requests
from ..constants import HTTP_TIMEOUT
from ..utils.logger import log

class GitHubScanner:
    def __init__(self, token):
        self.token = token
        self.headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        self.base_url = 'https://api.github.com'
    
    def _make_request(self, endpoint):
        """Make authenticated request to GitHub API"""
        url = f"{self.base_url}/{endpoint}"
        response = requests.get(url, headers=self.headers, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        return response.json()

def scan_github(token, org, is_json=False):
    """
    Scans GitHub org for suspicious repos/branches/workflows.
    
    Args:
        token (str): GitHub token
        org (str): Organization name
        is_json (bool): JSON mode
    
    Returns:
        dict: Results with githubIssues
    """
    results = {'githubIssues': []}
    
    if not token or not org:
        if not is_json:
            log.warn('Provide both --github-token and --org for GitHub scan.')
        return results
    
    scanner = GitHubScanner(token)
    
    try:
        # List repositories for the organization
        repos = scanner._make_request(f'orgs/{org}/repos')
        
        if not is_json:
            log.cyan(f"GitHub scan for org '{org}' ({len(repos)} repos checked):")
        
        for repo in repos:
            repo_name = repo['full_name']
            
            # Repo name check
            if '-migration' in repo['name'] or repo['name'] == 'Shai-Hulud':
                results['githubIssues'].append({
                    'type': 'repo',
                    'name': repo_name
                })
                if not is_json:
                    log.warn(f"Suspicious repo: {repo_name}")
            
            # Check branches
            try:
                branches = scanner._make_request(f'repos/{org}/{repo["name"]}/branches')
                
                for branch in branches:
                    if branch['name'] == 'shai-hulud':
                        results['githubIssues'].append({
                            'type': 'branch',
                            'name': f"{repo_name} (branch: shai-hulud)"
                        })
                        if not is_json:
                            log.warn(f"Suspicious branch 'shai-hulud' in: {repo_name}")
            except requests.exceptions.RequestException:
                # Skip repo if no access
                continue
            
            # Check workflows
            try:
                workflows = scanner._make_request(f'repos/{org}/{repo["name"]}/actions/workflows')
                
                for workflow in workflows.get('workflows', []):
                    if 'shai-hulud-workflow.yml' in workflow.get('path', ''):
                        results['githubIssues'].append({
                            'type': 'workflow',
                            'name': repo_name
                        })
                        if not is_json:
                            log.warn(f"Suspicious workflow in: {repo_name}")
            except requests.exceptions.RequestException:
                # Skip if workflows not accessible
                continue
        
        if not results['githubIssues'] and not is_json:
            log.success('No GitHub issues detected.')
    
    except requests.exceptions.RequestException as e:
        error_msg = str(e)
        if not is_json:
            log.error('GitHub scan failed: ' + error_msg)
        results['githubError'] = error_msg
    except Exception as e:
        error_msg = str(e)
        if not is_json:
            log.error('GitHub scan failed: ' + error_msg)
        results['githubError'] = error_msg
    
    return results
