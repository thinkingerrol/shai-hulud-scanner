#!/usr/bin/env python3
"""
Enhanced UI utilities for beautiful terminal output
"""

from colorama import Fore, Style, init
from .logger import log

# Initialize colorama
init(autoreset=True)

def create_banner(version):
    """Create clean ASCII art banner"""
    return f"""{Fore.CYAN}
   _____ __          _ __  __          __          __
  / ___// /_  ____ _(_) / / /_  __  __/ /_  ______/ /
  \\__ \\/ __ \\/ __ `/ / /_/ __ \\/ / / / / / / / __  / 
 ___/ / / / / /_/ / / /_/ / / / /_/ / / /_/ / /_/ /  
/____/_/ /_/\\__,_/_/_/ /_/ /_/\\__,_/_/\\__,_/\\__,_/   {Fore.WHITE}v{version}

\t\t\t{Fore.LIGHTBLACK_EX}by Amruth{Style.RESET_ALL}
"""

def create_header(path, version, is_git_repo):
    """Create clean header"""
    return create_banner(version)

def create_results_section(results, duration):
    """Create clean results section"""
    total_issues = results.get('totalIssues', 0)
    bad_deps = results.get('badDeps', [])
    suspicious_files = results.get('suspiciousFiles', [])
    git_issues = results.get('gitIssues', [])
    total_scanned = results.get('totalScanned', 0)
    scanned_dir = results.get('scannedDir', '')
    
    duration_sec = duration / 1000.0
    
    output = f"\nTarget: {Fore.WHITE}{scanned_dir}{Style.RESET_ALL}\n\n"
    
    if total_issues > 0:
        # Show warnings first
        if bad_deps:
            output += f"{Fore.YELLOW}[WRN]{Style.RESET_ALL} Found {len(bad_deps)} compromised packages\n"
        if suspicious_files:
            output += f"{Fore.YELLOW}[WRN]{Style.RESET_ALL} Found {len(suspicious_files)} suspicious files\n"
        if git_issues:
            output += f"{Fore.YELLOW}[WRN]{Style.RESET_ALL} Found {len(git_issues)} git-based threats\n"
    
    # Always show info
    output += f"{Fore.BLUE}[INF]{Style.RESET_ALL} Scanned {total_scanned} dependencies in {duration_sec:.1f}s\n"
    
    if total_issues == 0:
        output += f"{Fore.GREEN}[INF]{Style.RESET_ALL} No security threats detected\n"
    else:
        output += f"{Fore.RED}[ERR]{Style.RESET_ALL} {total_issues} security issues require attention\n"
    
    return output

def create_summary(results, duration):
    """Create scan summary in minimal format"""
    total_issues = results.get('totalIssues', 0)
    bad_deps = results.get('badDeps', [])
    suspicious_files = results.get('suspiciousFiles', [])
    suspicious_scripts = results.get('suspiciousScripts', [])
    git_issues = results.get('gitIssues', [])
    total_scanned = results.get('totalScanned', 0)
    
    critical_issues = len(bad_deps) if bad_deps else 0
    file_threats = len(suspicious_files or []) + len(suspicious_scripts or [])
    duration_sec = duration / 1000.0
    
    git_was_scanned = git_issues is not None
    git_status = 'skipped' if not git_was_scanned else ('threats found' if git_issues else 'clean')
    
    output = '\n'
    
    # Status
    status_text = 'SECURE' if total_issues == 0 else 'THREATS DETECTED'
    status_color = Fore.GREEN if total_issues == 0 else Fore.RED
    output += f"{Fore.BLUE}[INF]{Style.RESET_ALL} Security status: {status_color}{status_text}{Style.RESET_ALL}\n"
    
    # Metrics
    output += f"{Fore.BLUE}[INF]{Style.RESET_ALL} Dependencies scanned: {total_scanned}\n"
    critical_color = Fore.GREEN if critical_issues == 0 else Fore.RED
    output += f"{Fore.BLUE}[INF]{Style.RESET_ALL} Critical threats: {critical_color}{critical_issues}{Style.RESET_ALL}\n"
    file_color = Fore.GREEN if file_threats == 0 else Fore.YELLOW
    output += f"{Fore.BLUE}[INF]{Style.RESET_ALL} File threats: {file_color}{file_threats}{Style.RESET_ALL}\n"
    
    if git_status == 'clean':
        git_color = Fore.GREEN
    elif git_status == 'skipped':
        git_color = Fore.LIGHTBLACK_EX
    else:
        git_color = Fore.RED
    output += f"{Fore.BLUE}[INF]{Style.RESET_ALL} Git scan result: {git_color}{git_status}{Style.RESET_ALL}\n"
    output += f"{Fore.BLUE}[INF]{Style.RESET_ALL} Scan duration: {duration_sec:.1f}s\n"
    
    return output

def create_recommendations():
    """Create security recommendations in minimal format"""
    output = '\n'
    
    output += f"{Fore.BLUE}[INF]{Style.RESET_ALL} Security recommendations:\n"
    output += f"{Fore.BLUE}[INF]{Style.RESET_ALL} - Enable 2FA/MFA on npm & GitHub accounts\n"
    output += f"{Fore.BLUE}[INF]{Style.RESET_ALL} - Pin exact versions with lockfiles (package-lock.json)\n"
    output += f"{Fore.BLUE}[INF]{Style.RESET_ALL} - Use integrity hashes for critical dependencies\n"
    output += f"{Fore.BLUE}[INF]{Style.RESET_ALL} - Run 'npm audit' regularly in your CI/CD pipeline\n"
    output += f"{Fore.BLUE}[INF]{Style.RESET_ALL} - Consider 'npm ci --ignore-scripts' during security incidents\n"
    output += f"{Fore.BLUE}[INF]{Style.RESET_ALL} - Monitor dependencies with tools like Dependabot\n"
    output += f"{Fore.BLUE}[INF]{Style.RESET_ALL} Pro tip: Run this scanner regularly to stay protected!\n"
    
    return output

def create_threat_details(results):
    """Create minimal threat details (when issues found)"""
    bad_deps = results.get('badDeps', [])
    suspicious_files = results.get('suspiciousFiles', [])
    suspicious_scripts = results.get('suspiciousScripts', [])
    git_issues = results.get('gitIssues', [])
    
    output = ''
    
    if bad_deps:
        output += f"{Fore.RED}[ERR]{Style.RESET_ALL} Compromised packages detected:\n"
        for dep in bad_deps:
            output += f"{Fore.RED}[ERR]{Style.RESET_ALL} - {dep['name']}@{dep['version']}\n"
        package_names = ' '.join([dep['name'] for dep in bad_deps])
        output += f"{Fore.YELLOW}[INF]{Style.RESET_ALL} Run: npm uninstall {package_names}\n"
    
    if suspicious_files or suspicious_scripts:
        files = (suspicious_files or []) + (suspicious_scripts or [])
        for file_info in files:
            file_path = file_info.get('path') or file_info.get('name', 'Unknown')
            output += f"{Fore.YELLOW}[WRN]{Style.RESET_ALL} Suspicious file: {file_path}\n"
    
    if git_issues:
        for issue in git_issues:
            issue_type = issue.get('type') or issue.get('message', 'Unknown issue')
            output += f"{Fore.YELLOW}[WRN]{Style.RESET_ALL} Git threat: {issue_type}\n"
            
            # Add explanations for specific threat types
            explanation = ''
            if issue.get('type') == 'suspicious-remote':
                explanation = "Flagged because remote URL contains 'shai-hulud' (matches known worm repo patterns). Verify if this is legitimate."
            elif issue.get('type') == 'unsigned-commits':
                explanation = "Recent commits lack GPG signatures, combined with other indicators. Consider enabling commit signing for added security."
            
            if explanation:
                output += f"  {Fore.LIGHTBLACK_EX}{explanation}{Style.RESET_ALL}\n"
    
    return output
