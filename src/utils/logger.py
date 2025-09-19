#!/usr/bin/env python3
"""
Logging utilities for Shai-Hulud Scanner
"""

import sys
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class Logger:
    def __init__(self, verbose=False):
        self.verbose = verbose
    
    def info(self, message):
        """Print info message in blue"""
        print(f"{Fore.BLUE}[INF]{Style.RESET_ALL} {message}")
    
    def success(self, message):
        """Print success message in green"""
        print(f"{Fore.GREEN}[INF]{Style.RESET_ALL} {message}")
    
    def warn(self, message):
        """Print warning message in yellow"""
        print(f"{Fore.YELLOW}[WRN]{Style.RESET_ALL} {message}")
    
    def error(self, message):
        """Print error message in red"""
        print(f"{Fore.RED}[ERR]{Style.RESET_ALL} {message}", file=sys.stderr)
    
    def gray(self, message):
        """Print gray message (for details/explanations)"""
        print(f"{Fore.LIGHTBLACK_EX}{message}{Style.RESET_ALL}")
    
    def cyan(self, message):
        """Print cyan message (for headers)"""
        print(f"{Fore.CYAN}{message}{Style.RESET_ALL}")
    
    def debug(self, message):
        """Print debug message only if verbose mode is enabled"""
        if self.verbose:
            print(f"{Fore.MAGENTA}[DBG]{Style.RESET_ALL} {message}")

# Global logger instance
log = Logger()
