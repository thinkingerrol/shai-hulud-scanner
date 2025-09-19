#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="shai-hulud-scanner",
    version="1.3.0",
    author="Amruth",
    author_email="pothula.amruth@cloudsek.com",
    description="CLI tool to scan for Shai-Hulud npm worm infections, affected packages and with automated remediation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Amruth-SV/shai-hulud-scanner",
    project_urls={
        "Bug Reports": "https://github.com/Amruth-SV/shai-hulud-scanner/issues",
        "Source": "https://github.com/Amruth-SV/shai-hulud-scanner",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "shai-hulud-scanner=src.cli:main",
        ],
    },
    keywords=[
        "security", "npm", "malware", "supply-chain", "shai-hulud",
        "scanner", "vulnerability", "threat-detection", "cybersecurity",
        "npm-worm", "package-scanner", "security-audit"
    ],
    include_package_data=True,
    package_data={
        "": ["*.json", "*.md", "*.txt"],
    },
)
