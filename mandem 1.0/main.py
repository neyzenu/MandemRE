#!/usr/bin/env python3
"""
RE Framework - Main Entry Point

A pure Python reverse engineering framework.
"""

import sys
import os

# Add the package to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from reframework.cli.main import main

if __name__ == '__main__':
    main()
