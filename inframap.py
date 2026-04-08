#!/usr/bin/env python3
"""inframap — entry point wrapper."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from inframap.inframap import main

if __name__ == "__main__":
    main()
