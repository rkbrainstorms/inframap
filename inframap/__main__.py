"""
Entry point for pip-installed inframap.
Allows: inframap -d evil.com  (after pip install inframap)
"""
import sys
import os

# Add parent dir to path when running as a module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from inframap.inframap import main

if __name__ == "__main__":
    main()
