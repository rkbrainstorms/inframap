#!/usr/bin/env python3
"""
inframap — entry point wrapper.
Allows both:
  python3 inframap.py -d evil.com        (direct script)
  python3 -m inframap -d evil.com        (module)
  inframap -d evil.com                   (after pip install)
"""
from inframap.inframap import main

if __name__ == "__main__":
    main()
