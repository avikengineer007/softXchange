"""Module execution entry point: python -m cve_check."""

import sys
from cve_check.cli import main

if __name__ == "__main__":
    sys.exit(main())
