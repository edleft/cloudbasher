"""Allow running cloudbasher.cli as a module."""

import sys

from cloudbasher.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
