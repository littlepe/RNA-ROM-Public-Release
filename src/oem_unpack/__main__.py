# -*- coding: utf-8 -*-
"""The ``python -m oem_unpack`` entry point."""

from __future__ import print_function

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
