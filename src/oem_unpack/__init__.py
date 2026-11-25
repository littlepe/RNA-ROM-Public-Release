# -*- coding: utf-8 -*-
"""oem_unpack: unpack the vendor firmware packages.

The vendor formats are unpacked in pure Python, the external binaries are only
needed for the images that come out of the unpack and those are left alone.

Everything the tool prints is in English.
"""

from __future__ import print_function

__version__ = "1.0.0"

__all__ = ["__version__", "cli"]
