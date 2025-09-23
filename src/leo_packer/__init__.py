"""
leo_packer - library for packing and unpacking Leo Pack archives.
"""

from .core import pack, unpack

try:
    from importlib.metadata import version
    __version__ = version("leo-packer")
except ImportError:
    __version__ = "unknown"

__all__ = ["pack", "unpack"]

