# setup.py
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext as _build_ext
import os

class build_ext_optional(_build_ext):
    """Don't fail the install if optional C extensions can't be built."""
    def build_extension(self, ext):
        try:
            super().build_extension(ext)
        except Exception as e:
            if getattr(ext, "optional", False):
                self._announce_skip(ext, e)
            else:
                raise

    def run(self):
        try:
            super().run()
        except Exception as e:
            # Some environments fail early in run(); treat everything optional
            self._announce_skip(None, e)

    def _announce_skip(self, ext, err):
        name = ext.name if ext else "one or more C extensions"
        self.warn(f"*** Skipping build of {name}: {err}\n"
                  f"*** Falling back to pure Python implementation.")

# Allow forcing pure-Python builds to test fallback:
PUREPY = os.environ.get("LEO_PACKER_PUREPY") == "1"

exts = []
if not PUREPY:
    exts.append(Extension(
        "leo_packer._xor",
        sources=["src/leo_packer/_xor.c"],
        optional=True,         # <-- key: don't fail install if it won't build
    ))

setup(
    ext_modules=exts,
    cmdclass={"build_ext": build_ext_optional},
)

