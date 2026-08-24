import os
import sys
from setuptools import setup, find_packages

USE_CYTHON = os.environ.get("USE_CYTHON", "0") == "1" or "--cython" in sys.argv
if "--cython" in sys.argv:
    sys.argv.remove("--cython")

ext_modules = []
if USE_CYTHON:
    try:
        from Cython.Build import cythonize
        ext_modules = cythonize([
            "strilight/pruning/interval.py",
            "strilight/engine/loop_compressor.py",
            "strilight/engine/vsa_evaluator.py",
            "strilight/engine/tracker_bridge.py",
            "strilight/engine/instruction.py",
        ], compiler_directives={'language_level': "3"})
        print(" [Build] Compiling modules with Cython for proprietary binary distribution...")
    except ImportError:
        print(" [Warning] Cython not available, building pure Python package.")

setup(
    packages=find_packages(include=["strilight*"], exclude=["strilight.tests*"]),
    package_data={"strilight": ["py.typed"]},
    ext_modules=ext_modules,
)
