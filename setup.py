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
            "asm_analyzer/pruning/interval.py",
            "asm_analyzer/engine/loop_compressor.py",
            "asm_analyzer/engine/vsa_evaluator.py",
            "asm_analyzer/engine/tracker_bridge.py",
            "asm_analyzer/engine/instruction.py",
        ], compiler_directives={'language_level': "3"})
        print(" [Build] Compiling modules with Cython for proprietary binary distribution...")
    except ImportError:
        print(" [Warning] Cython not available, building pure Python package.")

setup(
    packages=find_packages(include=["asm_analyzer*"], exclude=["asm_analyzer.tests*"]),
    ext_modules=ext_modules,
)
