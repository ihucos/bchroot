#!/usr/bin/env python

"""
setup.py file for SWIG example
"""

from distutils.core import setup, Extension


brtlib_module = Extension('_brtlib',
                           sources=['brtlib_wrap.c', 'brtlib.c'],
                           )

setup (name = 'brtlib',
       version = '0.1',
       author      = "SWIG Docs",
       description = """Simple swig brtlib from docs""",
       ext_modules = [brtlib_module],
       py_modules = ["brtlib"],
       )