#!/usr/bin/env python

"""
setup.py file for SWIG example
"""

from distutils.core import setup, Extension


brtlib_module = Extension('_brtlib',
                           sources=['lib/brtlib_wrap.c', 'lib/brtlib.c'],
                           )
setup (name = 'brtlib',
       version = '0.1',
       author      = "SWIG Docs",
       description = """Simple swig brtlib from docs""",
       ext_modules = [brtlib_module],
       package_dir = {'': 'lib'},
       py_modules = ["brtlib"],
       )
