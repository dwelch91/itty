#!/usr/bin/env python
import os

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

long_desc = ''

try:
    long_desc = open(os.path.join(os.path.dirname(__file__), 'README.rst')).read()
except:
    # The description isn't worth a failed install...
    pass

setup(
    name='itty',
    version='1.0.0',
    description='The itty-bitty Python web framework.',
    long_description=long_desc,
    author='Daniel Lindsley',
    author_email='daniel@toastdriven.com',
    url='http://github.com/dwelch91/itty/',
    py_modules=['itty'],
    license='BSD',
    classifiers=[
        'License :: OSI Approved :: BSD License'
    ],
)
