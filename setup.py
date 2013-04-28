#!/usr/bin/env python

"""
Distutils setup script for PyDNSSEC module
"""

import sys
from distutils.core import setup

version = '0.1'

kwargs = {
    'name' : 'pydnssec',
    'version' : version,
    'description' : 'DNSSEC toolkit',
    'long_description' : """
PyDNSSEC is a DNSSEC toolkit for Python. It's based on dnspython's dnssec
module. It supports resource record signing and verification, generating RSA
keypairs for signing, manipulation with NSEC/NSEC3 authenticated denial of
existence. Currently, DNSKEY algorithms RSASHA1, RSASHA1NSEC3SHA1, RSASHA256
and RSASHA512 are supported.
    """,
    'author' : 'Tomas Mazak',
    'author_email' : 'tomas@valec.net',
    'license' : 'GPLv3',
    'url' : 'https://github.com/tomas-mazak/pydnssec',
    'py_modules': ['dnssec'],
    'requires': ['dns', 'Crypto']
}

setup(**kwargs)
