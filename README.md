PyDNSSEC
========

PyDNSSEC is a DNSSEC toolkit for Python. It supports public/private keypairs
generation and resource records signing and verification using DNSSEC.

The toolkit is based on dnspython (http://www.dnspython.org/), and uses 
PyCrypto (http://www.pycrypto.org/) for cryptography operations. Both packages
are required by PyDNSSEC.

Features:
*   Public/private keypairs generation
*   Export to DNSSEC private key format
*   Resource record signing
*   Whole zone signing
*   Both NSEC and NSEC3 are supported

DNSKEY algorithm support:
*   RSAMD5 (1): not supported
*   DSA (3): not supported
*   RSASHA1 (5): __supported__
*   DSANSEC3SHA1 (6): not supported 
*   RSASHA1NSEC3SHA1 (7): __supported__
*   RSASHA256 (8): __supported__
*   RSASHA512 (10): __supported__
*   ECDSAP256SHA256 (13): _planned_
*   ECDSAP384SHA384 (14): _planned_

Recent RFC-6944 defines which algorithms should be supported by DNSSEC
implementations. As ECDSAP256SHA256 and ECDSAP384SHA384 are recommended, they
will be implemented soon.


EXAMPLES
--------

Key generation and exporting to DNSSEC private key files:

	from dns import zone
	import os
	import dnssec
	
	ksk = dnssec.PrivateDNSKEY.generate(
	        dnssec.DNSKEY_FLAG_ZONEKEY | dnssec.DNSKEY_FLAG_SEP, 
	        dnssec.RSASHA256, bits=2048
	)
	ksk.to_file('example.com', os.path.dirname(__file__))
	
	zsk = dnssec.PrivateDNSKEY.generate(
	        dnssec.DNSKEY_FLAG_ZONEKEY, 
	        dnssec.RSASHA256, bits=1024
	)
	zsk.to_file('example.com', os.path.dirname(__file__))

Zone signing:

	z = zone.from_file('example.com.zone', origin='example.com.')
	dnssec.sign_zone(z, [ksk, zsk])
	z.to_file('example.com.signed', relativize=False)

Zone unsigning (removes all DNSSEC specific resource records from it):

	dnssec.unsign_zone(z) 
	z.to_file('example.com.unsigned', relativize=False)


INSTALLATION
------------

The module is packed using distutils, so it can be easily installed by running
following command from the package directory:

	python setup.py install

__PyCrypto__ and __dnspython__ packages are required by PyDNSSEC.


