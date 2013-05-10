# PyDNSSEC - DNSSEC toolkit
# Copyright (C) 2013 Tomas Mazak
# (based on dnssec module from dnspython package)
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""DNSSEC toolkit"""

import cStringIO
import os
import math
import struct
import time
import base64

import Crypto.PublicKey.RSA
import Crypto.PublicKey.DSA
import Crypto.Util.number
import Crypto.Hash.SHA
import Crypto.Hash.SHA256
import Crypto.Hash.SHA384
import Crypto.Hash.SHA512
import Crypto.Signature.PKCS1_v1_5

import dns.exception
import dns.hash
import dns.name
import dns.node
import dns.rdataset
import dns.rdata
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes.ANY.DNSKEY
import dns.rdtypes.ANY.DS
import dns.rdtypes.ANY.RRSIG
import dns.rdtypes.ANY.NSEC
import dns.rdtypes.ANY.NSEC3
import dns.rdtypes.ANY.NSEC3PARAM


class UnsupportedAlgorithm(dns.exception.DNSException):
    """Raised if an algorithm is not supported."""
    pass

class ValidationFailure(dns.exception.DNSException):
    """The DNSSEC signature is invalid."""
    pass

class NSEC3Collision(dns.exception.DNSException):
    """Collision was detected in hashed owner names."""
    pass

# DNSSEC algorithm numbers, according to IANA authority
# http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xml
RSAMD5 = 1 # deprecated
DH = 2
DSA = 3
RSASHA1 = 5
DSANSEC3SHA1 = 6
RSASHA1NSEC3SHA1 = 7
RSASHA256 = 8
RSASHA512 = 10
ECCGOST = 12
ECDSAP256SHA256 = 13
ECDSAP384SHA384 = 14
INDIRECT = 252
PRIVATEDNS = 253
PRIVATEOID = 254

# DNSKEY flags
DNSKEY_FLAG_NONE = 0
DNSKEY_FLAG_ZONEKEY = 256
DNSKEY_FLAG_SEP = 1 # Secure entry point

# NSEC3 parameters according to IANA authority:
# http://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xml
NSEC3_ALG_SHA1 = 1
NSEC3_FLAG_NONE = 0
NSEC3_FLAG_OPTOUT = 1


_algorithm_by_text = {
    'RSAMD5' : RSAMD5, 
    'DH' : DH,
    'DSA' : DSA,
    'RSASHA1' : RSASHA1,
    'DSANSEC3SHA1' : DSANSEC3SHA1,
    'RSASHA1NSEC3SHA1' : RSASHA1NSEC3SHA1,
    'RSASHA256' : RSASHA256,
    'RSASHA512' : RSASHA512,
    'ECCGOST' : ECCGOST,
    'ECDSAP256SHA256' : ECDSAP256SHA256,
    'ECDSAP384SHA384' : ECDSAP384SHA384,
    'INDIRECT' : INDIRECT,
    'PRIVATEDNS' : PRIVATEDNS,
    'PRIVATEOID' : PRIVATEOID,
    }

# We construct the inverse mapping programmatically to ensure that we
# cannot make any mistakes (e.g. omissions, cut-and-paste errors) that
# would cause the mapping not to be true inverse.

_algorithm_by_value = dict([(y, x) for x, y in _algorithm_by_text.iteritems()])

def algorithm_from_text(text):
    """Convert text into a DNSSEC algorithm value
    @rtype: int"""

    value = _algorithm_by_text.get(text.upper())
    if value is None:
        value = int(text)
    return value

def algorithm_to_text(value):
    """Convert a DNSSEC algorithm value to text
    @rtype: string"""

    text = _algorithm_by_value.get(value)
    if text is None:
        text = str(value)
    return text

def _to_rdata(record, origin):
    s = cStringIO.StringIO()
    record.to_wire(s, origin=origin)
    return s.getvalue()

def key_id(key, origin=None):
    rdata = _to_rdata(key, origin)
    total = 0
    for i in range(len(rdata) // 2):
        total += (ord(rdata[2 * i]) << 8) + ord(rdata[2 * i + 1])
    if len(rdata) % 2 != 0:
        total += ord(rdata[len(rdata) - 1]) << 8
    total += ((total >> 16) & 0xffff);
    return total & 0xffff

def make_ds(name, key, algorithm, origin=None):
    if algorithm.upper() == 'SHA1':
        dsalg = 1
        hash = dns.hash.get('SHA1')()
    elif algorithm.upper() == 'SHA256':
        dsalg = 2
        hash = dns.hash.get('SHA256')()
    else:
        raise UnsupportedAlgorithm, 'unsupported algorithm "%s"' % algorithm

    if isinstance(name, (str, unicode)):
        name = dns.name.from_text(name, origin)
    hash.update(name.canonicalize().to_wire())
    hash.update(_to_rdata(key, origin))
    digest = hash.digest()

    dsrdata = struct.pack("!HBB", key_id(key), key.algorithm, dsalg) + digest
    return dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.DS, dsrdata, 0,
                               len(dsrdata))

def _find_candidate_keys(keys, rrsig):
    candidate_keys=[]
    value = keys.get(rrsig.signer)
    if value is None:
        return None
    if isinstance(value, dns.node.Node):
        try:
            rdataset = node.find_rdataset(dns.rdataclass.IN,
                                          dns.rdatatype.DNSKEY)
        except KeyError:
            return None
    else:
        rdataset = value
    for rdata in rdataset:
        if rdata.algorithm == rrsig.algorithm and \
               key_id(rdata) == rrsig.key_tag:
            candidate_keys.append(rdata)
    return candidate_keys

def _is_rsa(algorithm):
    return algorithm in (RSASHA1, RSASHA1NSEC3SHA1, RSASHA256, RSASHA512)

def _is_dsa(algorithm):
    return algorithm in (DSA, DSANSEC3SHA1)

def _is_sha1(algorithm):
    return algorithm in (DSA, RSASHA1,
                         DSANSEC3SHA1, RSASHA1NSEC3SHA1)

def _is_sha256(algorithm):
    return algorithm == RSASHA256

def _is_sha384(algorithm):
    return algorithm == ECDSAP384SHA384

def _is_sha512(algorithm):
    return algorithm == RSASHA512

def _make_hash(algorithm):
    if _is_sha1(algorithm):
        return Crypto.Hash.SHA.new()
    if _is_sha256(algorithm):
        return Crypto.Hash.SHA256.new()
    if _is_sha384(algorithm):
        return Crypto.Hash.SHA384.new()
    if _is_sha512(algorithm):
        return Crypto.Hash.SHA512.new()
    raise ValidationFailure, 'unknown hash for algorithm %u' % algorithm

def _make_algorithm_id(algorithm):
    if _is_sha1(algorithm):
        oid = [0x2b, 0x0e, 0x03, 0x02, 0x1a]
    elif _is_sha256(algorithm):
        oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
    elif _is_sha512(algorithm):
        oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]
    else:
        raise ValidationFailure, 'unknown algorithm %u' % algorithm
    olen = len(oid)
    dlen = _make_hash(algorithm).digest_size
    idbytes = [0x30] + [8 + olen + dlen] + \
              [0x30, olen + 4] + [0x06, olen] + oid + \
              [0x05, 0x00] + [0x04, dlen]
    return ''.join(map(chr, idbytes))


def _get_minimum_ttl(zone):
    """
    Get minimum TTL from SOA record in the given zone.
    """
    try:
        rdataset = zone.find_rdataset(zone.origin, dns.rdatatype.SOA)
        return rdataset[0].minimum
    except KeyError:
        raise dns.zone.NoSOA


def _is_delegation(rrname, rdataset, zone):
    """
    Test if the given rrset is a subzone delegation
    """
    if rdataset.rdtype == dns.rdatatype.NS and \
       rrname.derelativize(zone.origin) != zone.origin:
        return True
    else:
        return False


def _get_delegations(zone):
    """
    Get all zone delegation rrsets
    """
    return [x[0].derelativize(zone.origin) 
            for x in zone.iterate_rdatasets(dns.rdatatype.NS)
            if _is_delegation(x[0], x[1], zone)]


def _is_authoritative(rrname, rdataset, zone, delegations = None):
    """
    Checks if a given resource records is authoritative in the zone
    """
    if not delegations:
        delegations = _get_delegations(zone)
    rrname = rrname.derelativize(zone.origin)

    if not rrname.is_subdomain(zone.origin):
        return False

    deleg_dnssec = (dns.rdatatype.DS, dns.rdatatype.NSEC, dns.rdatatype.NSEC3)
    for delegation in delegations:
        if (rrname==delegation and rdataset.rdtype not in deleg_dnssec) or \
           (rrname.is_subdomain(delegation) and rrname != delegation):
            return False
    
    return True


def _get_authoritative(zone):
    """
    Get all owner names from the zone which contain any authoritative data.
    """
    delegs = _get_delegations(zone)
    names = []
    for name in zone.nodes:
        auth = False
        for rdataset in zone.get_node(name):
            if _is_authoritative(name, rdataset, zone, delegs):
                auth = True
                break
        if auth:
            names.append(name)
    return names


def _canonical_order(names, origin = None):
    """
    Sort the given names according to canonical order defined in RFC-4034,
    section 6.1
    """
    def labelCmp(n1, n2):
        for i in range(min(len(n1), len(n2))):
            i1 = len(n1) - i - 1
            i2 = len(n2) - i - 1
            if cmp(n1.labels[i1].lower(), n2.labels[i2].lower()) != 0:
                return cmp(n1.labels[i1].lower(), n2.labels[i2].lower())
        return cmp(len(n1), len(n2))
    
    if origin:
        names = [n.derelativize(origin) for n in names]
    return sorted(names, cmp=labelCmp)


def _hashed_order(names, origin=None, salt='', iterations=0):
    """
    Hash the given names using SHA-1 algorithm, the given salt and the given
    number of iterations. Return list of tuples (name, hash) in hash order.
    Used for NSEC3 records generation. See RFC-5155 for details.
    """

    # Add empty non terminals to the list, see RFC-5155, section 7.1
    nameset = set(names)
    for name in names:
        n = name.relativize(origin)
        while len(n) > 1:
            n = n.parent()
            nameset.add(n.derelativize(origin))
    names = list(nameset)

    ret = []
    for name in names:
        h = name.to_digestable(origin)
        i = iterations
        while i >= 0:
            sha = Crypto.Hash.SHA.new()
            sha.update(h)
            sha.update(salt)
            h = sha.digest()
            i -= 1
        ret.append((name, h))

    # Check for hash collision
    if len(ret) != len(set(ret)):
        raise NSEC3Collision()

    ret = sorted(ret, key=lambda x: x[1])
    return ret


def _rdtypes_to_bitmaps(rdtypes):
    """
    Convert list of RR types to bitmap windows required by NSEC/NSEC3 records
    (see RFC-4034, section 4.1.2). 
    Partly copied from dns.rdtypes.ANY.NSEC.from_text method
    """
    if not len(rdtypes):
        return []

    rdtypes.sort()
    window = 0
    octets = 0
    prior_rdtype = 0
    bitmap = ['\0'] * 32
    windows = []
    for nrdtype in rdtypes:
        if nrdtype == prior_rdtype:
            continue
        prior_rdtype = nrdtype
        new_window = nrdtype // 256
        if new_window != window:
            windows.append((window, ''.join(bitmap[0:octets])))
            bitmap = ['\0'] * 32
            window = new_window
        offset = nrdtype % 256
        byte = offset // 8
        bit = offset % 8
        octets = byte + 1
        bitmap[byte] = chr(ord(bitmap[byte]) | (0x80 >> bit))
    windows.append((window, ''.join(bitmap[0:octets])))
    return windows


def add_nsec(zone):
    """
    Add appropriate NSEC records to the given zone (see RFC-4034 for details).
    """
    # Only add NSEC records to owner names containing authoritative data or
    # zone delegations
    delegs = _get_delegations(zone)
    names = list(set(delegs + _get_authoritative(zone)))
    ordered = _canonical_order(names, zone.origin)

    ttl = _get_minimum_ttl(zone)
    for i, name in enumerate(ordered):
        # Compute RDATA types covered by this NSEC record
        rdtypes = [dns.rdatatype.RRSIG, dns.rdatatype.NSEC]
        node = zone.find_node(name)
        for rdataset in node:
            # Only include RDATA types of authoritative records or delegations
            if _is_authoritative(name, rdataset, zone, delegs) or \
               _is_delegation(name, rdataset, zone):
                rdtypes.append(rdataset.rdtype)
        typemap = _rdtypes_to_bitmaps(rdtypes)

        # Add the NSEC record to the zone
        rdataset = zone.find_rdataset(name, rdtype=dns.rdatatype.NSEC, 
                                      create=True)
        nsec = dns.rdtypes.ANY.NSEC.NSEC(dns.rdataclass.IN, dns.rdatatype.NSEC, 
                    ordered[(i+1)%len(ordered)], typemap)
        rdataset.add(nsec, ttl=ttl)


def add_nsec3(zone, salt=None, iters=None):
    """
    Add appropriate NSEC3 records to the given zone. The NSEC3PARAM record 
    is added as well. (see RFC-5155 for details)
    """
    # For NSEC3 purposes, 8 octets long salt is used and fixed number of
    # iterations - 10. As this configuration is used by CZ.NIC, it's considered
    # to be secure enough.
    can_resalt=False
    if salt is None:
        salt = os.urandom(8)
        can_resalt = True
    if iters is None:
        iters = 10

    # Only add NSEC records to owner names containing authoritative data or
    # zone delegations
    delegs = _get_delegations(zone)
    names = list(set(delegs + _get_authoritative(zone)))

    # If a collision occurs (two names with the same hash - EXTREMLY low
    # probability), change the salt and try again. 
    while True:
        try:
            hashed_names = _hashed_order(names, zone.origin, salt, iters)
            break
        except NSEC3Collision as collision:
            if not can_resalt:
                raise collision
            salt = os.urandom(8)
            continue

    # Add NSEC3PARAM resource record
    ttl = _get_minimum_ttl(zone)
    rdataset = zone.find_rdataset(zone.origin, rdtype=dns.rdatatype.NSEC3PARAM,
                                  create=True)
    nsec3param = dns.rdtypes.ANY.NSEC3PARAM.NSEC3PARAM(dns.rdataclass.IN, 
            dns.rdatatype.NSEC3PARAM, NSEC3_ALG_SHA1, NSEC3_FLAG_NONE, iters, 
            salt)
    rdataset.add(nsec3param, ttl=ttl)

    # Add NSEC3 records for all owner names having at least one authoritative
    # resource record
    for i, nametuple in enumerate(hashed_names):
        name, hashed = nametuple
        rdtypes = set()
        node = zone.get_node(name) or []
        for rdataset in node:
            if _is_authoritative(name, rdataset, zone, delegs):
                rdtypes.add(rdataset.rdtype)
                rdtypes.add(dns.rdatatype.RRSIG)
            if _is_delegation(name, rdataset, zone):
                rdtypes.add(rdataset.rdtype)
        typemap = _rdtypes_to_bitmaps(list(rdtypes))

        # Convert hashed name to DNSSEC's strange base32 encoding
        b32hash = base64.b32encode(hashed)
        b32hash = b32hash.translate(dns.rdtypes.ANY.NSEC3.b32_normal_to_hex)
        owner = dns.name.Name((b32hash.lower(),)).derelativize(zone.origin)

        rdataset = zone.find_rdataset(owner, rdtype=dns.rdatatype.NSEC3, 
                                      create=True)
        nexthash = hashed_names[(i+1)%len(hashed_names)][1]
        nsec3 = dns.rdtypes.ANY.NSEC3.NSEC3(dns.rdataclass.IN, 
                    dns.rdatatype.NSEC3, NSEC3_ALG_SHA1, 
                    NSEC3_FLAG_NONE, iters, salt, nexthash, typemap)
        rdataset.add(nsec3, ttl=ttl)


def validate_rrsig(rrset, rrsig, keys, origin=None, now=None):
    """Validate an RRset against a single signature rdata

    The owner name of the rrsig is assumed to be the same as the owner name
    of the rrset.

    @param rrset: The RRset to validate
    @type rrset: dns.rrset.RRset or (dns.name.Name, dns.rdataset.Rdataset)
    tuple
    @param rrsig: The signature rdata
    @type rrsig: dns.rrset.Rdata
    @param keys: The key dictionary.
    @type keys: a dictionary keyed by dns.name.Name with node or rdataset values
    @param origin: The origin to use for relative names
    @type origin: dns.name.Name or None
    @param now: The time to use when validating the signatures.  The default
    is the current time.
    @type now: int
    """

    if isinstance(origin, (str, unicode)):
        origin = dns.name.from_text(origin, dns.name.root)

    for candidate_key in _find_candidate_keys(keys, rrsig):
        if not candidate_key:
            raise ValidationFailure, 'unknown key'

        # For convenience, allow the rrset to be specified as a (name, rdataset)
        # tuple as well as a proper rrset
        if isinstance(rrset, tuple):
            rrname = rrset[0]
            rdataset = rrset[1]
        else:
            rrname = rrset.name
            rdataset = rrset

        if now is None:
            now = time.time()
        if rrsig.expiration < now:
            raise ValidationFailure, 'expired'
        if rrsig.inception > now:
            raise ValidationFailure, 'not yet valid'

        hash = _make_hash(rrsig.algorithm)

        if _is_rsa(rrsig.algorithm):
            keyptr = candidate_key.key
            (bytes,) = struct.unpack('!B', keyptr[0:1])
            keyptr = keyptr[1:]
            if bytes == 0:
                (bytes,) = struct.unpack('!H', keyptr[0:2])
                keyptr = keyptr[2:]
            rsa_e = keyptr[0:bytes]
            rsa_n = keyptr[bytes:]
            keylen = len(rsa_n) * 8
            pubkey = Crypto.PublicKey.RSA.construct(
                (Crypto.Util.number.bytes_to_long(rsa_n),
                 Crypto.Util.number.bytes_to_long(rsa_e)))
            sig = (Crypto.Util.number.bytes_to_long(rrsig.signature),)
        elif _is_dsa(rrsig.algorithm):
            keyptr = candidate_key.key
            (t,) = struct.unpack('!B', keyptr[0:1])
            keyptr = keyptr[1:]
            octets = 64 + t * 8
            dsa_q = keyptr[0:20]
            keyptr = keyptr[20:]
            dsa_p = keyptr[0:octets]
            keyptr = keyptr[octets:]
            dsa_g = keyptr[0:octets]
            keyptr = keyptr[octets:]
            dsa_y = keyptr[0:octets]
            pubkey = Crypto.PublicKey.DSA.construct(
                (Crypto.Util.number.bytes_to_long(dsa_y),
                 Crypto.Util.number.bytes_to_long(dsa_g),
                 Crypto.Util.number.bytes_to_long(dsa_p),
                 Crypto.Util.number.bytes_to_long(dsa_q)))
            (dsa_r, dsa_s) = struct.unpack('!20s20s', rrsig.signature[1:])
            sig = (Crypto.Util.number.bytes_to_long(dsa_r),
                   Crypto.Util.number.bytes_to_long(dsa_s))
        else:
            raise ValidationFailure, 'unknown algorithm %u' % rrsig.algorithm

        hash.update(_to_rdata(rrsig, origin)[:18])
        hash.update(rrsig.signer.to_digestable(origin))

        if rrsig.labels < len(rrname) - 1:
            suffix = rrname.split(rrsig.labels + 1)[1]
            rrname = dns.name.from_text('*', suffix)
        rrnamebuf = rrname.to_digestable(origin)
        rrfixed = struct.pack('!HHI', rdataset.rdtype, rdataset.rdclass,
                              rrsig.original_ttl)
        rrlist = sorted(rdataset);
        for rr in rrlist:
            hash.update(rrnamebuf)
            hash.update(rrfixed)
            rrdata = rr.to_digestable(origin)
            rrlen = struct.pack('!H', len(rrdata))
            hash.update(rrlen)
            hash.update(rrdata)

        digest = hash.digest()

        if _is_rsa(rrsig.algorithm):
            # PKCS1 algorithm identifier goop
            digest = _make_algorithm_id(rrsig.algorithm) + digest
            padlen = keylen // 8 - len(digest) - 3
            digest = chr(0) + chr(1) + chr(0xFF) * padlen + chr(0) + digest
        elif _is_dsa(rrsig.algorithm):
            pass
        else:
            # Raise here for code clarity; this won't actually ever happen
            # since if the algorithm is really unknown we'd already have
            # raised an exception above
            raise ValidationFailure, 'unknown algorithm %u' % rrsig.algorithm

        if pubkey.verify(digest, sig):
            return
    raise ValidationFailure, 'verify failure'

def validate(rrset, rrsigset, keys, origin=None, now=None):
    """Validate an RRset

    @param rrset: The RRset to validate
    @type rrset: dns.rrset.RRset or (dns.name.Name, dns.rdataset.Rdataset)
    tuple
    @param rrsigset: The signature RRset
    @type rrsigset: dns.rrset.RRset or (dns.name.Name, dns.rdataset.Rdataset)
    tuple
    @param keys: The key dictionary.
    @type keys: a dictionary keyed by dns.name.Name with node or rdataset values
    @param origin: The origin to use for relative names
    @type origin: dns.name.Name or None
    @param now: The time to use when validating the signatures.  The default
    is the current time.
    @type now: int
    """

    if isinstance(origin, (str, unicode)):
        origin = dns.name.from_text(origin, dns.name.root)

    if isinstance(rrset, tuple):
        rrname = rrset[0]
    else:
        rrname = rrset.name

    if isinstance(rrsigset, tuple):
        rrsigname = rrsigset[0]
        rrsigrdataset = rrsigset[1]
    else:
        rrsigname = rrsigset.name
        rrsigrdataset = rrsigset

    rrname = rrname.choose_relativity(origin)
    rrsigname = rrname.choose_relativity(origin)
    if rrname != rrsigname:
        raise ValidationFailure, "owner names do not match"

    for rrsig in rrsigrdataset:
        try:
            validate_rrsig(rrset, rrsig, keys, origin, now)
            return
        except ValidationFailure, e:
            pass
    raise ValidationFailure, "no RRSIGs validated"


def _rrsig_labels(name, origin):
    """
    Get label count of the given dns name as required for RRSIG labels field.
    See RFC-4034, section 3.1.3. for details.
    """
    labels = [x for x in name.derelativize(origin).labels
                if len(x) and x != '*']
    return len(labels)


def _sign(digest, key):
    """
    Sign the given string using the given key
    """
    if _is_rsa(key.algorithm):
        rsakey = Crypto.PublicKey.RSA.importKey(key.privkey)
        signer = Crypto.Signature.PKCS1_v1_5.new(rsakey)
        return signer.sign(digest)
    else:
        raise ValidationFailure("Unsupported algorithm %d" % key.algorithm)


def sign_rrset(rrset, key, origin, expiration, inception):
    """
    Generate a RRSIG record for given RR set
    """
    # For convenience, allow the rrset to be specified as a (name, rdataset)
    # tuple as well as a proper rrset
    if isinstance(rrset, tuple):
        rrname = rrset[0]
        rdataset = rrset[1]
    else:
        rrname = rrset.name
        rdataset = rrset

    # Prepare RRSIG record (without signature field)
    rrsig = dns.rdtypes.ANY.RRSIG.RRSIG(rdataset.rdclass, dns.rdatatype.RRSIG,
                rdataset.rdtype, key.algorithm, _rrsig_labels(rrname, origin),
                rdataset.ttl,expiration, inception, key.key_tag(), 
                origin.canonicalize(), 'NULL')

    # Prepare digest function
    digest = _make_hash(key.algorithm)

    # Add RRSIG fields to digest
    digest.update(_to_rdata(rrsig, origin)[:18])
    digest.update(rrsig.signer.to_digestable(origin))

    # Add RRs to digest
    rrnamebuf = rrname.to_digestable(origin)
    rrfixed = struct.pack('!HHI', rdataset.rdtype, rdataset.rdclass,
                  rrsig.original_ttl)
    rrlist = sorted(rdataset)
    for rr in rrlist:
        digest.update(rrnamebuf)
        digest.update(rrfixed)
        rrdata = rr.to_digestable(origin)
        rrlen = struct.pack('!H', len(rrdata))
        digest.update(rrlen)
        digest.update(rrdata)

    # Update RRSIG with calculated signature and return
    rrsig.signature = _sign(digest, key)
    return rrsig


def sign_zone(zone, keys, expiration=None, inception=None, nsec3=False,
               keyttl=3600, nsec3salt=None, nsec3iters=None):
    """
    Given dnspython zone instance and uNIC KSK and ZSK keys to be used,
    sign the zone with DNSSEC
    """
    # Set defaults
    zsk = [k for k in keys if not (k.flags & DNSKEY_FLAG_SEP)]
    if not len(zsk):
        zsk = keys
    if expiration is None:
        expiration = time.time() + (3600 * 24 * 90) # 90 days from now
    if inception is None:
        inception = time.time() - (3600 * 24) # 1 day ago

    # Add DNSKEY records to the zone 
    dnskey_set = zone.find_rdataset(zone.origin, rdtype=dns.rdatatype.DNSKEY, 
                                    create=True)
    for key in keys:
        dnskey_set.add(key.get_pubkey(), ttl=keyttl)

    # Add NSEC / NSEC3 RRs
    if nsec3:
        add_nsec3(zone, nsec3salt, nsec3iters)
    else:
        add_nsec(zone)

    # Sign the DNSKEY records with all keys
    rrsig_set = zone.find_rdataset(zone.origin, rdtype=dns.rdatatype.RRSIG, 
                                   create=True)
    for key in keys:
        rrsig = sign_rrset((zone.origin, dnskey_set), key, zone.origin, 
                           expiration, inception)
        rrsig_set.add(rrsig, ttl=dnskey_set.ttl)

    # Sign other RRs 
    delegations = _get_delegations(zone)
    for rrname, rdataset in zone.iterate_rdatasets():
        # DNSKEY are already signed, do not sign again 
        if rdataset.rdtype == dns.rdatatype.DNSKEY:
            continue
        # RRSIG records MUST NOT be signed (RFC-4035, section 2.2.)
        if rdataset.rdtype == dns.rdatatype.RRSIG:
            continue
        # Delegations and respective glue records MUST NOT be signed 
        # (RFC-4035, section 2.2.)
        if not _is_authoritative(rrname, rdataset, zone, delegations):
            continue
        rrsig_set = zone.find_rdataset(rrname, rdtype=dns.rdatatype.RRSIG, 
                                       create=True)
        for key in zsk:
            rrsig = sign_rrset((rrname, rdataset), key, zone.origin,expiration, 
                               inception)
            rrsig_set.add(rrsig, ttl=rdataset.ttl)


def sigs_expire_before(zone, limit):
    """
    Test if there are any signatures in the zone with the expiration date 
    before the given limit. It helps to detect if the given zone needs to be
    signed again.
    """
    for rrname, rdataset in zone.iterate_rdatasets():
        if rdataset.rdtype == dns.rdatatype.RRSIG:
            for rdata in rdataset:
                if rdata.expiration < limit:
                    return True
    return False


def unsign_zone(zone):
    """
    Remove all DNSSEC records from the given zone 
    """
    # Remove signatures
    for rrname, rdataset in zone.iterate_rdatasets():
        if rdataset.rdtype != dns.rdatatype.RRSIG:
            zone.delete_rdataset(rrname, rdtype=dns.rdatatype.RRSIG, 
                                 covers=rdataset.rdtype)

    # Remove NSEC/NSEC3
    for rrname, rdataset in zone.iterate_rdatasets():
        if rdataset.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
            zone.delete_rdataset(rrname, rdtype=rdataset.rdtype)

    # Remove NSEC3PARAM
    zone.delete_rdataset(zone.origin, rdtype=dns.rdatatype.NSEC3PARAM)

    # Remove DNSKEYs
    zone.delete_rdataset(zone.origin, rdtype=dns.rdatatype.DNSKEY)

    return zone


def _rsa2dnskey(key):
    """
    Get RSA public key in DNSKEY resource record format (RFC-3110)
    """
    octets = ''
    explen = int(math.ceil(math.log(key.e, 2)/8))
    if explen > 255:
        octets = "\x00"
    octets += Crypto.Util.number.long_to_bytes(explen) + \
              Crypto.Util.number.long_to_bytes(key.e) + \
              Crypto.Util.number.long_to_bytes(key.n)
    return octets


def _dnskey2rsa(keyptr):
    (b,) = struct.unpack('!B', keyptr[0:1]) 
    keyptr = keyptr[1:]
    if b == 0: 
        (b,) = struct.unpack('!H', keyptr[0:2]) 
        keyptr = keyptr[2:]
    rsa_e = keyptr[0:b] 
    rsa_n = keyptr[b:]
    return (rsa_e, rsa_n)

_file_privkey_rsa = \
"""Private-key-format: v1.2
Algorithm: %(alg)d (%(algtxt)s)
Modulus: %(n)s
PublicExponent: %(e)s
PrivateExponent: %(d)s
Prime1: %(p)s
Prime2: %(q)s
Exponent1: %(dmp1)s
Exponent2: %(dmq1)s
Coefficient: %(u)s
"""

class PrivateDNSKEY(dns.rdtypes.ANY.DNSKEY.DNSKEY):
    """
    Adds a private key field and methods to DNSKEY. Used for signature
    creation.

    @ivar privkey: the private key 
    @type flags: string
    """
    
    @classmethod
    def generate(cls, flags, algorithm, bits=None, rdclass=dns.rdataclass.IN,
                 rdtype=dns.rdatatype.DNSKEY, protocol=3):
        """
        Generate a new DNSKEY keypair
        """
        if _is_rsa(algorithm):
            if not isinstance(bits, (int, long)):
                raise ValidationFailure("For RSA key generation, key size in "
                                        "bits must be provided")
            key = Crypto.PublicKey.RSA.generate(bits)
            private = key.exportKey(format='PEM')
            public = _rsa2dnskey(key)
        else:
            raise ValidationFailure("Unknown algorithm %d" % algorithm)

        return cls(flags, algorithm, public, private, rdclass, rdtype,protocol)

    def __init__(self, flags, algorithm, key, privkey=None,
                 rdclass=dns.rdataclass.IN, rdtype=dns.rdatatype.DNSKEY, 
                 protocol=3):
        super(PrivateDNSKEY, self).__init__(rdclass, rdtype, flags, protocol,
                                            algorithm, key)
        self.privkey = privkey
        self._tag = None

    def get_pubkey(self):
        """
        Return original dns.rdtypes.ANY.DNSKEY.DNSKEY (without private key)
        """
        return dns.rdtypes.ANY.DNSKEY.DNSKEY(self.rdclass, self.rdtype,
                    self.flags, self.protocol, self.algorithm, self.key)

    def key_tag(self):
        """
        Get the key tag of this key (For details, see RFC 2535, section 4.1.6)
        """
        if self._tag is None:
            self._tag = key_id(self)
        return self._tag

    def bits(self):
        """
        Get the size of this key in bits.
        """
        if _is_rsa(self.algorithm): 
            (rsa_e,rsa_n) = _dnskey2rsa(self.key)
            return len(rsa_n)*8
        else:
            raise ValidationFailure("Unknown algorithm %d" % self.algorithm)

    def to_file(self, domain, directory=None, file=None):
        """
        Export this key to a private key file compatible with bind tools
        """
        if not _is_rsa(self.algorithm):
            raise ValidationFailure("Unknown algorithm %d" % self.algorithm)

        # Prepare key data
        key = Crypto.PublicKey.RSA.importKey(self.privkey)
        keydata = dict(alg=self.algorithm,
                       algtxt=algorithm_to_text(self.algorithm))
        for field in key.keydata:
            f = getattr(key, field)
            f = Crypto.Util.number.long_to_bytes(f)
            keydata[field] = base64.b64encode(f)
        dmp1 = Crypto.Util.number.long_to_bytes(key.d % (key.p - 1))
        keydata['dmp1'] = base64.b64encode(dmp1)
        dmq1 = Crypto.Util.number.long_to_bytes(key.d % (key.p - 1))
        keydata['dmq1'] = base64.b64encode(dmq1)

        # Write to file
        if file:
            fname = file
        else:
            fname = 'K%s.+%03d+%05d.private' % (domain.strip('.'), 
                                                self.algorithm, self.key_tag())
            if directory:
                fname = "%s/%s" % (directory, fname)
        fd = open(fname, 'w')
        fd.write(_file_privkey_rsa % keydata)
        fd.close()
