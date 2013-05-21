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

"""PyDNSSEC unit tests"""

import unittest
import Crypto.Util.number
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.zone

import dnssec

# Validation testcase data {{{
abs_dnspython_org = dns.name.from_text('dnspython.org')

abs_keys = { abs_dnspython_org :
             dns.rrset.from_text('dnspython.org.', 3600, 'IN', 'DNSKEY',
                                 '257 3 5 AwEAAenVTr9L1OMlL1/N2ta0Qj9LLLnnmFWIr1dJoAsWM9BQfsbV7kFZ XbAkER/FY9Ji2o7cELxBwAsVBuWn6IUUAJXLH74YbC1anY0lifjgt29z SwDzuB7zmC7yVYZzUunBulVW4zT0tg1aePbpVL2EtTL8VzREqbJbE25R KuQYHZtFwG8S4iBxJUmT2Bbd0921LLxSQgVoFXlQx/gFV2+UERXcJ5ce iX6A6wc02M/pdg/YbJd2rBa0MYL3/Fz/Xltre0tqsImZGxzi6YtYDs45 NC8gH+44egz82e2DATCVM1ICPmRDjXYTLldQiWA2ZXIWnK0iitl5ue24 7EsWJefrIhE=',
                                 '256 3 5 AwEAAdSSghOGjU33IQZgwZM2Hh771VGXX05olJK49FxpSyuEAjDBXY58 LGU9R2Zgeecnk/b9EAhFu/vCV9oECtiTCvwuVAkt9YEweqYDluQInmgP NGMJCKdSLlnX93DkjDw8rMYv5dqXCuSGPlKChfTJOLQxIAxGloS7lL+c 0CTZydAF')
         }

abs_keys_duplicate_keytag = { abs_dnspython_org :
             dns.rrset.from_text('dnspython.org.', 3600, 'IN', 'DNSKEY',
                                 '257 3 5 AwEAAenVTr9L1OMlL1/N2ta0Qj9LLLnnmFWIr1dJoAsWM9BQfsbV7kFZ XbAkER/FY9Ji2o7cELxBwAsVBuWn6IUUAJXLH74YbC1anY0lifjgt29z SwDzuB7zmC7yVYZzUunBulVW4zT0tg1aePbpVL2EtTL8VzREqbJbE25R KuQYHZtFwG8S4iBxJUmT2Bbd0921LLxSQgVoFXlQx/gFV2+UERXcJ5ce iX6A6wc02M/pdg/YbJd2rBa0MYL3/Fz/Xltre0tqsImZGxzi6YtYDs45 NC8gH+44egz82e2DATCVM1ICPmRDjXYTLldQiWA2ZXIWnK0iitl5ue24 7EsWJefrIhE=',
                                 '256 3 5 AwEAAdSSg++++THIS/IS/NOT/THE/CORRECT/KEY++++++++++++++++ ++++++++++++++++++++++++++++++++++++++++++++++++++++++++ ++++++++++++++++++++++++++++++++++++++++++++++++++++++++ AaOSydAF',
                                 '256 3 5 AwEAAdSSghOGjU33IQZgwZM2Hh771VGXX05olJK49FxpSyuEAjDBXY58 LGU9R2Zgeecnk/b9EAhFu/vCV9oECtiTCvwuVAkt9YEweqYDluQInmgP NGMJCKdSLlnX93DkjDw8rMYv5dqXCuSGPlKChfTJOLQxIAxGloS7lL+c 0CTZydAF')
         }

rel_keys = { dns.name.empty :
             dns.rrset.from_text('@', 3600, 'IN', 'DNSKEY',
                                 '257 3 5 AwEAAenVTr9L1OMlL1/N2ta0Qj9LLLnnmFWIr1dJoAsWM9BQfsbV7kFZ XbAkER/FY9Ji2o7cELxBwAsVBuWn6IUUAJXLH74YbC1anY0lifjgt29z SwDzuB7zmC7yVYZzUunBulVW4zT0tg1aePbpVL2EtTL8VzREqbJbE25R KuQYHZtFwG8S4iBxJUmT2Bbd0921LLxSQgVoFXlQx/gFV2+UERXcJ5ce iX6A6wc02M/pdg/YbJd2rBa0MYL3/Fz/Xltre0tqsImZGxzi6YtYDs45 NC8gH+44egz82e2DATCVM1ICPmRDjXYTLldQiWA2ZXIWnK0iitl5ue24 7EsWJefrIhE=',
                                 '256 3 5 AwEAAdSSghOGjU33IQZgwZM2Hh771VGXX05olJK49FxpSyuEAjDBXY58 LGU9R2Zgeecnk/b9EAhFu/vCV9oECtiTCvwuVAkt9YEweqYDluQInmgP NGMJCKdSLlnX93DkjDw8rMYv5dqXCuSGPlKChfTJOLQxIAxGloS7lL+c 0CTZydAF')
         }

when = 1290250287

abs_soa = dns.rrset.from_text('dnspython.org.', 3600, 'IN', 'SOA',
                              'howl.dnspython.org. hostmaster.dnspython.org. 2010020047 3600 1800 604800 3600')

abs_other_soa = dns.rrset.from_text('dnspython.org.', 3600, 'IN', 'SOA',
                                    'foo.dnspython.org. hostmaster.dnspython.org. 2010020047 3600 1800 604800 3600')

abs_soa_rrsig = dns.rrset.from_text('dnspython.org.', 3600, 'IN', 'RRSIG',
                                    'SOA 5 2 3600 20101127004331 20101119213831 61695 dnspython.org. sDUlltRlFTQw5ITFxOXW3TgmrHeMeNpdqcZ4EXxM9FHhIlte6V9YCnDw t6dvM9jAXdIEi03l9H/RAd9xNNW6gvGMHsBGzpvvqFQxIBR2PoiZA1mX /SWHZFdbt4xjYTtXqpyYvrMK0Dt7bUYPadyhPFCJ1B+I8Zi7B5WJEOd0 8vs=')

rel_soa = dns.rrset.from_text('@', 3600, 'IN', 'SOA',
                              'howl hostmaster 2010020047 3600 1800 604800 3600')

rel_other_soa = dns.rrset.from_text('@', 3600, 'IN', 'SOA',
                                    'foo hostmaster 2010020047 3600 1800 604800 3600')

rel_soa_rrsig = dns.rrset.from_text('@', 3600, 'IN', 'RRSIG',
                                    'SOA 5 2 3600 20101127004331 20101119213831 61695 @ sDUlltRlFTQw5ITFxOXW3TgmrHeMeNpdqcZ4EXxM9FHhIlte6V9YCnDw t6dvM9jAXdIEi03l9H/RAd9xNNW6gvGMHsBGzpvvqFQxIBR2PoiZA1mX /SWHZFdbt4xjYTtXqpyYvrMK0Dt7bUYPadyhPFCJ1B+I8Zi7B5WJEOd0 8vs=')

sep_key = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY,
                              '257 3 5 AwEAAenVTr9L1OMlL1/N2ta0Qj9LLLnnmFWIr1dJoAsWM9BQfsbV7kFZ XbAkER/FY9Ji2o7cELxBwAsVBuWn6IUUAJXLH74YbC1anY0lifjgt29z SwDzuB7zmC7yVYZzUunBulVW4zT0tg1aePbpVL2EtTL8VzREqbJbE25R KuQYHZtFwG8S4iBxJUmT2Bbd0921LLxSQgVoFXlQx/gFV2+UERXcJ5ce iX6A6wc02M/pdg/YbJd2rBa0MYL3/Fz/Xltre0tqsImZGxzi6YtYDs45 NC8gH+44egz82e2DATCVM1ICPmRDjXYTLldQiWA2ZXIWnK0iitl5ue24 7EsWJefrIhE=')

good_ds = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS,
                              '57349 5 2 53A79A3E7488AB44FFC56B2D1109F0699D1796DD977E72108B841F96 E47D7013')

when2 = 1290425644

abs_example = dns.name.from_text('example')

abs_dsa_keys = { abs_example :
                 dns.rrset.from_text('example.', 86400, 'IN', 'DNSKEY',
                                     '257 3 3 CI3nCqyJsiCJHTjrNsJOT4RaszetzcJPYuoH3F9ZTVt3KJXncCVR3bwn 1w0iavKljb9hDlAYSfHbFCp4ic/rvg4p1L8vh5s8ToMjqDNl40A0hUGQ Ybx5hsECyK+qHoajilUX1phYSAD8d9WAGO3fDWzUPBuzR7o85NiZCDxz yXuNVfni0uhj9n1KYhEO5yAbbruDGN89wIZcxMKuQsdUY2GYD93ssnBv a55W6XRABYWayKZ90WkRVODLVYLSn53Pj/wwxGH+XdhIAZJXimrZL4yl My7rtBsLMqq8Ihs4Tows7LqYwY7cp6y/50tw6pj8tFqMYcPUjKZV36l1 M/2t5BVg3i7IK61Aidt6aoC3TDJtzAxg3ZxfjZWJfhHjMJqzQIfbW5b9 q1mjFsW5EUv39RaNnX+3JWPRLyDqD4pIwDyqfutMsdk/Py3paHn82FGp CaOg+nicqZ9TiMZURN/XXy5JoXUNQ3RNvbHCUiPUe18KUkY6mTfnyHld 1l9YCWmzXQVClkx/hOYxjJ4j8Ife58+Obu5X',
                                     '256 3 3 CJE1yb9YRQiw5d2xZrMUMR+cGCTt1bp1KDCefmYKmS+Z1+q9f42ETVhx JRiQwXclYwmxborzIkSZegTNYIV6mrYwbNB27Q44c3UGcspb3PiOw5TC jNPRYEcdwGvDZ2wWy+vkSV/S9tHXY8O6ODiE6abZJDDg/RnITyi+eoDL R3KZ5n/V1f1T1b90rrV6EewhBGQJpQGDogaXb2oHww9Tm6NfXyo7SoMM pbwbzOckXv+GxRPJIQNSF4D4A9E8XCksuzVVdE/0lr37+uoiAiPia38U 5W2QWe/FJAEPLjIp2eTzf0TrADc1pKP1wrA2ASpdzpm/aX3IB5RPp8Ew S9U72eBFZJAUwg635HxJVxH1maG6atzorR566E+e0OZSaxXS9o1o6QqN 3oPlYLGPORDiExilKfez3C/x/yioOupW9K5eKF0gmtaqrHX0oq9s67f/ RIM2xVaKHgG9Vf2cgJIZkhv7sntujr+E4htnRmy9P9BxyFxsItYxPI6Z bzygHAZpGhlI/7ltEGlIwKxyTK3ZKBm67q7B')
                 }

abs_dsa_soa = dns.rrset.from_text('example.', 86400, 'IN', 'SOA',
                                  'ns1.example. hostmaster.example. 2 10800 3600 604800 86400')

abs_other_dsa_soa = dns.rrset.from_text('example.', 86400, 'IN', 'SOA',
                                        'ns1.example. hostmaster.example. 2 10800 3600 604800 86401')

abs_dsa_soa_rrsig = dns.rrset.from_text('example.', 86400, 'IN', 'RRSIG',
                                        'SOA 3 1 86400 20101129143231 20101122112731 42088 example. CGul9SuBofsktunV8cJs4eRs6u+3NCS3yaPKvBbD+pB2C76OUXDZq9U=')

example_sep_key = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY,
                                      '257 3 3 CI3nCqyJsiCJHTjrNsJOT4RaszetzcJPYuoH3F9ZTVt3KJXncCVR3bwn 1w0iavKljb9hDlAYSfHbFCp4ic/rvg4p1L8vh5s8ToMjqDNl40A0hUGQ Ybx5hsECyK+qHoajilUX1phYSAD8d9WAGO3fDWzUPBuzR7o85NiZCDxz yXuNVfni0uhj9n1KYhEO5yAbbruDGN89wIZcxMKuQsdUY2GYD93ssnBv a55W6XRABYWayKZ90WkRVODLVYLSn53Pj/wwxGH+XdhIAZJXimrZL4yl My7rtBsLMqq8Ihs4Tows7LqYwY7cp6y/50tw6pj8tFqMYcPUjKZV36l1 M/2t5BVg3i7IK61Aidt6aoC3TDJtzAxg3ZxfjZWJfhHjMJqzQIfbW5b9 q1mjFsW5EUv39RaNnX+3JWPRLyDqD4pIwDyqfutMsdk/Py3paHn82FGp CaOg+nicqZ9TiMZURN/XXy5JoXUNQ3RNvbHCUiPUe18KUkY6mTfnyHld 1l9YCWmzXQVClkx/hOYxjJ4j8Ife58+Obu5X')

example_ds_sha1 = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS,
                                      '18673 3 1 71b71d4f3e11bbd71b4eff12cde69f7f9215bbe7')

example_ds_sha256 = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS,
                                        '18673 3 2 eb8344cbbf07c9d3d3d6c81d10c76653e28d8611a65e639ef8f716e4e4e5d913')
# }}}

class DNSSECValidatorTestCase(unittest.TestCase): # {{{

    def testAbsoluteRSAGood(self):
        dnssec.validate(abs_soa, abs_soa_rrsig, abs_keys, None, when)

    def testDuplicateKeytag(self):
        dnssec.validate(abs_soa, abs_soa_rrsig, abs_keys_duplicate_keytag, None, when)

    def testAbsoluteRSABad(self):
        def bad():
            dnssec.validate(abs_other_soa, abs_soa_rrsig, abs_keys, None,
                                when)
        self.failUnlessRaises(dnssec.ValidationFailure, bad)

    def testRelativeRSAGood(self):
        dnssec.validate(rel_soa, rel_soa_rrsig, rel_keys,
                            abs_dnspython_org, when)

    def testRelativeRSABad(self):
        def bad():
            dnssec.validate(rel_other_soa, rel_soa_rrsig, rel_keys,
                                abs_dnspython_org, when)
        self.failUnlessRaises(dnssec.ValidationFailure, bad)

    def testMakeSHA256DS(self):
        ds = dnssec.make_ds(abs_dnspython_org, sep_key, 'SHA256')
        self.failUnless(ds == good_ds)

    def testAbsoluteDSAGood(self):
        dnssec.validate(abs_dsa_soa, abs_dsa_soa_rrsig, abs_dsa_keys, None,
                            when2)

    def testAbsoluteDSABad(self):
        def bad():
            dnssec.validate(abs_other_dsa_soa, abs_dsa_soa_rrsig,
                                abs_dsa_keys, None, when2)
        self.failUnlessRaises(dnssec.ValidationFailure, bad)

    def testMakeExampleSHA1DS(self):
        ds = dnssec.make_ds(abs_example, example_sep_key, 'SHA1')
        self.failUnless(ds == example_ds_sha1)

    def testMakeExampleSHA256DS(self):
        ds = dnssec.make_ds(abs_example, example_sep_key, 'SHA256')
        self.failUnless(ds == example_ds_sha256)
# }}}

### Signing testcase data (text representations of zones) {{{

# Original (unsigned) zone {{{
zone_orig_txt = """
$ORIGIN example.com.
@ 3600 IN SOA cns1 hostmaster 2013042903 3600 1800 1209600 3600
@ 3600 IN NS cns1
@ 3600 IN NS cns2
@ 3200 IN A 10.128.128.10
@ 3200 IN AAAA fc00::fc00
@ 3200 IN MX 10 mx1.example.org.
@ 3200 IN MX 20 mx2.example.org.
* 3200 IN A 10.1.2.4
_sip._tcp 3200 IN SRV 0 5 5060 sipserver.example.org.
a 3200 IN A 10.1.2.4
yljkjljk.a 3200 IN A 10.1.2.4
Z.a 3200 IN A 10.1.2.4
zABC.a 3200 IN A 10.1.2.4
delegated 3200 IN NS ns1.example.org.
delegation2 3200 IN NS ns1.delegation2
delegation2 3200 IN A 10.2.3.4
ns1.delegation2 3200 IN A 10.34.12.34
empty.non.terminal 3200 IN A 10.1.2.4
test 3200 IN TXT "aaa"
test 3200 IN TXT "bbb"
test 3200 IN DNAME example.org.
www 3200 IN A 10.1.2.3
www 3200 IN A 10.1.2.5
www 3200 IN A 10.1.2.4
z 3200 IN A 10.1.2.4
cns1 3200 IN A 10.4.4.3
cns2 3200 IN A 10.5.4.3
uppercase 3200 IN CNAME UPPERCASE.EXAMPLE.ORG.
"""
# }}}

# Zone signed using single RSASHA1 ZSK key {{{
zone_rsasha1_txt = """
$ORIGIN example.com.
example.com.	3600	IN	SOA	cns1.example.com. hostmaster.example.com. 2013042903 3600 1800 1209600 3600
example.com.	3600	IN	RRSIG	SOA 5 2 3600 20140430073146 20130420073221 8560 example.com. WvNC5PAnRTsFLHkzDUmWWxAwe2ZzhMAGz40N400PmToMAKC1xDnOD9tJi5Zxx9lhON89x1ncmmfPnIZ+Ki9U3qDbt9U0mjiE6ESmm1b+zvqFmX5lAS8jBW12OYzC6Bu6cHi2v48Y+PdHT93NlMz3HW6YJfckbq/U/NbIwEtrB1E=
example.com.	3200	IN	A	10.128.128.10
example.com.	3200	IN	RRSIG	A 5 2 3200 20140430073146 20130420073221 8560 example.com. AbZC4qkQOeEHrt7az6QYq4PdG1GuTScsYXbI/IM1Bpw7YJD2LiQfaOSE+IrWiVHH7XniiCdOU2IT1W9R/fdUJJWk9aROE9qaCb6sNK8GgC7Kw8P76N9oMrMB0CBqqQiWZxm2vUACKkFleHljKnb3TAzVUEaZ/CInkIbgp1E4xmk=
example.com.	3600	IN	NS	cns1.example.com.
example.com.	3600	IN	NS	cns2.example.com.
example.com.	3600	IN	RRSIG	NS 5 2 3600 20140430073146 20130420073221 8560 example.com. t6dymuKe0lx+s1KYg99BROwNVGfmaUnqk4/t9Ady1DOqQBVz4V0tdxiH4q3BVhl7lURBxvOa5CxmwNU5XDTJWeuI0ZILBlrcG+h9pr7APUi57MfHstBMYOWYxxsxU2TYUh86iR9vHQ1M+Ll2s0oL7PMxEGrxl+Qf30gulmUD1Ig=
example.com.	3200	IN	MX	10 mx1.example.org.
example.com.	3200	IN	MX	20 mx2.example.org.
example.com.	3200	IN	RRSIG	MX 5 2 3200 20140430073146 20130420073221 8560 example.com. fcyipGXS87aiiSvZYkLPm0lJF9ktpES8c6Pgl6z0UjiFSGpeyZX2Q4DpRYdaLnuRenbl0rDzTrIvbrEeUF+RhOPsLO+uxLFlcdHQMQqHjbjT73HI0pAJmgDLahAuKUIFWIkiFK8ukDrOF9B9/sJnelxPuRKvafydOULKJGG2Dxw=
example.com.	3200	IN	AAAA	fc00::fc00
example.com.	3200	IN	RRSIG	AAAA 5 2 3200 20140430073146 20130420073221 8560 example.com. lGHqA+WLOFEp436PoetFSKfO/3eXP+7t5/oxfZjCZKCpZGJNOxiqtRZprPqkYUYvUkPcJz+OYC4I3n2AeSELylmDMMF2pTL6rISr7K8yi9ebe0MzDjMCUx8VOMVb/0IWtFfwj6z2Atazbd0gvYaz1M2z0milTZi2Hz2kJch/nCM=
example.com.	3600	IN	DNSKEY	256 3 5 AwEAAbwPwkos3jZeAODOzW6AE0qf2ezpSEK6x7VAU2gMVTWAjN9IlkQAmxcNfBBFy9ny4o/8kZTTWyw7pyALzNx9jxhrnwiIdoWR/7N0Qq1Ia/CWfszWjlXvzDEwwkM/Qs41/8evCEShJBuk17wMJKmuHkAPoEgUcN4v0tnB892Aeq0v ;{id = 8560 (zsk), size = 1024b}
example.com.	3600	IN	RRSIG	DNSKEY 5 2 3600 20140430073146 20130420073221 8560 example.com. OVtvMgztmU7mI0zFz+YYI3MSbcLoZeSOn0a1NxT1yC1NK1ImHxnA6ewQA2X9vxrUdXSdoZu9yhEVkpuj2hhtBOWp1B2GHNLpy9Mj/8TMrmOHRT8fih/1uyuWeMQZlxwakVyGNgh6iWGXcav+96tCyWtk4bSNmRG7iwxM9huQOTo=
example.com.	3600	IN	NSEC	*.example.com. A NS SOA MX AAAA RRSIG NSEC DNSKEY 
example.com.	3600	IN	RRSIG	NSEC 5 2 3600 20140430073146 20130420073221 8560 example.com. CM6/tFqCBcX/6shqUlTMzLMzZCkuMjBr3nrUbHhu+5a4mfQt5zJuZ8LqgVojP6+ADi62kFWLNEk9rPeH5Pg30aRvaD//NfAuNV860QGF3a2c2eZiJwPXwm6ChpbIV2Z6Wb3eSx9D74rzUgcfKkhVHxD6hQh/zoqGVN+t3BzgShI=
*.example.com.	3200	IN	A	10.1.2.4
*.example.com.	3200	IN	RRSIG	A 5 2 3200 20140430073146 20130420073221 8560 example.com. pi4NU0oru/PRLSaOu9qbPMRXXmyIhfmythEWd/qEnT0X6XoKZ/+cncYtI2/nvknM4ui88eb/uL5+g1V/JXC2ozbCwSDovZ1biz4GIVkR+fFFX04tUYwpeKSbVZcPUMiXGZHbQk/AhVMzpfEFBcDPIAbBiEFo8AiVvEMdvHtPBNA=
*.example.com.	3600	IN	NSEC	_sip._tcp.example.com. A RRSIG NSEC 
*.example.com.	3600	IN	RRSIG	NSEC 5 2 3600 20140430073146 20130420073221 8560 example.com. uSauzVWZ/zshTbcN0rOFxHwJyHKkZrTIV9lW4ZhH/o2xb502ugEMxKwyEcRz6pfb2N3qiSiVUB1Q/wmNyE+AfZDV6V5akm/6n401BvvCr2/3nTs6UkGuqg1HT8ytGTi4cT49b4YZiGAw5FpQiKMGxaqHLnP/hLCykBLjkfn8/Hw=
_sip._tcp.example.com.	3200	IN	SRV	0 5 5060 sipserver.example.org.
_sip._tcp.example.com.	3200	IN	RRSIG	SRV 5 4 3200 20140430073146 20130420073221 8560 example.com. LvWY2kTmKAEdRIc8SJbczI3Lei3pIrKDLgNUYAnp+igQIXqMoZ6xb8ZpLybpJxRn5K0Ph3WZ7S+ypc1FsScm+JhptITyU2/ZRBrxm0Q0zFYa3cGHRbgXTGBcVah0BFx+Gm0uJMXk9zegN6ST05XcbsLBhZk6ckYqq+XLTFjMV5A=
_sip._tcp.example.com.	3600	IN	NSEC	a.example.com. SRV RRSIG NSEC 
_sip._tcp.example.com.	3600	IN	RRSIG	NSEC 5 4 3600 20140430073146 20130420073221 8560 example.com. dHobUHvvNDUb2sCae0mqei2iyILFyA3Xlytq23+Prk4B5f55cP71NRN3l6wPQgwnFMqxt8dkyyOrbEGg88EDWOQOxjZATrA+EEzBDs5dPt1jB1RnbEC1xTuRwaqHyl9cRxzDXIMgF9HsQIWBuDkkPngrDU3N1nnKz2Guq0qsFVE=
a.example.com.	3200	IN	A	10.1.2.4
a.example.com.	3200	IN	RRSIG	A 5 3 3200 20140430073146 20130420073221 8560 example.com. sG16bknl+KJPMbab40XPUDaGVXYJq58JLRA0vfcoAuIKP629P0po5DBOYu6Ou0n+wUqGLFSBIgqJV5ABiJCE0eoh8UM8QTJ197sxODe5jMHKZvqx9YULohj7x+hi4qrU5WowEH1fD23/xMue73eltUz6ZK09Q3wIeZMu6BPuw/k=
a.example.com.	3600	IN	NSEC	yljkjljk.a.example.com. A RRSIG NSEC 
a.example.com.	3600	IN	RRSIG	NSEC 5 3 3600 20140430073146 20130420073221 8560 example.com. VqsyZOvSWXYeA3CybG+0GTLiBIqLN/8l0Rmz/PPc685X6LO9kFf25UQ0GtvAD8vub10oUIE+cZODSQckFxb1yc7KYA1T3q77RkhcC84ENFMO9so16h0pxKPS1jEoCPY95Cw7X92gbS/NUB15u+l7B1LMVaGXqRGi/7UmL65e18o=
yljkjljk.a.example.com.	3200	IN	A	10.1.2.4
yljkjljk.a.example.com.	3200	IN	RRSIG	A 5 4 3200 20140430073146 20130420073221 8560 example.com. fqHqGBo8Y0kGGGlR28EjdmVIyVl09LxSTIY8bjKM6+su7+gnB2/7VltBBWLGTDBStBB7tKBKsw1n0DyLlvWquLchcwWURz7m3X4r0jhg+EQLUgaukt2HuYGxeWHzOLpE5k7c31+ffEQn12zAzn1JfGWdFnM+jj09vTj0xw4xUBg=
yljkjljk.a.example.com.	3600	IN	NSEC	Z.a.example.com. A RRSIG NSEC 
yljkjljk.a.example.com.	3600	IN	RRSIG	NSEC 5 4 3600 20140430073146 20130420073221 8560 example.com. guXei548zRH7NYFm08s+TkSKpbTvQeQ0to6HrvDB86Qug86kVDps4Ec4NWolH0I8viSAV0F0MTY9ccQ5wUvbh+xb0HGoX4kvRcM5tLe3uF22rQJsJkUfkvFZI4ht5HUo6niLvPd1eKJirrjuEkOdVD0jQhYTV60/a+k30MxIYHk=
Z.a.example.com.	3200	IN	A	10.1.2.4
z.a.example.com.	3200	IN	RRSIG	A 5 4 3200 20140430073146 20130420073221 8560 example.com. i2KWRLqhLbGt1FNgF9OZwnloEZMJ4KocTSUOzmvCR1XYs3mD4gySHJen3KyH5sxTRPT5CHVv78X1ne2BmFrO7+q6pOmd2rwb/vRTRe4ClkFBTcJtjy1wkoPtlezWmU80AVmQs63+eOX1K3sDUZl3lp8ifahR27aWdmxKnnIPID0=
Z.a.example.com.	3600	IN	NSEC	zABC.a.example.com. A RRSIG NSEC 
z.a.example.com.	3600	IN	RRSIG	NSEC 5 4 3600 20140430073146 20130420073221 8560 example.com. Opl4yjC7spVBq01pwQc9Vxhlny+6iREhR8j3RaD0Rcp/CWb16f9cUxHXdU1eD9aKMshkFmeBk75ib/dHb6P7lMzliLGjXwdePJ6FIywvcPKVKH4seKMK3pIn8Mn26BDm15VyCRK653z1VM+ZH4PEf9hL5KyXYK1hypKjkJTcnTw=
zABC.a.example.com.	3200	IN	A	10.1.2.4
zabc.a.example.com.	3200	IN	RRSIG	A 5 4 3200 20140430073146 20130420073221 8560 example.com. Ny48MWVGVWRSzhJvRDqmW6hwyrNVPg7paTnSexPoYWrL2mhe/0jyZRClP1zJChjMRBJDCIWIuUCCWm4nq5oO9GudYWe2c7QQxGOvuCRadBZUL7VnswdqivBMEJw2l7ti9seTdlvn4Ad/qcDcOnvpqR4ZX+pTriipygroYFcIBdA=
zABC.a.example.com.	3600	IN	NSEC	cns1.example.com. A RRSIG NSEC 
zabc.a.example.com.	3600	IN	RRSIG	NSEC 5 4 3600 20140430073146 20130420073221 8560 example.com. WJZBKgpZCY0s1qcC4FkkIYpz7tbApX7MfRYtQ324fPdsUpf+PWwqgyxZm5eQ7lz+xbYtquDu4iCk1Q/RO8m/qMZNR6mRoylF7yP+bs4K7k4gTsmRIQz4wyC089GBJCcTQR+ULdWhTvuXDD0Ar8gB2LrwkEO5tzlr8MwBx2MBUK4=
cns1.example.com.	3200	IN	A	10.4.4.3
cns1.example.com.	3200	IN	RRSIG	A 5 3 3200 20140430073146 20130420073221 8560 example.com. a16/qThTAe18uusG6FvYfo7cz6eTITeoR4snKkLW+mj7A60Yg6nnvZrPNu0zkx6AsULnE55kxIs06dwrDX/lNiIRrSbT1EiNHau9aqmduAFgjxxtNh2ouWZSVoqp5qps9//tFoLiCMMQ0D7HzyC4qoYh75N5i0LXmkvbtMvHRkM=
cns1.example.com.	3600	IN	NSEC	cns2.example.com. A RRSIG NSEC 
cns1.example.com.	3600	IN	RRSIG	NSEC 5 3 3600 20140430073146 20130420073221 8560 example.com. SE/zG0BdzIzPzxthRZ84KFzJDUudoMdO18Vk/0UdcxtCNpK5eMpODx3WV5uo1ZN5jYXrUZt2AyvFX2hA+gfI0JXnb6WUHFWJBZU+99ogwBUzhGwHHFk+3x5lpyXg9uvkHP0ySPjkNrew10tpM+eDVxH88HPa4+kH3xkGW7jrrMA=
cns2.example.com.	3200	IN	A	10.5.4.3
cns2.example.com.	3200	IN	RRSIG	A 5 3 3200 20140430073146 20130420073221 8560 example.com. O5xa9nWR/bIAuKXz6JUEC75nYVNqAqtoaGh6OHJ5h3JylnEy4Lsen0ClUVLaAof+5kbDTi2O33AQWjbHGdH8Nb5VPGh0Ur8chpOkDqq8sRm1xA+1+r7uLuV74frQtubhokSblNMXnh/PliYF+BeI8+jq5QqLEcMpnN4F5FF/07M=
cns2.example.com.	3600	IN	NSEC	delegated.example.com. A RRSIG NSEC 
cns2.example.com.	3600	IN	RRSIG	NSEC 5 3 3600 20140430073146 20130420073221 8560 example.com. LMSgxTA7PpzHMl8nh+hPLH3lLyWL5guZLzP+UoSMtfeAa5VoTEtbzSC6kVta2+X+W3K6FR3lHJqKvSY9KXgIaC3Qus4Uw247hgT9BmVPfus7ZII9AtrW7/pOLBkPuXilQw45sl8ktvh+6iQzlxscZ++iwmx+ID2WQfF2iQ3aV4I=
delegated.example.com.	3200	IN	NS	ns1.example.org.
delegated.example.com.	3600	IN	NSEC	delegation2.example.com. NS RRSIG NSEC 
delegated.example.com.	3600	IN	RRSIG	NSEC 5 3 3600 20140430073146 20130420073221 8560 example.com. lHQEqAhT+DOLA2U/SGhhP2sNW9cDMs5yOTcF7p5OhHBb2OgEPlHhtj1lX1XMXBxQQlrAAToIYTAvzgAvzcfgTCbwYHxb/lKRZjcmFgASU1SSnlksR84w7t+6HEAsFDdfCguckU2bFiT6iHWMvF9VLsr3/ZxBEwcZKeco5Uoug6o=
delegation2.example.com.	3200	IN	A	10.2.3.4
delegation2.example.com.	3200	IN	NS	ns1.delegation2.example.com.
delegation2.example.com.	3600	IN	NSEC	empty.non.terminal.example.com. NS RRSIG NSEC 
delegation2.example.com.	3600	IN	RRSIG	NSEC 5 3 3600 20140430073146 20130420073221 8560 example.com. FrQe6XzLQE5o4X1nCTVpV3Vm5nW+DDPa4BPT9LEePmBWwjgNsxBlbJJyqKcDfRVhksIttQpcqmt6mVRoXEItbMt1xHOPsktj1FVoCgYKoDZMCtW69VnDhCtRj3J9qRgJs8GMv2Oca2FGgyHfj3NqtHLEwKpO0BnOtmJwN6YU08U=
ns1.delegation2.example.com.	3200	IN	A	10.34.12.34
empty.non.terminal.example.com.	3200	IN	A	10.1.2.4
empty.non.terminal.example.com.	3200	IN	RRSIG	A 5 5 3200 20140430073146 20130420073221 8560 example.com. aoMFgDUyHuj+T8ybfC9nb4PwiMJSmcAhyJ6qTPMb+RfAA9kAz8nL8J81ZtDMH79/HYfVhEwXZLMCABEGO8TG1Cs6sANZO287+ElFUNbvBE5ax6uF9ksse5gtDbLmVQ0lXHpUYca+lB1UZfkojZhru3Ll2X7Uby/7yd854c838Iw=
empty.non.terminal.example.com.	3600	IN	NSEC	test.example.com. A RRSIG NSEC 
empty.non.terminal.example.com.	3600	IN	RRSIG	NSEC 5 5 3600 20140430073146 20130420073221 8560 example.com. DpHKoXnNnoF+1k7iBy+LEVmkzrZcXyvmJtfFRLnxsxlRLJxAFkPze1hMMPl2cHLKe+I14MdEIzTL59XP21G7QVs2VQ/evbiMLfYyVSY9YWYiRFY9fo8Bc6iDrDniFPYkqcq+1P7tq/pMo5tMGoGdgQxeDPlo22a6545pKmb/ZAM=
test.example.com.	3200	IN	TXT	"aaa"
test.example.com.	3200	IN	TXT	"bbb"
test.example.com.	3200	IN	RRSIG	TXT 5 3 3200 20140430073146 20130420073221 8560 example.com. VQ8IKu07p6bM/pOs6jpfvUhVhrJbLRxQFeF8cgwbh1MtCgsl+o2LRqNVEzjUktisaBj1rXeOOQX6i3BzioWSUvNnagV6+zguE0OyanoEx9PdBC1Hzx5kjEosX/bvKsfyy91O87U9raApofjmA+N888uzRYE84F7lMARmusLPAws=
test.example.com.	3200	IN	DNAME	example.org.
test.example.com.	3200	IN	RRSIG	DNAME 5 3 3200 20140430073146 20130420073221 8560 example.com. uRm0B40jz2HFmMarbwZrZUO5nonKHVvkERze5xyw5vSvKGPatrvvGPobAE9rIDaIJjP1MSKvvZohCwcAADHuW9+3kGbG0DDld/J8mSYySiWqwzfzS13pIo41P3Vfyf5ITwqB31QVNQglAUm5ZpEVjeN00nGwgCKyLpoGnNA4tYI=
test.example.com.	3600	IN	NSEC	uppercase.example.com. TXT DNAME RRSIG NSEC 
test.example.com.	3600	IN	RRSIG	NSEC 5 3 3600 20140430073146 20130420073221 8560 example.com. KqfYAyBUtd11ZUCleVNMkS5Lw5oLcmOFwUpQPr2BoIRb6a4mc6xaIxNzHPv/YzJGYjTa+FWW13Tfy2tsB+SczYDXPIJrq0LsGg0KWA4VMU82lnEAPcTCNgCEKa7/zQgVIcfWwJa6dPvycMDvyMSWmS5TFAaRPlxiaZlW4MXwIwY=
uppercase.example.com.	3200	IN	CNAME	UPPERCASE.EXAMPLE.ORG.
uppercase.example.com.	3200	IN	RRSIG	CNAME 5 3 3200 20140430073146 20130420073221 8560 example.com. WNjX5AfwazukmXLLu3EsV2MlLKb5ShUyyf0YRSOcvS4yQyVQC3vaoeR3FjN5lj5rcFyhY1aBjn4RsjMirgZ6pJ2ACeADS6aQB3/BWoxdgvgDynf/xyiWiNDLgfxH3rJaI0y4+tprppkZC+F2gdnoUVJpYAZR7w0l31Y8lRbP3DQ=
uppercase.example.com.	3600	IN	NSEC	www.example.com. CNAME RRSIG NSEC 
uppercase.example.com.	3600	IN	RRSIG	NSEC 5 3 3600 20140430073146 20130420073221 8560 example.com. bgmO6wOHrAbzAJCpMcLd44U/Flt4rR24dRMAHn2fJObtcUp+ycW14BcfXYDjXbkzVGE8ckbVmxuI/47nfwg6ZwmXY3IzC5owhEuX2SYAHCkFl1QEI/j8zUQE+owHf7bIPiyi6jJJdJPXvRUYYChivmERqb3Q2WVGy/Knsl/ojSM=
www.example.com.	3200	IN	A	10.1.2.3
www.example.com.	3200	IN	A	10.1.2.4
www.example.com.	3200	IN	A	10.1.2.5
www.example.com.	3200	IN	RRSIG	A 5 3 3200 20140430073146 20130420073221 8560 example.com. mYzi3SmhzGN4zFY0IGLI04QB8h7d+I+5XVDW3mB3MFq/Zz7beOBIk6RSPovXMRpnagdmvGsp7cAT2c2Zkk1x1Hef5a10UkVd9tLMDXNpQHY+ieKZvOEhQhRci36YEBjOWSr/k8YriuBH0zECS0h/rq/VSqh/1Kwj1jB59G32lSc=
www.example.com.	3600	IN	NSEC	z.example.com. A RRSIG NSEC 
www.example.com.	3600	IN	RRSIG	NSEC 5 3 3600 20140430073146 20130420073221 8560 example.com. c6TccOGVC23tZM5QCQw/U0KqU7tziOq6fBKU8FMZpPAUlLqUqwqlRXpshu0rW5rFEADkm9kkKlMYGosSbG+YaGaxPns1QihQ5HzaTSLn8zCPXGnS4NNDtPuNxUJB02DhCTtcX4ZFxgfwHMoZptEub5MMPU0jcJ3/lCX9K3Or/5Y=
z.example.com.	3200	IN	A	10.1.2.4
z.example.com.	3200	IN	RRSIG	A 5 3 3200 20140430073146 20130420073221 8560 example.com. BiSgn7b8ya0C+cBNaFFSDztMyfUN+c6W6zhsJ60vfCs5FDdPfl+eeH9pAaF936ojjAvdsHB6MK1dYiYeZN+pEuK9K2dmt4fRHx+eWxppZTv9P62EF6e/iZxqz8uD0FyE8fjq2eLU9v9YhOorSpZR0e4JQtHMEYA/GiIGroAF6Z4=
z.example.com.	3600	IN	NSEC	example.com. A RRSIG NSEC 
z.example.com.	3600	IN	RRSIG	NSEC 5 3 3600 20140430073146 20130420073221 8560 example.com. aMjtwOSKj0k+k0/U0ToXlB7adIjUlL5AYF6rNSmqRuKCyt4lfQnPy6e5LmN7I2kEi3A3hZzk0Z50ZVmeus3gaZ2iwnmkfxEJIpgAyTtl9WY4Y8CHhQYeXTgNnM2Q3YcsWEJjNZI8crhDM3ANVKCZEFS+SbtY8e/AtY5sMcQKlmA=
"""
# }}}

# Zone signed using single RSASHA1NSEC3SHA1 ZSK key (NSEC3) {{{
zone_rsasha1nsec3sha1_txt = """
$ORIGIN example.com.
example.com.	3600	IN	SOA	cns1.example.com. hostmaster.example.com. 2013042903 3600 1800 1209600 3600
example.com.	3600	IN	RRSIG	SOA 7 2 3600 20140430073146 20130420073221 8562 example.com. ouKIq416BC64zpChwdw4/HcHqQLgDiNHIZqdSMOnFGW5UmOtqYzC6TN6TXN2nVCi2cC0wZJdpgX//wTCAkzh3UPD6lcPpoMvG6v5zt0NYesa/fy5z2Ms5/UCwnrtw32jSUjomY0KIhLHL5yO9aItrIMh/CqmGb12H/tBor4Rp5Q=
example.com.	3200	IN	A	10.128.128.10
example.com.	3200	IN	RRSIG	A 7 2 3200 20140430073146 20130420073221 8562 example.com. caVCf5hKNprlQfrj1jneuYfn7+zj+BNvCWoyRMF7wMMo1rmlZpEkjx29HlTm3bqtIU8E6BdwlSyzY+jLAah88m8CmKvJtQ6lGD8/MIkTPBrJzC1Lof80KA9CzGgTkEUHiJ247aoHMc7dFTSb9faIKWl7tY5+6sBJbISU/hybCB0=
example.com.	3600	IN	NS	cns1.example.com.
example.com.	3600	IN	NS	cns2.example.com.
example.com.	3600	IN	RRSIG	NS 7 2 3600 20140430073146 20130420073221 8562 example.com. LZ0XDJy/h2lC+yEvSa9YgKsKEM+eQakEw1ZRCK9+g2b/OXewTsFZN1yo5bSzLcmlouZYD6FRaFKAKBMH1WMarMdEcsszhDjVA9Ey8OplxeXaCXvswe+G2qPNiE16rplDQviNheiznNiXeAdHsiPkPvaT1oTlf8LBhAdS3vK+bSQ=
example.com.	3200	IN	MX	10 mx1.example.org.
example.com.	3200	IN	MX	20 mx2.example.org.
example.com.	3200	IN	RRSIG	MX 7 2 3200 20140430073146 20130420073221 8562 example.com. oMcxYTlD/GqvJcguevSJF/htRmw0k3Q/DUS/dKdMBvo1erbR8c/O3U22uSVZPreG704krtxbsQlKOU2acFBS/KwVKbVIxV1pSQBKqYAR4OUqRhJ3KgvEupG8dZ+V9u6P0Wuj2EzlpFhsgsx433nTVXBklnK1orh6UVHb8ijbHrg=
example.com.	3200	IN	AAAA	fc00::fc00
example.com.	3200	IN	RRSIG	AAAA 7 2 3200 20140430073146 20130420073221 8562 example.com. WZgrVf1NXwTslNoxqh5ULOORs4fpe48L4jxa5CES7CmvxC89HJHSqsHLKuRq5dE5N4eyvpmswlHebkLSE/dYF7yrfQh76VWjY2O+SabCVpUeC1Q6qRjFRi77VrdudJFLNJf1I17Ujhmw+MwKCapFVKma6A+ZL7PHI8+ld5Bogpc=
example.com.	3600	IN	DNSKEY	256 3 7 AwEAAbwPwkos3jZeAODOzW6AE0qf2ezpSEK6x7VAU2gMVTWAjN9IlkQAmxcNfBBFy9ny4o/8kZTTWyw7pyALzNx9jxhrnwiIdoWR/7N0Qq1Ia/CWfszWjlXvzDEwwkM/Qs41/8evCEShJBuk17wMJKmuHkAPoEgUcN4v0tnB892Aeq0v ;{id = 8562 (zsk), size = 1024b}
example.com.	3600	IN	RRSIG	DNSKEY 7 2 3600 20140430073146 20130420073221 8562 example.com. AU/y2KJw7pFItNqmcqkW7vTWqqT1ZnpavuT9uDv/GzGa/peDU2EpuaS8OySw21LniQ7JQg+bwbdp6b4PdpaUzmq2y2oBN9lRJnayvgU+NWku1s7hsjWDum4BSwizrjh+BqhVr7JQfaSLncCXK6fLuMiymReFaEEc//3Uf/5M1i0=
example.com.	3600	IN	NSEC3PARAM	1 0 10 05d67bb3fe7bf907 
example.com.	3600	IN	RRSIG	NSEC3PARAM 7 2 3600 20140430073146 20130420073221 8562 example.com. WiXLsJQyzl/aPVG4b2NLaN9LCGAEuVT8sNC4sGWKGORjRs9RZYaILTudiBp69g0d3sG+ZrSfojcSL7XnHusGF1kJPGHO6P4OaNiMs5mfDAK2C8eN3ZjZCfjHghZBsgDkAe4WY4zn80+zXrJ1VfAXOvekq3H/M6niEGdfjA3QGn8=
6r1v3vosorqt80kb3ailjib5a7n3cnlk.example.com.	3600	IN	NSEC3	1 0 10 05d67bb3fe7bf907  884sems3cdr70nhc4d9qhno9a449gslj A NS SOA MX AAAA RRSIG DNSKEY NSEC3PARAM 
6r1v3vosorqt80kb3ailjib5a7n3cnlk.example.com.	3600	IN	RRSIG	NSEC3 7 3 3600 20140430073146 20130420073221 8562 example.com. bW0wMJq3OHsSlRuTpvb6Zr01L+OdJ+UjHR3ACeT/76nA10Vzl3VfO9SyLaQX6hYjq6y7Lo+2vCuwy0IhylDJfex/UtcNjCsa/n8qzI2Gy/UvFVOC27sAnQLKuN7p1oSWtBhI7ZtuAhW8+aJfQMwLsZ9PIXXdkFHAC4ei88VZq34=
*.example.com.	3200	IN	A	10.1.2.4
*.example.com.	3200	IN	RRSIG	A 7 2 3200 20140430073146 20130420073221 8562 example.com. JTFtpPH9+CSoanwr7cCrtFmfuifiVV8CQBWpGbOr3Er3cj4boYxQhpPm1upCPhuI41x+um1BWd9tBxL6o+qjOeyj9rBzVAGDsZdF87n34qvY741cv/Z4trIoco2lFvizf8rouFvC+TNxZ2Xwmnx58VQddhrF+3xH5WL9fAMxJxg=
fiqcf70a6339k96ef2scbk4vkmm0p1j8.example.com.	3600	IN	NSEC3	1 0 10 05d67bb3fe7bf907  i2ferdohnjamei8n3rpmbv4lf5pt4ubg A RRSIG 
fiqcf70a6339k96ef2scbk4vkmm0p1j8.example.com.	3600	IN	RRSIG	NSEC3 7 3 3600 20140430073146 20130420073221 8562 example.com. MmZPh7h9h2z4QiuX3JhDzZzUr8Uz0Al5/EZwJ+HRqECKkFWAyARpOf2DRB6aid69PzdDiUyIBB59Jf0N+mfwSVG2A9qrYz0mmlJIuesAHf2I2lub+46+gce8EPShCYZAuVa8q0g2TiZ937dn8wSXC66+uS8E5rZeO1x26zUZhak=
q4s8hrhd7c8s824nkql0a52ng50mhtut.example.com.	3600	IN	NSEC3	1 0 10 05d67bb3fe7bf907  rdkf8d33qe24o2v2q21na3lbk3oaakcu
q4s8hrhd7c8s824nkql0a52ng50mhtut.example.com.	3600	IN	RRSIG	NSEC3 7 3 3600 20140430073146 20130420073221 8562 example.com. rbClq6iOQmuuUJnSvLYzI4TOmTH8tOaoAAyKHieOsrXcbkoOczAxKHRWYx5RqLN/2hiGrmlKtTWXKZKcCD2Q36zDIk2o1OoTWd4yv9BXcr8LpGV0BNu8lkgnBxshhjRr0CVop25xidr4gAA0XvueB2lPOHcMoxMnBefFEKYQ0SM=
_sip._tcp.example.com.	3200	IN	SRV	0 5 5060 sipserver.example.org.
_sip._tcp.example.com.	3200	IN	RRSIG	SRV 7 4 3200 20140430073146 20130420073221 8562 example.com. o9oyyeoknK2mvXhPGBOA5sTp4rUGVD9QG4CoktjvWkVkZEC5YnHP7yWsg438wtnmUYJrp9Tt0CgOT/1X5aSaph2wxU/ebPcwrko39q1se0mPu7PEebHPwmwhVq7o8oQarI0NeWYrxzYUmUh7AX1qiNyuXfyJB9Ko+szugY+1iXQ=
vju5kq0s3pj4fig4aev90i6m30m4ccsk.example.com.	3600	IN	NSEC3	1 0 10 05d67bb3fe7bf907  1iohp8j7vsr7h24al82qi9b0n3m7o2jt SRV RRSIG 
vju5kq0s3pj4fig4aev90i6m30m4ccsk.example.com.	3600	IN	RRSIG	NSEC3 7 3 3600 20140430073146 20130420073221 8562 example.com. Y6EsX88GMc0R4T8jp39M768H513GwFpXu/g5gjPCbchsZ99Cgygd942O/u6vNcdR/EORDyaKCmiz9MW9VbPYS/yZsH0zO4VRQMikpMMRN2NnykVZqNxp2oI1h/Fo8mZUVJtxQJnlz3oLqqH4W47z1TrPbcjk8xkaBF72kmHd+qs=
a.example.com.	3200	IN	A	10.1.2.4
a.example.com.	3200	IN	RRSIG	A 7 3 3200 20140430073146 20130420073221 8562 example.com. NfLa25PFvCK+lZ7FiyCVDz5lEzGnatA/e80MvIlwd7w+X7wF6rCV/DQby8l7LpnpP4N6fmqKmU5AJKGBqYSHmRYitu1ML/CM1OqSZNLyhIpsKIrqWTZip+cwZlD0KuQYqaPjpeOH2KdbY5V411khE+zvJSiIeO0dkehKqBGGzrQ=
9kpaurblh2ncekbdnnuml8o6tegktpve.example.com.	3600	IN	NSEC3	1 0 10 05d67bb3fe7bf907  a6t3254d1semge7fq420mfvqjkg7bgtf A RRSIG 
9kpaurblh2ncekbdnnuml8o6tegktpve.example.com.	3600	IN	RRSIG	NSEC3 7 3 3600 20140430073146 20130420073221 8562 example.com. Iqy+1gvmgtc+ojeNIkd96IC+Zhhkhb2/c+lBmVrA8BQjPMcakv2zOOSVwKzyxRK9PHaFPWLbYrMhO9eruFcAJn60r+4UTixhx3Di6oanIygGQ6AeFCMHYULZFHxJnJbXVhiELz5iNekqfwmzfKb2zFLLzgDXy8TaowzJyckWwgY=
yljkjljk.a.example.com.	3200	IN	A	10.1.2.4
yljkjljk.a.example.com.	3200	IN	RRSIG	A 7 4 3200 20140430073146 20130420073221 8562 example.com. INlfRB6Go5NE1Yzk9eQjrSl0vf1vwC2zCONcKRZXAh0QmcbXsH4F7+OpqXFcXXKLIHm1RkGmA47nz2ZLTzUn5Pdkn9YxteFShR5fb/xE5YLd8Vm6j77FshhZSqwaB5RlZ3f2sRyMF41hSS/zH3xkXCQwHVgkspUt55bMjDunaAA=
vcfnvpc2eqaspricadp3cigdgm8ujef8.example.com.	3600	IN	NSEC3	1 0 10 05d67bb3fe7bf907  vju5kq0s3pj4fig4aev90i6m30m4ccsk A RRSIG 
vcfnvpc2eqaspricadp3cigdgm8ujef8.example.com.	3600	IN	RRSIG	NSEC3 7 3 3600 20140430073146 20130420073221 8562 example.com. PjsXJJBgvl3vB0/mFPcUPLUrN0d95u8Ok69Zrsx8rI2fl/P787+fEOVJqjoNCBj2/oUjYG94Lc0yHRI5FJbazIkghTgmmOdUQPBbDPjVr/BNsvWrghkeeLzctuWBtVV0CbGGzR17r3MeHSSB7Wi3eviG+L/vt44JfBcMo7moQ1U=
Z.a.example.com.	3200	IN	A	10.1.2.4
z.a.example.com.	3200	IN	RRSIG	A 7 4 3200 20140430073146 20130420073221 8562 example.com. TUhzGWUnmmI13QzP+LxoURxsVcZHjsTfgGdbUbIEQumWy10vMhobq6hxg+8cmZvYIc6wM4zS+wgPfjLTtbvI1gpBPflGblRLMCdeQYbJ/k3xERbln470WihtZclx2sFCmPXCZA7uTy/R6ikPns6V2gHnPxw2NVSz00XkjXfMmrY=
884sems3cdr70nhc4d9qhno9a449gslj.example.com.	3600	IN	NSEC3	1 0 10 05d67bb3fe7bf907  9kpaurblh2ncekbdnnuml8o6tegktpve A RRSIG 
884sems3cdr70nhc4d9qhno9a449gslj.example.com.	3600	IN	RRSIG	NSEC3 7 3 3600 20140430073146 20130420073221 8562 example.com. bYjvbOjB2OSd39+3GSSaKD2h4BWBQ5fRLTSdgXqL/OA6zNsCGFuDKv+e2juN7jVNXOEDnQJHf71fGsg+sxJrm++kONv+T2xCThe2vz3g6javTpGepg2ISTSqmca7AtroPh/Q2f+XnzlasQqqCTsdwcEjxKhXLkgyO4kVa4IfunQ=
zABC.a.example.com.	3200	IN	A	10.1.2.4
zabc.a.example.com.	3200	IN	RRSIG	A 7 4 3200 20140430073146 20130420073221 8562 example.com. dc3jzgQM+9W2fbz4nZjQLj49C1kWtWH1r6fC2oc6vZq8cuMLrDJ4zIt1rvxWL6Efp07D+aJ2606pSJqWNUy/eb6Odb9O2YMeU+2hTaCNWxDj8ay3M0mkKHUMd4q6Qj35m92U6UPhdzM3zDvkkw2WkaOBZDqvrYay5TOSuMkXGTA=
i887uaqoprdnmesu0ughr7sheqaug3h1.example.com.	3600	IN	NSEC3	1 0 10 05d67bb3fe7bf907  iu0ms05m0tb8if6q0hsa6pnppi75ap3g A RRSIG 
i887uaqoprdnmesu0ughr7sheqaug3h1.example.com.	3600	IN	RRSIG	NSEC3 7 3 3600 20140430073146 20130420073221 8562 example.com. Hb+CEkIzkJxX1vGc/0/V+mGMFN0bIvf7G81AObX3AWzcdehADCGFsW5UoeVGcANLNDXQoY4rLtBXL6gpmRNKtFflWqZAYcSZdpM3y04+w21SBNqpXTUV7ZkUbvKQ9WpJyIYWWYkma7noponVp02tfSLv92rBJ+viJWOdgatI42o=
cns1.example.com.	3200	IN	A	10.4.4.3
cns1.example.com.	3200	IN	RRSIG	A 7 3 3200 20140430073146 20130420073221 8562 example.com. nHgVoPJNT2QEjjY0+zfbNxotkO5+MNyDIKUOS2uyP4jEKMgHwLEDa+9YmhPh5wJe+MFe/6oQDUDdGK/5yU7t5qol5VijKYGnokBXl9ZkvNqpLrK9wMBto0QEKI9B2S/rN/iMjgrlwBWdskDLmNEbMyx9e3yZI8yPDFCLAO0ZujU=
rdkf8d33qe24o2v2q21na3lbk3oaakcu.example.com.	3600	IN	NSEC3	1 0 10 05d67bb3fe7bf907  vcfnvpc2eqaspricadp3cigdgm8ujef8 A RRSIG 
rdkf8d33qe24o2v2q21na3lbk3oaakcu.example.com.	3600	IN	RRSIG	NSEC3 7 3 3600 20140430073146 20130420073221 8562 example.com. sOkawNigRaRdp/szyxvGXhzcLv4Ut5WNENC4OR2c6nXgN/Ht8YYySCTnTXQlaY4VOc8AmhRa3H0dT8QVBKIovM3PwiQC8OIfHcZuGvR2CaI+nnVo65DRP0bOZfnKSEL+rwQWqvQ7TqcPNA9PlImKFTpdUTcbz4h0js4nqVAv0Ss=
cns2.example.com.	3200	IN	A	10.5.4.3
cns2.example.com.	3200	IN	RRSIG	A 7 3 3200 20140430073146 20130420073221 8562 example.com. kgbxwn2g42wGNhmxOtzAO23/dtMhKyIVn8HnhNiCQZAYI/9mXZWOgN/181iwgnoEwQl/IFUndeY+xcktlv2ZHGQSf7U8ReXctL2MInWdcE20G8We9XhK11zLCP1aeOirRqmZH8QBwqnj4Z8bF1d06Vy20F88JXEEJxD7QM3zxsk=
i2ferdohnjamei8n3rpmbv4lf5pt4ubg.example.com.	3600	IN	NSEC3	1 0 10 05d67bb3fe7bf907  i887uaqoprdnmesu0ughr7sheqaug3h1 A RRSIG 
i2ferdohnjamei8n3rpmbv4lf5pt4ubg.example.com.	3600	IN	RRSIG	NSEC3 7 3 3600 20140430073146 20130420073221 8562 example.com. lgtcICR7bGpiOf1Prt2rdVw7txxwPVhAhwDbr1Z7ScKjjdgjlIcppmciWZRFLBCZ7kn0FGSNjbiPnjDdtMzd52BcB4B9a6/1djvXKGWHkXxfF/eOuwnpI8/ntzc6js9jWGoKmQCnh1k5Wg2ED9+KGqscdTadTE3vN7yXSHadvu0=
delegated.example.com.	3200	IN	NS	ns1.example.org.
1iohp8j7vsr7h24al82qi9b0n3m7o2jt.example.com.	3600	IN	NSEC3	1 0 10 05d67bb3fe7bf907  55quulbf2cj6nvm5odj6rmmer1985s95 NS 
1iohp8j7vsr7h24al82qi9b0n3m7o2jt.example.com.	3600	IN	RRSIG	NSEC3 7 3 3600 20140430073146 20130420073221 8562 example.com. H3z+RgDsNLzrPsGVbMMUHjgEoHUFkg4jQRsjIqZKkwFvCqqp8mjAXKJ+b53G00veOIR31JymPtM+TZzfhPVjU7JfF7FxRRxjMBLd03pPyG806N9dZ8Uz1VN7F/4lyZpV4crWXIdFoa+6u5GsvDWKioCOUc/03Lmq5Zg7bIDd6ss=
delegation2.example.com.	3200	IN	A	10.2.3.4
delegation2.example.com.	3200	IN	NS	ns1.delegation2.example.com.
55quulbf2cj6nvm5odj6rmmer1985s95.example.com.	3600	IN	NSEC3	1 0 10 05d67bb3fe7bf907  61fcihg3gtvgh50kcnm0k3nlprqhvk0j NS 
55quulbf2cj6nvm5odj6rmmer1985s95.example.com.	3600	IN	RRSIG	NSEC3 7 3 3600 20140430073146 20130420073221 8562 example.com. Mjf+gnJG1QBng2oSJO2ADuw+cQPC1qNyfwPbno76sQ+1xkKQtbqgjsEq0bWiqRh/q7P1TD+AxDVyOh4kJ4F/Pg4HcG0IAM15wabJH+Spdj+LYYXWc9CK2lYvDHxBx0EEtWWzq2jAVa8JBqDMY+3ctlPdA12J3npZUpBeo1vml9c=
ns1.delegation2.example.com.	3200	IN	A	10.34.12.34
a6t3254d1semge7fq420mfvqjkg7bgtf.example.com.	3600	IN	NSEC3	1 0 10 05d67bb3fe7bf907  d34nh4783sq7etvv6s4u35hn2dar42v4
a6t3254d1semge7fq420mfvqjkg7bgtf.example.com.	3600	IN	RRSIG	NSEC3 7 3 3600 20140430073146 20130420073221 8562 example.com. mHP2n47Jw7/9quLetXOc/FQU1qISYz4mOHYiWyKl6c7/cWY5mh6Ki5IINh/EtXXrMpei/gwxcumuIPZCxnEoCSY6ZcNK5lvZ3/8b7icu7mRwvHUDQ4KUXqxxyVx20F6iZ1+1mriB0kABFfvhBl8swQQicUTDUxTMAyjEBlQv4RE=
djikj02ef37hp4d50jij9v3g79u5aee5.example.com.	3600	IN	NSEC3	1 0 10 05d67bb3fe7bf907  fiqcf70a6339k96ef2scbk4vkmm0p1j8
djikj02ef37hp4d50jij9v3g79u5aee5.example.com.	3600	IN	RRSIG	NSEC3 7 3 3600 20140430073146 20130420073221 8562 example.com. fdwL1gsyNaPW93jnsbog7OFZwWdo5wY+ycAesc43XmBUDaYDZeuN/Mf/h44On4maB5h1+H4xAsj0TOCjHrlV5XGB4m7unL+hQN0WaEaA0Rofa4xJ7HDQId20N/NIgyvBA/oGuEcoiQdinJkrPt7fOrmfmEulmRGSGj/wJJ3berg=
empty.non.terminal.example.com.	3200	IN	A	10.1.2.4
empty.non.terminal.example.com.	3200	IN	RRSIG	A 7 5 3200 20140430073146 20130420073221 8562 example.com. f8E9ixD2NHHmTSVBrhPqL0gw9CjK+3rSI3xkM/8jSzXbjys8jMcsizdp2HBV3T125jPkqCYGQ7SkVsoUgdF7T3f8Lb+fLtO4sXKsf/2uRNEoU7ggtnWT83ghBynUrBCVS96tRMM+0eNzNSYc5Odw3u0qnm4EN8IWDT/ngUxNdM0=
n5cr9nt1bf55rgf5rirpoc8dh48bdm1r.example.com.	3600	IN	NSEC3	1 0 10 05d67bb3fe7bf907  q4s8hrhd7c8s824nkql0a52ng50mhtut A RRSIG 
n5cr9nt1bf55rgf5rirpoc8dh48bdm1r.example.com.	3600	IN	RRSIG	NSEC3 7 3 3600 20140430073146 20130420073221 8562 example.com. uDLckE2yY8i/M1PLt5kJgQD3d23Qump3TuMp4rMxLou0KFqc29ZdpLUs3zSwioTwiMYVMXL7eVgoZQcRyIf4S7ucLxcWO61R/U9mBlAtMcG0K4183Be77AqduHeoxYVyRNplZ+W0nutswhrvAjJLYKNYUJAWVNRhZ6Bhw7MIAJY=
test.example.com.	3200	IN	TXT	"aaa"
test.example.com.	3200	IN	TXT	"bbb"
test.example.com.	3200	IN	RRSIG	TXT 7 3 3200 20140430073146 20130420073221 8562 example.com. Dy8KPiKWzt7aMrOxB4LmfFDM+S2GhU8CM2oiyoe3oKUjf4rPVLvMV5FCyodFM47OiOYcp4CgVFg8hdNdMO/rIT1AZWESPwM34BIU9hVT2nUwA3kuLlWsiv54hUWr1UbdlQXXYUetrEtpf+vOiOAF93xgY+GOAwvB8DC74TLXHjo=
test.example.com.	3200	IN	DNAME	example.org.
test.example.com.	3200	IN	RRSIG	DNAME 7 3 3200 20140430073146 20130420073221 8562 example.com. LbsI0p8R9F0ZF7pzqVtDQoMRm9pfBVWB4dINNV4iD22PSR0jjoIQEWZWp/1+FeaXC83DhsELo7RVXBF7JtnYAguSf0XQlSWCKqVYojWMA69aKml/3NPn+GyY6FTk82NHgLYuHpLOVnQ7mqRMp9Q0LUiyySx+FVyNoJTA7V4YBfM=
iu0ms05m0tb8if6q0hsa6pnppi75ap3g.example.com.	3600	IN	NSEC3	1 0 10 05d67bb3fe7bf907  n5cr9nt1bf55rgf5rirpoc8dh48bdm1r TXT DNAME RRSIG 
iu0ms05m0tb8if6q0hsa6pnppi75ap3g.example.com.	3600	IN	RRSIG	NSEC3 7 3 3600 20140430073146 20130420073221 8562 example.com. EHA9BzYGOf7Ymm2Fq28H3QGqOW2BQIWD3AsfGIxo4w3AaSfSGGCk9FzIAmjyxda3GJ7qFqVh6M8MUwkKxp92TcjhILmhnCamFurzadJAMnV8OpLp0hkLNSyOiioEkbBjr+DbRxDybTOKIJjpyzpf+S0WPgjChY1z58FIZL3NcHI=
uppercase.example.com.	3200	IN	CNAME	UPPERCASE.EXAMPLE.ORG.
uppercase.example.com.	3200	IN	RRSIG	CNAME 7 3 3200 20140430073146 20130420073221 8562 example.com. MtDX2FtrmknWhg/krYhI3JAvgh/bE+t4x86n3x7pJXgw8kQHxxd7IuqzswLoku/koQBOFMeurMH7aPEii8LcgQML2KW8cwwjWKoDYIKI5SvMdQf71lbMwVdvlm0sr5PLehCeFOE6DYoz0pN8ivdowGlJMhr382W1rAMf+VW7ZEI=
61fcihg3gtvgh50kcnm0k3nlprqhvk0j.example.com.	3600	IN	NSEC3	1 0 10 05d67bb3fe7bf907  6nvejcs9vh19cvlaipno1p94s20t3eu3 CNAME RRSIG 
61fcihg3gtvgh50kcnm0k3nlprqhvk0j.example.com.	3600	IN	RRSIG	NSEC3 7 3 3600 20140430073146 20130420073221 8562 example.com. OlPx0X50jev5b5eKFXOxP+oHMM+bPmdBwxjWq79U3UyIvi9q99xXoPdOQKsWk97ZgyrY6vHuiFYg7N5uoA4JMfk2D6bUc1Z/kYtDPsSOEjr+kYI6MzT8Pkt/UjwEWbTJs2nSYOL78u4Q9KVqCdkamSPs6xEiMqRvljb2VJYIRH0=
www.example.com.	3200	IN	A	10.1.2.3
www.example.com.	3200	IN	A	10.1.2.4
www.example.com.	3200	IN	A	10.1.2.5
www.example.com.	3200	IN	RRSIG	A 7 3 3200 20140430073146 20130420073221 8562 example.com. C/eU9vGUT0y1ClreXtvfa6qi4lqktiKcUAwC0lIL8oeK9ZkOJ6+f0fJisq7+5s3WaIyNcEpi6JPCVN24LsulLXKMeUNZnY5KqB/b3SLt7glhnJcWKWp7pCRJSIwGjbr2ICJQg6gBRrIe8zRhgwLuB0Fv7fixdB9qDyuaNWszTGY=
d34nh4783sq7etvv6s4u35hn2dar42v4.example.com.	3600	IN	NSEC3	1 0 10 05d67bb3fe7bf907  djikj02ef37hp4d50jij9v3g79u5aee5 A RRSIG 
d34nh4783sq7etvv6s4u35hn2dar42v4.example.com.	3600	IN	RRSIG	NSEC3 7 3 3600 20140430073146 20130420073221 8562 example.com. XrehHRPhhQhC7+8MWGbleEeEu+BuIgYL7V/VPwQtihz49PFxX52ScmK064ch/VScy4nnupM8jDe58c3Gne7gpPERt0n/SbyhLKxPWIoTch2Z43J77yN4PTm6GELgAYpcgr48Xq3J6RUM8k294G8a8pA74B8WTuDq4V3jBZKoNN8=
z.example.com.	3200	IN	A	10.1.2.4
z.example.com.	3200	IN	RRSIG	A 7 3 3200 20140430073146 20130420073221 8562 example.com. mdGMPNXPUQ1vvXDpozs/BV3oRMfB0m02ad3CQHHSDc01xbwLPLNc/C04QH/hNEwa7bGhQQ2vnbrGgDjm5AA2bP/iSt9Edku62LrcNMMx2dkg3XQOpp5b7MsaNwxs+DnbQ83hbSTDD0GRV+Clj1DTfZX37nAZIKMXJtzn5T7aa5o=
6nvejcs9vh19cvlaipno1p94s20t3eu3.example.com.	3600	IN	NSEC3	1 0 10 05d67bb3fe7bf907  6r1v3vosorqt80kb3ailjib5a7n3cnlk A RRSIG 
6nvejcs9vh19cvlaipno1p94s20t3eu3.example.com.	3600	IN	RRSIG	NSEC3 7 3 3600 20140430073146 20130420073221 8562 example.com. flU9WQievMlOVMd19HzryetUEcVHvPLl9InH0m35yc/TODp6jkw3W18r7gWMD0LQ4OGa76Q4872uXtwW/40QhoDtWmx3eV6E2tJfFlutHrs92/cRQugL84qaBhui8rx4zkbCJ8TFBJeqRRQLPgflnkgoNchjLI0mIdKhrpmxMoU=
"""
# }}}

# Zone signed using single RSASHA256 KSK key (NSEC3) {{{
zone_rsasha256_txt = """
$ORIGIN example.com.
example.com.    3600    IN  SOA cns1.example.com. hostmaster.example.com. 2013042903 3600 1800 1209600 3600
example.com.    3600    IN  RRSIG   SOA 8 2 3600 20140430073146 20130420073221 8564 example.com. GndSN/VPy5aFMWP+BqS80Z189CCXs/iOeYvO++6g6xOKrFhvEylpzsWys6QUBxLxfzSIfxohdW0kiPnYwcufHAjNgzWzpwJ7OnZ38TD+h1iCFVhXkSyYMmDCupF4D2KFLbPuXxRNPhnVYLE8TiBdOS+JnBQc7jBEpCH1vS/rIEk=
example.com.    3200    IN  A   10.128.128.10
example.com.    3200    IN  RRSIG   A 8 2 3200 20140430073146 20130420073221 8564 example.com. WN4YX5P55te4YznhNMsETvoaRh4i9F50UXLXTLGgbcDRcYpdAf4Hmag5Fusj1KUhjFHhFEvzACWSIbzKpgAVUq1MxILUwyfMITE3vHkD4qhmGKB5rLKrDb4UrRxovffZuUA68u9VtRDqeEn8+0kj+/TB+ECp5cTVPKS9qj5xQLQ=
example.com.    3600    IN  NS  cns1.example.com.
example.com.    3600    IN  NS  cns2.example.com.
example.com.    3600    IN  RRSIG   NS 8 2 3600 20140430073146 20130420073221 8564 example.com. L4ySah/a9FVEmpHjdzwRIaM6VDF/RqgVegbtNkXjHRtLEIYuPtwByhyoppVyl/kjRmoyeYr4/Tj8smwUVSneHeN9+lld5cthBmlYsmxZFJ531mB/I1zUwkicP8ugw3xSWqC4k5SewhlRXeN1FIy0QEzgR5zn5u0jHOx6cvG2+w0=
example.com.    3200    IN  MX  10 mx1.example.org.
example.com.    3200    IN  MX  20 mx2.example.org.
example.com.    3200    IN  RRSIG   MX 8 2 3200 20140430073146 20130420073221 8564 example.com. FSInoDtGYHep52IjhtlDCHp4Ub2u0zmCCTc7mOPjtHym3SkBm/HlARykJyVj6CN5JRSCrVXNxZHDsMbxCYk7XBrAFEZcVSugIJuK8tdeGWGQgzs+HdcdydT9U3Pw0IV5OX08Zgef0yp3LpMN9wfKTo147o44vvnmVUL7N5jPjuM=
example.com.    3200    IN  AAAA    fc00::fc00
example.com.    3200    IN  RRSIG   AAAA 8 2 3200 20140430073146 20130420073221 8564 example.com. a1TzA47OIRFBBwyFRi33j085QndbSToImB+AD+y0nj4unfOXU9nF0wj2G3w7ABxx+JTf2hGGSXLPcXlOVqNVeBHTNZmUjs0ejdBl/Q6p2FJ66YYzWItHMORpR7hF8jl+xrO/w3NAe7E2Pwhjqz/N6V0NFAMXdMZfpQo4sZ5SqtA=
example.com.    3600    IN  DNSKEY  257 3 8 AwEAAbwPwkos3jZeAODOzW6AE0qf2ezpSEK6x7VAU2gMVTWAjN9IlkQAmxcNfBBFy9ny4o/8kZTTWyw7pyALzNx9jxhrnwiIdoWR/7N0Qq1Ia/CWfszWjlXvzDEwwkM/Qs41/8evCEShJBuk17wMJKmuHkAPoEgUcN4v0tnB892Aeq0v ;{id = 8564 (ksk), size = 1024b}
example.com.    3600    IN  RRSIG   DNSKEY 8 2 3600 20140430073146 20130420073221 8564 example.com. prfzEAXyF17efx4vIfbTcP5OrTtFiEXxhzoW2bhFjs/UNdJi/SRGSg9mUGDePq0l93cnaYMvkO+FEi3cc3Tqh4g6AGayhmeU/GSWsmU1+oP+fnBroOdtxseci9hxY4bTh4cBl77pMzveJzNvORK3/cMLP+OR4kPOcZna45KFKIc=
example.com.    3600    IN  NSEC3PARAM  1 0 10 05d67bb3fe7bf907 
example.com.    3600    IN  RRSIG   NSEC3PARAM 8 2 3600 20140430073146 20130420073221 8564 example.com. O87LxHwEHDUB47XYUAptCz64LT5w8mhjkBvl+/CK0n16ADbvHStcYvUcw56GgNyJeIPUtYjcMkWR0xOnM15nCtNaLChVPjQY2folhL9VGMlgbWeidVlQflKsH7nVedn4vQmczVGF1lcLgm3BShmkmV4PdoUOvM27vOvDhqtk0OY=
6r1v3vosorqt80kb3ailjib5a7n3cnlk.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  884sems3cdr70nhc4d9qhno9a449gslj A NS SOA MX AAAA RRSIG DNSKEY NSEC3PARAM 
6r1v3vosorqt80kb3ailjib5a7n3cnlk.example.com.   3600    IN  RRSIG   NSEC3 8 3 3600 20140430073146 20130420073221 8564 example.com. TOtdxCtKPVsR7XSZZB3M0qS0gcQcti/ztwuzvMib1u1c+W+UV584BjzUVaRVTxxZccqOD4qYhFIGUXHq94HCaweIyeakZXbR/xGPf98GL0CVP45Fg7YgpShT0KyZ5GvZRLJS0avYdNQiA1sAyv0pl/DXiRvI5MJdkDM2WrFMhks=
*.example.com.  3200    IN  A   10.1.2.4
*.example.com.  3200    IN  RRSIG   A 8 2 3200 20140430073146 20130420073221 8564 example.com. IHNayH6vTpJ2Bb7xcVLhrNUxFPG8F25QcWYYP9mxwwvcGXU/uK6ha7Cf3H/nwlDevo4UMcTiFZq51U+nt5kJHnagUY8Y5zSWFh8ibOmVH4FQkrp9C/VQ5PNYbAXazxeOnZOo8VLAQbxyfufRbNcf6u4MqeOerAkSsUGgecxGGHw=
fiqcf70a6339k96ef2scbk4vkmm0p1j8.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  i2ferdohnjamei8n3rpmbv4lf5pt4ubg A RRSIG 
fiqcf70a6339k96ef2scbk4vkmm0p1j8.example.com.   3600    IN  RRSIG   NSEC3 8 3 3600 20140430073146 20130420073221 8564 example.com. kLgcl+Ip7CEiJsHJIvegkqm2kP2IxvBiBPqwbhF4/+nnPkV7O4oXwoWFHD1Sxg47SPPJEHQq8lnuATGZGckZfRq3bWZAw8V62ffhE8hjXbhybG/F7n8a9/peBdn9f6z4Qhqzntl1fy6eWZ7JgERy+Q3t3SO2a84gm/gQDowqyXM=
q4s8hrhd7c8s824nkql0a52ng50mhtut.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  rdkf8d33qe24o2v2q21na3lbk3oaakcu
q4s8hrhd7c8s824nkql0a52ng50mhtut.example.com.   3600    IN  RRSIG   NSEC3 8 3 3600 20140430073146 20130420073221 8564 example.com. fxduC86nX6ByTE+tJs4qQs7hRyT+K5obQ9vHq21PQ3kHEfQ7hNCnSGmlAHunoam1hLv0pzngGKbUXZt2YS82UPp/K6lmL89EgIhUd32muLiD+tC2ugda+NbuQB1Gk0W3VKn6CxlKxOYjHC3Ub6P+2KcS92V0DP4+qZ0HsYkbTAA=
_sip._tcp.example.com.  3200    IN  SRV 0 5 5060 sipserver.example.org.
_sip._tcp.example.com.  3200    IN  RRSIG   SRV 8 4 3200 20140430073146 20130420073221 8564 example.com. CLJP+rkrfBlPGjOMgiVGZQYwhebzRdIdrMRvbMdDbACyxC4lUnlUEkxttqAPdQHVDbnU8gkb5Rwqi+7AV4GytRJ8xSZCMFHkK8FrKtgiTCsUADmxWJsuSXXciAJ8a6WZcHJKQc+B2I1MGrb59w+5lSlXREAkUiOBPA6jeWix9Io=
vju5kq0s3pj4fig4aev90i6m30m4ccsk.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  1iohp8j7vsr7h24al82qi9b0n3m7o2jt SRV RRSIG 
vju5kq0s3pj4fig4aev90i6m30m4ccsk.example.com.   3600    IN  RRSIG   NSEC3 8 3 3600 20140430073146 20130420073221 8564 example.com. Eb91ls/PsfkdzRuwRiI5dtnsUrXOWCYhS7EJkytem/X3RqCJOo1OU5I+wsevcaGNriePIsVbX2HZ2saMFX7cxXvcL1mqVhxxZ8ieag4u+4E4+FxwzdJ8T3OleeIfQbfrePCDkD6pK5wwQ5VqwAoN4OFTd0bKqd44BDyJWqfOyYI=
a.example.com.  3200    IN  A   10.1.2.4
a.example.com.  3200    IN  RRSIG   A 8 3 3200 20140430073146 20130420073221 8564 example.com. FZucGPH871UqnrrLjuIN1B1TDXLDksJ3kuCtfG6am3YUGraD9V44JmZqiiJzf89Xq+B4DzxDhZsKBv+6cF2HE4GQPLy1/6gHaPuiVwF6JECgpXiIuVkTPffZhvY51FxS4Q3e2lU9ZoIfjSXdzm4veDNfApBa8VOs+OwjXWBg41w=
9kpaurblh2ncekbdnnuml8o6tegktpve.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  a6t3254d1semge7fq420mfvqjkg7bgtf A RRSIG 
9kpaurblh2ncekbdnnuml8o6tegktpve.example.com.   3600    IN  RRSIG   NSEC3 8 3 3600 20140430073146 20130420073221 8564 example.com. HXl1/2bbgwYU6lebCX44kWnZQKujAkw+X9/FvO0r5Qj49WjNt+RlI8e/fe9tBli4yqUqG4kl7O2VZ+brPgEabutIl29fuRrD3OATjspvW3e9nkAaKYwjVFdMNklWk+d3Oo+0Ly8Vk6Tw2wutXjIO21/HWbH3VOnL0Ajr29qD5C8=
yljkjljk.a.example.com. 3200    IN  A   10.1.2.4
yljkjljk.a.example.com. 3200    IN  RRSIG   A 8 4 3200 20140430073146 20130420073221 8564 example.com. Kw1iNo1t98n1KM93AO+giwSz6U5CLe5uc+xKPQg3fqHMO9KyPTkVxGRh1jqKE5/KncW09PrU1oojWwAkaSL8CwBpRr3DsYrPHH6MyymCw7gqFlCbGJIQHKbWm2k4hDRb+ufMLMYuO2DHFPZDiimANfgMR2p4YZzql5XKn16WCt0=
vcfnvpc2eqaspricadp3cigdgm8ujef8.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  vju5kq0s3pj4fig4aev90i6m30m4ccsk A RRSIG 
vcfnvpc2eqaspricadp3cigdgm8ujef8.example.com.   3600    IN  RRSIG   NSEC3 8 3 3600 20140430073146 20130420073221 8564 example.com. qpuUmd1T+48JvyBh0ABmzESPU1YctHGdxq8oM6EySrW6REFGVIADPjb6T9vL70KBevjDCMwv1LXbHfno/H3cotBH6NDFAWayvZwkL01yjz3wzFc7vGiadtjSgBq+UtZBE0XUM9ZgCK6YiyxxfThqRdsdBz4ejtN4ntP/fdwIZzo=
Z.a.example.com.    3200    IN  A   10.1.2.4
z.a.example.com.    3200    IN  RRSIG   A 8 4 3200 20140430073146 20130420073221 8564 example.com. OJdQo5GXaLiQttmL2P9rsykrjWf5pVwPfQFSWpioCusYsfRASvrwjyEPByXdgunRiAK+uJoOh+Ja2GMGRd6KsG5w/02tUex/gx+TeyiWRDoTlawcoRVtYoQnNBRiLiXRyOwRwb8mhNB1KWHm6ire8HuUd8P8G9gnMO9aiAl7V9w=
884sems3cdr70nhc4d9qhno9a449gslj.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  9kpaurblh2ncekbdnnuml8o6tegktpve A RRSIG 
884sems3cdr70nhc4d9qhno9a449gslj.example.com.   3600    IN  RRSIG   NSEC3 8 3 3600 20140430073146 20130420073221 8564 example.com. Di9bN7pXchhtKS72eNTF/DyMVyb/obidj4mb1TR9c4oKV5rhVZSXLtR9oxScKx809heZny2JIYhw9ZObPTtKebS84IVp5QNJcuZ8P5RhzhZXS48CYxJVj8Q57MdYGR96sA7Kl+OYxUQRZoLrY8OlYLx5xDrbsD19UkP72YF1dw4=
zABC.a.example.com. 3200    IN  A   10.1.2.4
zabc.a.example.com. 3200    IN  RRSIG   A 8 4 3200 20140430073146 20130420073221 8564 example.com. TUgYAUrO6oOoaKOSf+ILEf0l0s7/pNsC7Il3K+5xZj4BPI+yoz6GjB9ciOZejr/jPXQ4uS6D53Nip9CSWLjkry8x0rcG90/yqPqPMOEUIehG4qOC8U6AVFvMkQ6ybXRnom7GhOi8eov8bCKrY7dbO1UJQSyngVBH+Md2Mqk0+j8=
i887uaqoprdnmesu0ughr7sheqaug3h1.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  iu0ms05m0tb8if6q0hsa6pnppi75ap3g A RRSIG 
i887uaqoprdnmesu0ughr7sheqaug3h1.example.com.   3600    IN  RRSIG   NSEC3 8 3 3600 20140430073146 20130420073221 8564 example.com. n1LkmG+9Q/bExeU3oNlyr45ZKAjM16qIUtbIZ8AVQMtRQfRGcez/OZRoeLBnv+w++bjZebmL3FKbY80lxpBtQDgfWg2GZhBoJpqedpNq9iJbvVoDpnj4soaUbsQ+WZl/RxiYI5X0mHmDCpSFOSWDb663uGWn1oy/x6crVfQ79BQ=
cns1.example.com.   3200    IN  A   10.4.4.3
cns1.example.com.   3200    IN  RRSIG   A 8 3 3200 20140430073146 20130420073221 8564 example.com. S6PdVFDcGCguN63uXH0KVBLa5NPi1o1CyuvfAVwoFyXY0kcBYITJYWVR7FulDZixk5vm/jHUYkV+5gfqaFug1t/vbz5NUWwb9NFcSvjuVK1Nhkkhw7j+KkfcSOsZ/VNhT+T423Eb+7pAi076HOVPertyzf7uof7iMH3vdWCnzBg=
rdkf8d33qe24o2v2q21na3lbk3oaakcu.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  vcfnvpc2eqaspricadp3cigdgm8ujef8 A RRSIG 
rdkf8d33qe24o2v2q21na3lbk3oaakcu.example.com.   3600    IN  RRSIG   NSEC3 8 3 3600 20140430073146 20130420073221 8564 example.com. HcM4IPlN/5nHnAjaWorWs7nPOmIEn5IyrVsmL2NSRO2rSu+jKRKulU/lQ3ysOTPnDAuVOCK06UryhCVqVIwoM590taGZVBqkE+pGJ/IdtlJGN1/Gl0nG3cwId5mW2fjKgE2f3ByJ5yJNzOegyEWfH6E4jjplq0bI3m3rD/f1K7U=
cns2.example.com.   3200    IN  A   10.5.4.3
cns2.example.com.   3200    IN  RRSIG   A 8 3 3200 20140430073146 20130420073221 8564 example.com. sKQ11zDjTzznGfn9OMuAm1vlv7AoXTuDFlRyOUJ9hj3lDCSVGq+Py0pydzd9HTqwrjuz8ai/WZI+ObqNT4Bxp7XNxXkmNOfNCYe+gKgK0zZLrXe85qPv09WXYDRNpMV1EktjQvC2RCCQaN0FZRA8q1VSbqKdhI/JLHtQ+9MZtP0=
i2ferdohnjamei8n3rpmbv4lf5pt4ubg.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  i887uaqoprdnmesu0ughr7sheqaug3h1 A RRSIG 
i2ferdohnjamei8n3rpmbv4lf5pt4ubg.example.com.   3600    IN  RRSIG   NSEC3 8 3 3600 20140430073146 20130420073221 8564 example.com. QhCGhYimbQ7eb9zy2BQ+58ftLl0/h/lO0juNunXV0QrxVIaw6cfv85Olz4jb2IB1O9Lci/EfvE54qh6Rj3mF0Z35LUlHnxCXu1AItUBAabFu5Utm04uCoC1aQ8biyO/1iM2Yh3hxFHGC0XBb1WDeo2QbZ7ndbVt3i85WGW3Je8A=
delegated.example.com.  3200    IN  NS  ns1.example.org.
1iohp8j7vsr7h24al82qi9b0n3m7o2jt.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  55quulbf2cj6nvm5odj6rmmer1985s95 NS 
1iohp8j7vsr7h24al82qi9b0n3m7o2jt.example.com.   3600    IN  RRSIG   NSEC3 8 3 3600 20140430073146 20130420073221 8564 example.com. GBAvU6pQmMHSUh2J2DSoyjCDBfG9RDedTGPAdPlix+O9YapED+An/X2EECFwidzcNPRcWdtum7QqKtCYo6pY6m4/CUdx31Ov2pYToUzcCENMBmjg6JB0Yex7g3HzQe3/1703m68tIw4jFGtXKwf+CJNyh9UXkl4NWNjnrwKgyx8=
delegation2.example.com.    3200    IN  A   10.2.3.4
delegation2.example.com.    3200    IN  NS  ns1.delegation2.example.com.
55quulbf2cj6nvm5odj6rmmer1985s95.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  61fcihg3gtvgh50kcnm0k3nlprqhvk0j NS 
55quulbf2cj6nvm5odj6rmmer1985s95.example.com.   3600    IN  RRSIG   NSEC3 8 3 3600 20140430073146 20130420073221 8564 example.com. BXTs81I7hqeeM3o1wQnzWTWZrAh2+ZojA4ViRj2aNO5oerbJsHD461NaIinWvnGMKsKQSaeqPrj9r9czkLECdee1GrbrIUQmMVNgu+OdjSrGJvU7192yLFUS8JsfnT0VVzgLLtXo/p0JMQxVcgl+U9jfs3gMO8j7mVtDVG9c+KQ=
ns1.delegation2.example.com.    3200    IN  A   10.34.12.34
a6t3254d1semge7fq420mfvqjkg7bgtf.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  d34nh4783sq7etvv6s4u35hn2dar42v4
a6t3254d1semge7fq420mfvqjkg7bgtf.example.com.   3600    IN  RRSIG   NSEC3 8 3 3600 20140430073146 20130420073221 8564 example.com. Ak91jgPJBGKgb/v1lXyP/ze0w7Et+1ZrFI6mlOSeOBQCNE0vWYYIAD4o4ClzVX8L1RusgMrlYkPVLVd5dkKeEEFafCII9FGC3fFZ9LmCKQKjFMnP3Pqs+BwStIutNP9RKfUdkRqI++UF5cD+XkEshjtHOBlyU97rI82NqfxW7bs=
djikj02ef37hp4d50jij9v3g79u5aee5.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  fiqcf70a6339k96ef2scbk4vkmm0p1j8
djikj02ef37hp4d50jij9v3g79u5aee5.example.com.   3600    IN  RRSIG   NSEC3 8 3 3600 20140430073146 20130420073221 8564 example.com. hoPY2H9jfBWHEb9vv3JO49oefGI4ri8BuicA6LYlXRHn3Hp3EMLXu0V3ssyI47rMvszPC3+7k1sqQh+xC45028LUQMNEKPtBN2w7tm6zt7HYmgdoyyXdIQKzHbXDvqjtnSylT/dIemeyKFZUAGxKU6PGGx1cZH0XwioVDt8mVeY=
empty.non.terminal.example.com. 3200    IN  A   10.1.2.4
empty.non.terminal.example.com. 3200    IN  RRSIG   A 8 5 3200 20140430073146 20130420073221 8564 example.com. EM8QLPUFBi37LnwblaDd0mxfCcbEqmMFDBmAI+IoOQNsWUk2KO1xr02ERBUwn4JOQu/fhceia8sVAJyB6AX1kb5dZfda+a8/UZe3fj1AHp7SQ+3FAQsJ9efG1qDRmR5iuzSH+kAtZVU/+oVVWY1pYVDvq8/J0kqV16+N+nAhkuI=
n5cr9nt1bf55rgf5rirpoc8dh48bdm1r.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  q4s8hrhd7c8s824nkql0a52ng50mhtut A RRSIG 
n5cr9nt1bf55rgf5rirpoc8dh48bdm1r.example.com.   3600    IN  RRSIG   NSEC3 8 3 3600 20140430073146 20130420073221 8564 example.com. b/3hLGFnvH4O11a1vP6C/kQta016slKpUc/R9S9wTvbttJ5YpxGbKGaTaH2oTmo3gWYx9SDiSbulGZ8+aDX04z5qczAPGQ4uVDPgVY/ltcTSHfIzlLCU8v+3TkhQfANCv2MdjL+JmeEXGFjyfATZYB3qcZD3EmSN7GfXCpRFirk=
test.example.com.   3200    IN  TXT "aaa"
test.example.com.   3200    IN  TXT "bbb"
test.example.com.   3200    IN  RRSIG   TXT 8 3 3200 20140430073146 20130420073221 8564 example.com. lYU/mtgH6O4/u38W+xpuyR6ePfePphmqQUzHGXYD5zPGbKF2ilUhoUkTeKwBpLLV8lcf0Ht/km/De4Jf66nUqc3j8ABAhvAm0RQvQi8q+NeW1AtILefQjyZJ3dmmRcHgAyXz3jCWzvcI0n/cxMwFaqhDy1nfzkSc8XKmecgsKjM=
test.example.com.   3200    IN  DNAME   example.org.
test.example.com.   3200    IN  RRSIG   DNAME 8 3 3200 20140430073146 20130420073221 8564 example.com. MjJmmpGeDxDIn2US0dBhNFibmyKDRnBrhNXCgsE3kQ+sF6H3FOt2In6kTKt/sQNutNLSCW6ULNbzTPU8K7OlCk/jq2Saw8Z1fCCotlanBVoXPya8CTt6uLkzJPq/olACIq/+YFJsmcZgu0ks2R/N6bQ0p3tbel+cylmPIrKbZAc=
iu0ms05m0tb8if6q0hsa6pnppi75ap3g.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  n5cr9nt1bf55rgf5rirpoc8dh48bdm1r TXT DNAME RRSIG 
iu0ms05m0tb8if6q0hsa6pnppi75ap3g.example.com.   3600    IN  RRSIG   NSEC3 8 3 3600 20140430073146 20130420073221 8564 example.com. k26VLkYxbJ4P7epDSYJEWOaYHLw+o9oPoTvMqF8mVMVTc8+kcESpxbfaujD7tqSX5A05Mt9GdOtbiwbGc9JImIJcsXABw2sCcuJx5VSmAowrIEigEBuDCgi5ChMacwp7CtUZonCST0g0etlhy1p72R2cr48MKEegyzDzvm6UOhY=
uppercase.example.com.  3200    IN  CNAME   UPPERCASE.EXAMPLE.ORG.
uppercase.example.com.  3200    IN  RRSIG   CNAME 8 3 3200 20140430073146 20130420073221 8564 example.com. rrxoYDH20/uFz0EuDmB3lja3GJK8DiGvAcQjRoQnChdglIgTiuRfE3hzNrhpC6YhVOfqnSFGdxSkHV/36WSYaq0h/pD/arEzO71bVSYnWDxyorlqTX4A/SLkYLV0GILHaFD8EfMJxj8qcrWf9nHPcJqVoNlNQma2g5V+kHLt2Dw=
61fcihg3gtvgh50kcnm0k3nlprqhvk0j.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  6nvejcs9vh19cvlaipno1p94s20t3eu3 CNAME RRSIG 
61fcihg3gtvgh50kcnm0k3nlprqhvk0j.example.com.   3600    IN  RRSIG   NSEC3 8 3 3600 20140430073146 20130420073221 8564 example.com. S9UCB7NgxbJkzSD8NNHBBjCbGrgTB/mOsoHpELlk0M4vT2vJExzao+YlGWohM6FDgcCyBx5pU4KO/Z1QqT67NsaGGhfGtPESC2ZarlZoVTWkQKTDbkqvz4IblGEgF1d+OjKWvyT8w8twc/wF4kz0AmsR6ghfq4Bav6S6uoPEe4g=
www.example.com.    3200    IN  A   10.1.2.3
www.example.com.    3200    IN  A   10.1.2.4
www.example.com.    3200    IN  A   10.1.2.5
www.example.com.    3200    IN  RRSIG   A 8 3 3200 20140430073146 20130420073221 8564 example.com. OebieGHqp9x3sE6Ls9VICuF2F4MIYLJf0oje8k2Lky51gPNfBlS9eGBllaeMGxFj2YzVoSMCJmEOFwOlcUd8BTt0ElmlSQsU3n1Z99ERIO1Er5V3v377u//EaqZt2tt+EUVKdO52W1BgpuMs8XB2mbyhDXDjnPYWy9WidxUp1a8=
d34nh4783sq7etvv6s4u35hn2dar42v4.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  djikj02ef37hp4d50jij9v3g79u5aee5 A RRSIG 
d34nh4783sq7etvv6s4u35hn2dar42v4.example.com.   3600    IN  RRSIG   NSEC3 8 3 3600 20140430073146 20130420073221 8564 example.com. WJodqUzAaSywAiONL7eJPxGoemnPTZ564zBHhel13e0uu3x2bY00ynVKTXpF7kOKtkodA6C/uVamWVLlH6vsS5y/GXev1YJKRCQMHhM0Qzyr9YOY51uWucWrlOR2FMvj3ACgjHbTz5hN9KC10N6dxSDlN0y81ZsKUvJUtsPcArc=
z.example.com.  3200    IN  A   10.1.2.4
z.example.com.  3200    IN  RRSIG   A 8 3 3200 20140430073146 20130420073221 8564 example.com. U3pJz1X8AbUPJmveszUorYMcks/FRyLC1vX0Jv9kHQqu9L4WNisZz7gLCi++9nd/bBMKNvUQsnvXfNd5HHNNBX6qyVgGfL1OVZ4qnFzE/zJww3+NwraYXc2G6J7aFTdzIKSB7isvd5IOqT35iGu+JrP5GYkXYyx/mrfcK7hfdFw=
6nvejcs9vh19cvlaipno1p94s20t3eu3.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  6r1v3vosorqt80kb3ailjib5a7n3cnlk A RRSIG 
6nvejcs9vh19cvlaipno1p94s20t3eu3.example.com.   3600    IN  RRSIG   NSEC3 8 3 3600 20140430073146 20130420073221 8564 example.com. kXqogOSesWxcjMySDu8KXohdiFMKB/dui2oiArH4gtix04sTudHOTWIjdp58zUFX6fZcVu3d/eGsNyzaKpAz2g2lFk5osnJgG1sWs/ukNaz4k65AozAt+gBbZGXQquBuo5UyrCwbYW/U9vdb34uBjnwMZa/hLzflEYU4Um97HrM=
"""
# }}}

# Zone signed using single RSASHA512 KSK key (NSEC3) {{{
zone_rsasha512_txt = """
$ORIGIN example.com.
example.com.    3600    IN  SOA cns1.example.com. hostmaster.example.com. 2013042903 3600 1800 1209600 3600
example.com.    3600    IN  RRSIG   SOA 10 2 3600 20140430073146 20130420073221 8566 example.com. Tjgd1g5iVvdfnJYFI5XSDQNiZCU9BG2hOLVzcdxgJMd7FGQVrv1XTJVO3SG5RulDVd5Vi6QRtM1kqkTIdAJ7w4Kjc3OiFX/jcMMCITtZdujmVlzZwrUOodDQqzq/obl3zgdaAWtvsPwdTamYWRY+eCZTsNFLbB+PS7r5M69rllg=
example.com.    3200    IN  A   10.128.128.10
example.com.    3200    IN  RRSIG   A 10 2 3200 20140430073146 20130420073221 8566 example.com. otmQoyRMQJnI1LK7lm0JD321yXt+/ZaCSTqPnvg7u5JG1sP5yf6EkpDowFs+xF4T5p+XigmcBs3N+WUXNRE0L62SuR46j8s29EOpiSnNJ+ay91W2zsrbp7JDDFATji4VAdzFPFsxaCNgMn0s/b1c3b78DidWdDUW0HVsDF1dNq8=
example.com.    3600    IN  NS  cns1.example.com.
example.com.    3600    IN  NS  cns2.example.com.
example.com.    3600    IN  RRSIG   NS 10 2 3600 20140430073146 20130420073221 8566 example.com. bt3vZghL93pn3LRHNj/vctghvfhed2LJK00HCCYtzKJHlQpDobY7z+tYrbGezftLcBhLAs72aEqcOv0vynnmmvPbdK3ksHcYZjFPDiXcgVxNB4h7xijx04DcY8T0cXa5A3Q0tcArS+mOAJMghsZCHVkvR5Gz1NI3OQeqYPjpQWw=
example.com.    3200    IN  MX  10 mx1.example.org.
example.com.    3200    IN  MX  20 mx2.example.org.
example.com.    3200    IN  RRSIG   MX 10 2 3200 20140430073146 20130420073221 8566 example.com. un8hqZMUAjo0NY4dCb7mreT2N7Ct/bULX1eAtlQ9ea6c7nhvskSrTbHEG5Rk4XctRj7dcDuP7bclwCrN9tcX/rv4rWYENfzCzBFWQZ1/fjxlaRIQ61u023K5XUsxBTJzeZD+nXCd0aMfNRBtALVeszqmbkZZ3NNxEYmr/Fw3l2o=
example.com.    3200    IN  AAAA    fc00::fc00
example.com.    3200    IN  RRSIG   AAAA 10 2 3200 20140430073146 20130420073221 8566 example.com. CID3p3qQqYRKY76pKKOXShSg7/NAllYIFm2Fq6NWZWURB6oandH7+FS4/xvtS31HzBkHgOclH0+HTcGkvgECnI8V0YUE+aKcuT8ipGRJCUli7T5USLVrXW8D3ZVgLm67CuL4bSOB/JXDrwbp4j0THk7JdPbXw11JdQD/nyOI31k=
example.com.    3600    IN  DNSKEY  257 3 10 AwEAAbwPwkos3jZeAODOzW6AE0qf2ezpSEK6x7VAU2gMVTWAjN9IlkQAmxcNfBBFy9ny4o/8kZTTWyw7pyALzNx9jxhrnwiIdoWR/7N0Qq1Ia/CWfszWjlXvzDEwwkM/Qs41/8evCEShJBuk17wMJKmuHkAPoEgUcN4v0tnB892Aeq0v ;{id = 8566 (ksk), size = 1024b}
example.com.    3600    IN  RRSIG   DNSKEY 10 2 3600 20140430073146 20130420073221 8566 example.com. Zwq526dg55Uc3UAa7AwA9oH98tS57+yn8FZKaaZoJ1g25sCAyx20gqRaOdmrBMydoKaWX+XWHXnE94VjnNHehpRTLRUxdG/xYanK/Uy81DEqtVpedzPYvCpz2lhG6rU/QZTQvQJ6DaQhmR2TcmwYjl2/uWIcrXoBbaJUTt3amuQ=
example.com.    3600    IN  NSEC3PARAM  1 0 10 05d67bb3fe7bf907 
example.com.    3600    IN  RRSIG   NSEC3PARAM 10 2 3600 20140430073146 20130420073221 8566 example.com. Iaj3Ch+0EzlFRC043eTIu1zSOcXsgindxteyOlSBOUxCJoWQneFoV88PQUCjdBKkc8qVWUzSgNiMzTuwCqFXbP920+uJoU6T/gOHAEYA9QLWEawhoSKuvhFwmVCkAIY5dt8oHYFTACxfN5edn8LhVc1sIt+r4MjroCa3AFpcuRA=
6r1v3vosorqt80kb3ailjib5a7n3cnlk.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  884sems3cdr70nhc4d9qhno9a449gslj A NS SOA MX AAAA RRSIG DNSKEY NSEC3PARAM 
6r1v3vosorqt80kb3ailjib5a7n3cnlk.example.com.   3600    IN  RRSIG   NSEC3 10 3 3600 20140430073146 20130420073221 8566 example.com. pc0WNTyduUB3ZjX5rubqp8+LlQ9sdVr/8r5JfN2y+21+q9X6a6wSHm0bpZdrk/MFVJ6dW2C9cnxGXuqoo1ZSjd41pa4K7ckmbcqAErUwLLB6fjjgWYvG4uepdW/t30euWyh6SulIPl6cfYUkN3e0EIuKtC6iLtouaCefPUmAPKI=
*.example.com.  3200    IN  A   10.1.2.4
*.example.com.  3200    IN  RRSIG   A 10 2 3200 20140430073146 20130420073221 8566 example.com. ETNNPE83k5PzdImm6N4Qe6qjxPMF3sLJtS+kFDr0DL+Q9hfiqcoM3hohpyuZhWYeyOYjFTrxJePs+rmYTMO5w2BdFpyrU6oDPCw/FjCGTnGkktDYLf4EG4vHtsD1yrdoZ1xPlZBirm8KKXy9RGyc/R0p4ca5Kb0i8xEOBGTGexY=
fiqcf70a6339k96ef2scbk4vkmm0p1j8.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  i2ferdohnjamei8n3rpmbv4lf5pt4ubg A RRSIG 
fiqcf70a6339k96ef2scbk4vkmm0p1j8.example.com.   3600    IN  RRSIG   NSEC3 10 3 3600 20140430073146 20130420073221 8566 example.com. QoGFPE/dKB63oS2Fz+Xcdxq1F3QzSxm4ApgvGJl0S8h6iCNBG6RAU11u6TPikaOaSIWkwpCLQFjBYPvBLObRY1cKvcWKTyNG6+UNcqNWujCPJA9Is4WLBOFqrU/A3tZ37cssB1wsQtQXK8/mDAp7PXHSLVUMBypwZB2DuVgpXec=
q4s8hrhd7c8s824nkql0a52ng50mhtut.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  rdkf8d33qe24o2v2q21na3lbk3oaakcu
q4s8hrhd7c8s824nkql0a52ng50mhtut.example.com.   3600    IN  RRSIG   NSEC3 10 3 3600 20140430073146 20130420073221 8566 example.com. EP8yNSgRmlvBcc+DHyVEPpv2Kd0LPyhI6UnHGHPgA2ghebqb/QmYP0J/KzWhVQEvnf7tq/V2jc4BgYurj2UuHaYMLRFRtudqfohJu32onHL5jsjxxPet99DpgMs9Zgl/Ln86UysN+BakL23emeAVuG3rff3dVrqGDroh/dUos98=
_sip._tcp.example.com.  3200    IN  SRV 0 5 5060 sipserver.example.org.
_sip._tcp.example.com.  3200    IN  RRSIG   SRV 10 4 3200 20140430073146 20130420073221 8566 example.com. fZJbBwVoVazyuzlhzqmGZIuarnd8k1Z3JYuEYCbNHuOkcLL86sMe5Oi7tFT3T1AnLws0NaAKy86QoH3QKJUeUVx2yCN/4CSsO48PlzGG+kTgTeV0BslTF9DaYLCatOjefitwJ57fSbF82oM5yDmsbc6dmqJC1VsIDgIKMFu9iIM=
vju5kq0s3pj4fig4aev90i6m30m4ccsk.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  1iohp8j7vsr7h24al82qi9b0n3m7o2jt SRV RRSIG 
vju5kq0s3pj4fig4aev90i6m30m4ccsk.example.com.   3600    IN  RRSIG   NSEC3 10 3 3600 20140430073146 20130420073221 8566 example.com. ayxND+yU9ptqrz8jnF9TmM2dydWbr6hqoyGwwfi53A+WYT+2A2/8lF/Q7/L8sww32M5/+ZoauplckhTNZYygWRH6fyHYqSkRidxrKJa8bhKYbwJMCwtDrb9h62io8frsvliWNWMtHXajO5ZR0ypJ8ABj2yh5yMqLXKaQTaVqRgw=
a.example.com.  3200    IN  A   10.1.2.4
a.example.com.  3200    IN  RRSIG   A 10 3 3200 20140430073146 20130420073221 8566 example.com. rmOht4gEoEfrbqLGNygR6H9wqQUcux0+s8lhe6CdDTr5lhaAedpPjtms9fjvU72ZG+eyLjqnmZEATrooiNn18OniiNTubMt3D9UssLzCT77zMKK2d6s1sWmOSvfnjxw8uljKz6PX7Ge8POjoKThbo00CnQQlVVcWZSTFnAmvkYE=
9kpaurblh2ncekbdnnuml8o6tegktpve.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  a6t3254d1semge7fq420mfvqjkg7bgtf A RRSIG 
9kpaurblh2ncekbdnnuml8o6tegktpve.example.com.   3600    IN  RRSIG   NSEC3 10 3 3600 20140430073146 20130420073221 8566 example.com. QYPaML0Rs2GigAqo8UVVFVZ0RNVvQ3d8iGddJmGq4nxCpcHvQ1gVIhUFMgeQS7kLzu/5WSAHZMIKM9AcO+GHZ6szmIHmJ/H1D4dok+RWHb069qiROrFkhm22rqBe17lheUDdHvcpSSDZdkHr5G6yRXLIu9lAkkFDHL5ZY699rDg=
yljkjljk.a.example.com. 3200    IN  A   10.1.2.4
yljkjljk.a.example.com. 3200    IN  RRSIG   A 10 4 3200 20140430073146 20130420073221 8566 example.com. DUJtFP6Rg3HVvXBHGuoXcEQtf93iqy1GQqISL+EJlt1pTQMBNOq6IFkjoQ6i8eDaZHYvzAB8QB9M1R0oLcsMUkJ2tFOKjC+69OE6H3QI8GVgaEvuOLJkUTHhGVdyXQarLmgzYhmQ41CA8j/67vCYSdIPTX5+8f0qlCvUNIiTlKw=
vcfnvpc2eqaspricadp3cigdgm8ujef8.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  vju5kq0s3pj4fig4aev90i6m30m4ccsk A RRSIG 
vcfnvpc2eqaspricadp3cigdgm8ujef8.example.com.   3600    IN  RRSIG   NSEC3 10 3 3600 20140430073146 20130420073221 8566 example.com. J3i9kqmo0J+rcIhEHileMtVvHRz9cYxjbduzuY1RcKDkUDl0d6DUcG6duKeFuN88ldiu6DRwH5ygviOWeFhxm3GNlGBK7sVDqIuaZrKDIKpKBIGkwQmw2e6kBCCcCS1zgpGzlBr3vtH19KsbotH4k2+tvxxG8FIo39r0VhMtOcw=
Z.a.example.com.    3200    IN  A   10.1.2.4
z.a.example.com.    3200    IN  RRSIG   A 10 4 3200 20140430073146 20130420073221 8566 example.com. mb8QGw3DKlUONAfNAMhwTeglcNEtPt4fz7fcJlQBnCrCy38ktWgEHWULnTSYlQb49+Mt/lXRzFuqMomKyNi+4VA7PcSHGvo3wpBkiT2dqSk/jFYYnrWhGBncD7c6SyE/QbYj1Wvcy7WaBz5s+QVVWDqg6KLkoIwXMd7eTsM/018=
884sems3cdr70nhc4d9qhno9a449gslj.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  9kpaurblh2ncekbdnnuml8o6tegktpve A RRSIG 
884sems3cdr70nhc4d9qhno9a449gslj.example.com.   3600    IN  RRSIG   NSEC3 10 3 3600 20140430073146 20130420073221 8566 example.com. J9ihRyn9hDTdLW1a4ZPkRtftEqFk9RWizEfTjdW7trTh+m4+6eY+iQy6J09ZD7LMx1nqSniWPATEKZS3hitXrru8Yexrw6qmWrKSIq55H0XAtfdfU3y5MPMcjcJstTocBAxy4s8K8qerF/NpxfKEN3L/KNO5f8RxYlDt3FagFeA=
zABC.a.example.com. 3200    IN  A   10.1.2.4
zabc.a.example.com. 3200    IN  RRSIG   A 10 4 3200 20140430073146 20130420073221 8566 example.com. uZP+WmK8cyJQLG/Vdx8SUrQrK6/2MLAU0KpQm7+n8fLdngw4+7umASXtfSTheThmNVR/iQnHvWMhiSKuMqRTGpYj1eXIPPGBQiymaUFQGZNjSliWQmNW83lFARmRhLwKghtKGL7R9FgxI7tAiGycYThM1pGGN2D+4z+BVqsVAoo=
i887uaqoprdnmesu0ughr7sheqaug3h1.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  iu0ms05m0tb8if6q0hsa6pnppi75ap3g A RRSIG 
i887uaqoprdnmesu0ughr7sheqaug3h1.example.com.   3600    IN  RRSIG   NSEC3 10 3 3600 20140430073146 20130420073221 8566 example.com. nTTrm8xIQEo46/9l7EaZmCyS/MMtFNCKGsye13Zk5kJ0zrPNVYstkPTpylPIOLWnO/NFIkVDm6Mcih3nrFHjbrzkYU25rhYknC4qe4UTMWGV+DncbyGqHRVYSufxKVBxfAFP10kRknJTw5ndbxQXXvqXneiP/hbbm6WZOeetDZk=
cns1.example.com.   3200    IN  A   10.4.4.3
cns1.example.com.   3200    IN  RRSIG   A 10 3 3200 20140430073146 20130420073221 8566 example.com. mNeGoBSRHXqKhtcgP/I2Fpp0ynPpO6roMKGNedmnOTgbmqNfNKx8JpnY0il7+Bpot0kT4cQg+gFNhTWNBty2BSyxcThsQ2yxv1skZttGx57bfdvi9YRd0g2lL+dMZOx9uboBroBjohCTGM4rKxUBATpkQjHX/4vV67QZl9q2M7A=
rdkf8d33qe24o2v2q21na3lbk3oaakcu.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  vcfnvpc2eqaspricadp3cigdgm8ujef8 A RRSIG 
rdkf8d33qe24o2v2q21na3lbk3oaakcu.example.com.   3600    IN  RRSIG   NSEC3 10 3 3600 20140430073146 20130420073221 8566 example.com. X33/DY9s+OBzeMlz7Rpvz4xWS0kqH4IKXByLeiHY7/JK2+DnXjczhOsVgfOtDxClHNuPq2xVHr/WeCLk79o1mYkkhY6bod+S0kUScggAWdJECMzAOvln919QAJIQfJObmQSneIIPLWDQdzBT+n967jJXNfiP5SOmMZ4n3qv7R7Y=
cns2.example.com.   3200    IN  A   10.5.4.3
cns2.example.com.   3200    IN  RRSIG   A 10 3 3200 20140430073146 20130420073221 8566 example.com. Qm+F4B/WN3ezBAPDmf430t3/saK0EZOTnEXBsf88pQHiUv9Fe0t/0sHFJJpjFweOGt+RVUqQ7eleX+sa8MpJe/R9GuqWarFWDHxkoWX33OuVBlTKdZnv9wLz+TFOa2f4F3bMseDjbZhsJPfnCx32yBy7E4BxPS5YhncPE3CXIdY=
i2ferdohnjamei8n3rpmbv4lf5pt4ubg.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  i887uaqoprdnmesu0ughr7sheqaug3h1 A RRSIG 
i2ferdohnjamei8n3rpmbv4lf5pt4ubg.example.com.   3600    IN  RRSIG   NSEC3 10 3 3600 20140430073146 20130420073221 8566 example.com. fu9wjEJWJMGnC6KwQT5rqjRuA3lOimqotsvy/dqDctnTBgnVNyOgQGBHoc+Htoa5ntZ0xYk8dWN9K+9VQLLFC1igdGjBBgf5jFTRwFEI+Vdc7sNV8pmNPLsbWZ1oa+s/3Ov/hnETOIUiY+WLr4xARCaS2QcFw5eojrEzYdDEFsQ=
delegated.example.com.  3200    IN  NS  ns1.example.org.
1iohp8j7vsr7h24al82qi9b0n3m7o2jt.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  55quulbf2cj6nvm5odj6rmmer1985s95 NS 
1iohp8j7vsr7h24al82qi9b0n3m7o2jt.example.com.   3600    IN  RRSIG   NSEC3 10 3 3600 20140430073146 20130420073221 8566 example.com. tgD3P5tNja/DWtb9+Pe+j00ZUEtsr8I9BRQzVaF1pMgDpgSCbR0d4npe74Fej16alih+5kPfNgnWsx3jcfot32MoKmUNAKXW0vIsJHM1fYzDMZUe38b8SPaJrcp5sb6M3XS1AfFGBFazK+ozOm/ut8xgMsCKVQD6Ldwa9ellxhs=
delegation2.example.com.    3200    IN  A   10.2.3.4
delegation2.example.com.    3200    IN  NS  ns1.delegation2.example.com.
55quulbf2cj6nvm5odj6rmmer1985s95.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  61fcihg3gtvgh50kcnm0k3nlprqhvk0j NS 
55quulbf2cj6nvm5odj6rmmer1985s95.example.com.   3600    IN  RRSIG   NSEC3 10 3 3600 20140430073146 20130420073221 8566 example.com. exN7jl6GumM1E9z9btsM46a1quKnyQruNVbuW7R4oZyDWhfnxQy7Ch0tze0L1M1ZOlCuW5Dao9pYCSOsZL0iSCZ/ZvFFl/Dh5dbkd6Qh6yApjIaC9uj3dlyDF1fmkeXRXuITZMxMxQFAXhWFa+phGplrDaRqNB5AaZx4HkCISCU=
ns1.delegation2.example.com.    3200    IN  A   10.34.12.34
a6t3254d1semge7fq420mfvqjkg7bgtf.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  d34nh4783sq7etvv6s4u35hn2dar42v4
a6t3254d1semge7fq420mfvqjkg7bgtf.example.com.   3600    IN  RRSIG   NSEC3 10 3 3600 20140430073146 20130420073221 8566 example.com. VVGKI0R84u9ixmL96Q+GKphFVK39veuaYyQZmE5Qwl4bQ1vz7QnXdtKiL0N78Lt0YuQFTuFuOHZ4caopAPUF7/4OxmcsaBRvmxGyEw3kUy1wIr7jFFyp48i66sW0GYRWzVK48+s7ygpbQvJ4BItrCfKCSi9ZEqcuaTiRZZa/Emg=
djikj02ef37hp4d50jij9v3g79u5aee5.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  fiqcf70a6339k96ef2scbk4vkmm0p1j8
djikj02ef37hp4d50jij9v3g79u5aee5.example.com.   3600    IN  RRSIG   NSEC3 10 3 3600 20140430073146 20130420073221 8566 example.com. LSTN8ulWJabgoriWBRMmRf8OndLlbxWwjZbYdrHpOVEuxv5gqzJrb4tEwTol+4fAZCa+E3UfeteHrviAWy+Jl7gatzDDMLSPJbvsBejeSzLW7bnKChcopkBmeEyTdiEf0dQ5PczTg3/xNIlHn6AbSgUGtiF/p5p5zQn+0PichM8=
empty.non.terminal.example.com. 3200    IN  A   10.1.2.4
empty.non.terminal.example.com. 3200    IN  RRSIG   A 10 5 3200 20140430073146 20130420073221 8566 example.com. bwmxkteBxahF+bGzfPP5hx8TVJROutuiWz9zrFJNeZtAIz/JIIZDM2HN9EjC3ymB8jb1QjYnlwRL1OpRdG/A0Zjf6buPr+OS+NnPb4QUiDY9BQFkUUstXQn5aIMIID+78AE0UGTvX5v4JjQrI2HfRHnCsYHExN4bTHrlB4X/6U8=
n5cr9nt1bf55rgf5rirpoc8dh48bdm1r.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  q4s8hrhd7c8s824nkql0a52ng50mhtut A RRSIG 
n5cr9nt1bf55rgf5rirpoc8dh48bdm1r.example.com.   3600    IN  RRSIG   NSEC3 10 3 3600 20140430073146 20130420073221 8566 example.com. DKiHRl8M5OEc8IfjUKhtIougaYJBYXtv8mJ/H8037w/gatSwl0B+dpx0X8h0R0/DD3aK2VIxqLlbUFTwFjlqYGtPVBzXAbOcuVb1hPF1BuW7cOmgtH6Ao+7gftP9wzVsAo9AhEf/xGFsT4u0qpgpYf62aBL+IhuqgzFQwE46rZk=
test.example.com.   3200    IN  TXT "aaa"
test.example.com.   3200    IN  TXT "bbb"
test.example.com.   3200    IN  RRSIG   TXT 10 3 3200 20140430073146 20130420073221 8566 example.com. OiyVtWk37MSBD66fyNPeZueX+H5F1Wiv34xqwYVmi80R0dO2ioPEtM8oz3z2964LFDI6BwXGNOhgY3akimn5MbEZgyxRoDUwGXy7XL2CcuvOrUnsuWm5qfSbteQYblu6kR5qLBgmYODzjc8FyemZRsUGNcHGG2HVspCBNS55Z9g=
test.example.com.   3200    IN  DNAME   example.org.
test.example.com.   3200    IN  RRSIG   DNAME 10 3 3200 20140430073146 20130420073221 8566 example.com. YSy+wXNOSaQQN2CW8zP31x1K5mQ9UTkQRD48iEWhf2F7tZFHq7ReVyamTbIjq+se0ijGP9JdcOTJH79xchvsKcs2vKul/NOQRwn2TzLs/fI/66wK1ncPJ7f3gAH/AeKniG8Us81TErhZ7XSsR7JViUpr/nt/vxr0AaE3MF3eJvQ=
iu0ms05m0tb8if6q0hsa6pnppi75ap3g.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  n5cr9nt1bf55rgf5rirpoc8dh48bdm1r TXT DNAME RRSIG 
iu0ms05m0tb8if6q0hsa6pnppi75ap3g.example.com.   3600    IN  RRSIG   NSEC3 10 3 3600 20140430073146 20130420073221 8566 example.com. kDwOReXlaZ9SY8LRKms5Syn8ANwGhHtwUK70+ZQ9W3Rz7x/g4YbvqT+Os0zS/E/Mrxl/lqC0/Nt+qQKSB0zOHbOcHRJTOmgYnGJFMEOl0OAKZpG/FMHUNv7h9n1Ht2N3YadAd8OKoWJrKLvBvsIPMVsIJ2+WU7q1lQcyoFUnoAg=
uppercase.example.com.  3200    IN  CNAME   UPPERCASE.EXAMPLE.ORG.
uppercase.example.com.  3200    IN  RRSIG   CNAME 10 3 3200 20140430073146 20130420073221 8566 example.com. tFTvUo1sA3M3FV9Erda8Qmya6vVcpJ7OQ9LmyYSnSiNo5s6vmzu7bllOCsjqJHFrr3izkIOR7ZDBBd7jJB1caO/oSPnDx2YnkF+kXIVXTVAMv5fWZqoNT+vBYk8Gsb3oA9djLOuc27qrF7UVhCpN1XvV+Mx5Xn0nrXEVgm9KusY=
61fcihg3gtvgh50kcnm0k3nlprqhvk0j.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  6nvejcs9vh19cvlaipno1p94s20t3eu3 CNAME RRSIG 
61fcihg3gtvgh50kcnm0k3nlprqhvk0j.example.com.   3600    IN  RRSIG   NSEC3 10 3 3600 20140430073146 20130420073221 8566 example.com. SeWAZ+jxah8ZnFuc5Lwt0hIMV2dL9TkKLbTQFR0wz8gJPeanPDj9hrpN/wHK/wOrzYu6Y+D8wX99/tLlynccvJq8Z/sxsZIHYkBXVF4QAbtAu6/xm0rbzJT+SaYACkjPGgHiEWMrvnIcA1oBYLsmmlcDAlKBLH4D5JZqACacjp8=
www.example.com.    3200    IN  A   10.1.2.3
www.example.com.    3200    IN  A   10.1.2.4
www.example.com.    3200    IN  A   10.1.2.5
www.example.com.    3200    IN  RRSIG   A 10 3 3200 20140430073146 20130420073221 8566 example.com. SmJ6jr6QxnjfR5nM2CDzudfw9noEutAOeKea9JifTP2eP+fb0AlvNrAFqPjvFD72x+CYAREylWMugXs6sW5LsE0vHHwuXqStCI0UzM6VkmH2Gy8MSP5jj05OZStIPS6AISP2TpKdRxpK9yvV3DFSctKQ3xs6ztbaRccHDsTRBQ0=
d34nh4783sq7etvv6s4u35hn2dar42v4.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  djikj02ef37hp4d50jij9v3g79u5aee5 A RRSIG 
d34nh4783sq7etvv6s4u35hn2dar42v4.example.com.   3600    IN  RRSIG   NSEC3 10 3 3600 20140430073146 20130420073221 8566 example.com. fslDstp+7FqlPA10tzfZh/2l4qeDZL6LbvOeDfj01b6V7fnOWqJTronK8vgtbOohamIy3hreSuSEUl+SIxuJEs8D3iVd2mONrLRCDm5rQ5EsTuTI3z3r8O114IpXMFJiaVYxSLlNBxYwf1XchuhFvfmtD3NxrdbmQDzp12UzYKY=
z.example.com.  3200    IN  A   10.1.2.4
z.example.com.  3200    IN  RRSIG   A 10 3 3200 20140430073146 20130420073221 8566 example.com. uWonKGhmJT3GkVagfjuLJvlggc0h5A/74r2C7oc8T5tNk+vV6CKE2ydM1atOO5EzwJl8JQ9qRT7KiATFhVLdlBhb9pujFVvZmeWtzwS1lnh0uqlhMQIyJfBAxGIOyzU1v9InNGUPd2lhN4AaCx2rBpXM5XCo7iU1mKNp9jhli+Y=
6nvejcs9vh19cvlaipno1p94s20t3eu3.example.com.   3600    IN  NSEC3   1 0 10 05d67bb3fe7bf907  6r1v3vosorqt80kb3ailjib5a7n3cnlk A RRSIG 
6nvejcs9vh19cvlaipno1p94s20t3eu3.example.com.   3600    IN  RRSIG   NSEC3 10 3 3600 20140430073146 20130420073221 8566 example.com. ZWque75Wm1Ti/B8ACHDD+0O04zGuvwZLXq19E0KYZORydhxWi8N1F/gDX54ApcDXjl6NxB4yKREYxkNUyOCDprryzqX7gqq+igYnXPYEsh3yFCAeICOVKrazl8kp5jLmlmcIAmVEQJLDHlmtb0P7noZ5+qX/tV3XZkkuJ7v5cso=
"""
# }}}

# RSA key data {{{
rsa_priv  = """-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC8D8JKLN42XgDgzs1ugBNKn9ns6UhCuse1QFNoDFU1gIzfSJZE
AJsXDXwQRcvZ8uKP/JGU01ssO6cgC8zcfY8Ya58IiHaFkf+zdEKtSGvwln7M1o5V
78wxMMJDP0LONf/HrwhEoSQbpNe8DCSprh5AD6BIFHDeL9LZwfPdgHqtLwIDAQAB
AoGBAI8D8P4Vtvtja4mK24FQFtumSsU29wQAJQW6oHM9BcPFOdxHyDZ4u3jBgXqi
iY76fb+AFHo4bVprFwJw1t9LAPkEONDyTG4Jov+OkjAVPdrnfWg41teEiXjMFhhk
Y/zsHExYgWJSIn3TG3mBA5m1YUBQk9FfSrb7VpgZa6M2ZyBpAkEA0d7/BDCm7RLe
76y7vZgXU3MFOwxaYeKhTIlMq/E8Z8iv76LpoNl/nzgsJ/CidPF2W9Ofk/Xp6xqb
RkbA0U9DWwJBAOVllkR+53P75la6XlZOhh6+ltr0NlmxwHmjzk7BD8n3Ve/N1rZH
ro0wwOWJx27JBG815qnpQoyNHt4dPU0TSb0CQAahzF8+hlfhi8f5JmmkX8BUVyr5
hfWn6r73a8PXOLhy4BRrioR5uw22Abc1ZHzbkIjwVA+h6sVyLsv2umsi3RcCQDgT
AQx1SPadGM0SeYT3ZOmXBSE4mSCLxtT1KbUulEF2aFdaJaYhF5YD2ONDLrDyCld1
AZF/J3lb9bOtyhJRKLECQQCRAv6ZI1UqEb/AJWT4ho2yV8NedxYvrKsNudZKfd33
/ahAiginomXoy5n8O2C6aTocjKm/hbSnYXZkonrZ/IqS
-----END RSA PRIVATE KEY-----"""

rsa_pub = "AwEAAbwPwkos3jZeAODOzW6AE0qf2ezpSEK6x7VAU2gMVTWAjN9IlkQAmxcNfB"\
          "BFy9ny4o/8kZTTWyw7pyALzNx9jxhrnwiIdoWR/7N0Qq1Ia/CWfszWjlXvzDEw"\
          "wkM/Qs41/8evCEShJBuk17wMJKmuHkAPoEgUcN4"\
          "v0tnB892Aeq0v".decode('base64')
# }}}

### }}}

class DNSSECSignerTestCase(unittest.TestCase):
    def _nsec3fix(self, zone):
        """
        Older versions of DNSpython have a bug in NSEC3 from_text routine.
        In order to run tests successfully with older DNSpython, we
        need to fix automatically loaded NSEC3s.
        """
        for name, rdataset in zone.iterate_rdatasets():
            if rdataset.rdtype != dns.rdatatype.NSEC3:
                continue
            for rdata in rdataset:
                if rdata.windows == [(0, '')]:
                    rdata.windows = []

    def _diff(self, zone1, zone2):
        for name in zone1.nodes:
            if zone1.nodes[name] != zone2.nodes[name]:
                print " ======> DIFFERENCE IN NODE", name 
                for rdataset in zone1.nodes[name]:
                    print rdataset.to_text(name)
                print "--------"
                for rdataset in zone2.nodes[name]:
                    print rdataset.to_text(name)

    def setUp(self):
        self.expiration = 1398843106
        self.inception  = 1366443141
        self.rsasha1 = dnssec.PrivateDNSKEY(
            dnssec.DNSKEY_FLAG_ZONEKEY,
            dnssec.RSASHA1, rsa_pub, rsa_priv
        )
        self.rsasha1nsec3sha1 = dnssec.PrivateDNSKEY(
            dnssec.DNSKEY_FLAG_ZONEKEY,
            dnssec.RSASHA1NSEC3SHA1, rsa_pub, rsa_priv
        )
        self.rsasha256_ksk = dnssec.PrivateDNSKEY(
            dnssec.DNSKEY_FLAG_ZONEKEY | dnssec.DNSKEY_FLAG_SEP,
            dnssec.RSASHA256, rsa_pub, rsa_priv
        )
        self.rsasha512_ksk = dnssec.PrivateDNSKEY(
            dnssec.DNSKEY_FLAG_ZONEKEY | dnssec.DNSKEY_FLAG_SEP,
            dnssec.RSASHA512, rsa_pub, rsa_priv
        )

    def testRSASHA1(self):
        zone = dns.zone.from_text(zone_orig_txt, relativize=False)
        dnssec.sign_zone(zone, [self.rsasha1], self.expiration, self.inception, 
                         nsec3=False, keyttl=3600)
        signedzone = dns.zone.from_text(zone_rsasha1_txt, relativize=False)
        self._diff(zone, signedzone)
        self.assertEqual(zone, signedzone)

    def testRSASHA1NSEC3SHA1(self):
        zone = dns.zone.from_text(zone_orig_txt, relativize=False)
        dnssec.sign_zone(zone, [self.rsasha1nsec3sha1], self.expiration, 
                         self.inception, nsec3=True, keyttl=3600,
                         nsec3salt='05D67BB3FE7BF907'.decode('hex'),
                         nsec3iters=10)
        signedzone = dns.zone.from_text(zone_rsasha1nsec3sha1_txt, 
                                        relativize=False)
        self._nsec3fix(signedzone)
        self._diff(zone, signedzone)
        self.assertEqual(zone, signedzone)

    def testRSASHA256(self):
        zone = dns.zone.from_text(zone_orig_txt, relativize=False)
        dnssec.sign_zone(zone, [self.rsasha256_ksk], self.expiration, 
                         self.inception, nsec3=True, keyttl=3600,
                         nsec3salt='05D67BB3FE7BF907'.decode('hex'),
                         nsec3iters=10)
        signedzone = dns.zone.from_text(zone_rsasha256_txt, 
                                        relativize=False)
        self._nsec3fix(signedzone)
        self._diff(zone, signedzone)
        self.assertEqual(zone, signedzone)

    def testRSASHA512(self):
        zone = dns.zone.from_text(zone_orig_txt, relativize=False)
        dnssec.sign_zone(zone, [self.rsasha512_ksk], self.expiration, 
                         self.inception, nsec3=True, keyttl=3600,
                         nsec3salt='05D67BB3FE7BF907'.decode('hex'),
                         nsec3iters=10)
        signedzone = dns.zone.from_text(zone_rsasha512_txt, 
                                        relativize=False)
        self._nsec3fix(signedzone)
        self._diff(zone, signedzone)
        self.assertEqual(zone, signedzone)

if __name__ == '__main__':
    unittest.main()
