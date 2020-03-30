#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Manually encrypt a wep message given the WEP key"""

__author__ = "Abraham Rubinstein"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
import binascii
from rc4 import RC4
import sys, netifaces, argparse, zlib

# Args parsing
parser = argparse.ArgumentParser(prog="Scapy WEP encryptor and fragmentor",
                                 usage="%(prog)s -i mon0 -k aa:aa:aa:aa:aa -m aa:ab:ac:ad",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to send packet out of, needs to be set to monitor mode")
parser.add_argument("-k", "--wep-key", required=True,
                    help="The WEP key to encrypt the message with, must be of the format XX:XX:XX:XX:XX")
parser.add_argument("-m", "--message", required=True,
                    help="The message to encrypt, at most 16*36 bytes (576), as an hex string")

args = parser.parse_args()

pktdump = PcapWriter("fragment.pcap", append=True, sync=True)

# Cle wep AA:AA:AA:AA:AA
key = binascii.unhexlify(args.wep_key.replace(':', ''))

# lecture du template message WEP - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]

# rc4 seed est composé de IV+clé
seed = arp.iv + key

cipher = RC4(seed, streaming=False)

cleartext = binascii.unhexlify(args.message.replace(':', ''))

# configurable
fragmentSize = 36
minFragCount = 3

fragments = []
for i in range(0, max(math.ceil(len(cleartext) / fragmentSize), minFragCount)):
    frag = cleartext[i*fragmentSize: (i+1) * fragmentSize]
    frag += b'\0'*(fragmentSize - len(frag))
    fragments.append(frag)

# same method as for manual encryption but for each fragment
for i, fragment in enumerate(fragments):

    # then we create the appropriate CRC32 value, packing it to little endian
    crc = struct.pack('<L', zlib.crc32(fragment))

    # we generate the ciphertext with the cleartext, and the previously used seed
    ciphertext = cipher.crypt(fragment + crc)

    # we then can add the ciphertext to the arp packet wepdata (ommiting the ICV)
    arp.wepdata = ciphertext[:-4]

    # we can then add the numerical icv to the arp packet
    arp.icv = struct.unpack('!L', ciphertext[-4:])[0]

    # we set the FCfield depending on whether it's the last fragment or not
    if i != len(fragments) - 1:
        arp.FCfield |= 0x4
    else:
        arp.FCfield &= ~0x4

    arp.SC += i
    pktdump.write(arp)

    #sendp(arp, iface=args.Interface)

    arp.SC -= i

