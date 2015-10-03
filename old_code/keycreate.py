#!/usr/bin/env python
"""
DiabloHorn https://diablohorn.wordpress.com

Converts rsa primitives extracted with windbg from memory
to a workable rsa private key format
"""
import sys
import base64
from Crypto.PublicKey import RSA

def string_to_long(data):
	data = data.split(' ')
	data.reverse()
	return long(("".join(data)),16)

if __name__ == "__main__":
	#setup the primitives
	rsamod = string_to_long('7955549b 79eb3c32 ee6e6b2c 405d4cfb c22ae82b a467ac7b 0f5875bb 5fec483b 72b26f8a 8c27373f a1abcfff d142c88a 88564e3b 1c45d0c4 53535ca6 72695f43 6fdde462 32741a1f ff1e0440 219fffea 04beaa49 73308e60 2a3e7ba6 644f51ba 8a4ddf2d 1fe2ba37 e7bcf094 adf5a610 3845feb6 2349edf5 2eb40451 e0ed9d03 923a0a70 e835a702 b0d4887b a20493ed 17c55930 29b672c9 167dc521 80327c02 daf9b3fe f3c39157 cffb8360 96c5d8db 670e1092 6d4e9f0d 2f517912 d42b8ce1 6fea58d5 7038f788 115a1eaa e5963585 7cdcd082 64d0a88c 66a4a66f fa3648ae c2fb89bc 099a73f7 f3292ffa ce2c2428 55da8859 ce045224 6190274f b1652f29')
	rsapubexp = long(0x25)
	rsaprivexp = string_to_long('a396f24d 8fd800ec 6dc00c2e abcd8943 a98f0d92 217299a8 a1ba8dcf c5b87820 96373ebe 76c0a795 92340c3b 05651d18 9ccf90bc 108c2ab3 329fc033 d36e9837 c3f7e413 22c62633 7b854536 acbd5c31 cbe7c3a3 a292eb62 b5c4146d 9f55ffa6 5d241da1 608fcce7 d2de7859 b76b703a c9960358 734329ad 13781aec 3af1eb80 fdf94703 5ac52b0f 9b12eee4 5064b34a 600635f8 c900a55c 65deff1b 41e51bca 8df3ce28 a9a3daa3 ec869e81 699101cc a95ecf9d 2b26323b e95fefd1 8154eba7 3b2c20ea 18d5c879 00b34a20 c05b4199 46051d66 69393345 a21b3f56 0fe84abb a35d2060 61fdf275 7f9f0c85 cf556a67 c478d31a dd0a8a02 1a640542 94a0e253')

	rawkey = (rsamod,rsapubexp,rsaprivexp)
	#construct the desired RSA key
	rsakey = RSA.construct(rawkey)
	#print the object, publickey, privatekey
	print rsakey
	print rsakey.publickey().exportKey('PEM')
	print rsakey.exportKey('PEM')