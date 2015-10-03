#!/usr/bin/env python

"""
DiabloHorn https://diablohorn.wordpress.com
Automatically extract rsa keys from a pageant minidump

http://moyix.blogspot.nl/2008/05/parsing-windows-minidumps.html
	import minidump
	parsed_minidump = minidump.MINIDUMP_HEADER.parse_stream(file)
http://infopurge.tumblr.com/post/10445418822/the-format-of-a-minidump-mdmp-file
http://www.mit.edu/afs.new/sipb/project/wine/src/wine-0.9.37/tools/winedump/minidump.c
https://github.com/bsmedberg/minidump-memorylist
https://www.zyantific.com/2014/12/dumping-packed-executables-using-minidumps/

"""

import sys
import os
import struct
from ctypes import *

try:
	import minidump
except:
	print "You need the minidump library"
	print "Download http://moyix.blogspot.com.au/2008/05/parsing-windows-minidumps.html"
	sys.exit()

try:
	from Crypto.PublicKey import RSA
except:
	print "You need pycrypto"
	sys.exit()

#version 0.65
START_TREE234_SSH2KEYS = 0x00420D2C

class node234(Structure):
	"""
	    node234 *parent;
    	node234 *kids[4];
    	int counts[4];
    	void *elems[3];
	"""
	_fields_ = [("parent",c_uint), ("kids", c_uint * 4), ("count", c_uint * 4), ("elements",c_uint * 3)]

	def count_elements(self):
		totalcount = 0
		for i in self.elements:
			if i != 0:
				totalcount += 1
		return totalcount

	def count_kids(self):
		totalcount = 0
		for i in self.kids:
			if i != 0:
				totalcount += 1
		return totalcount

	def __str__(self):
		return hex(self.parent) + '|' + ' '.join(map(hex,self.kids)) + '|' + ' '.join(map(hex,self.count))

class ssh_signkey(Structure):
	_fields_ = [("fucn1",c_uint),("fucn2",c_uint),("fucn3",c_uint),("fucn4",c_uint),("fucn5",c_uint),
				("fucn6",c_uint),("fucn7",c_uint),("fucn8",c_uint),("fucn9",c_uint),("fucn10",c_uint),
				("fucn11",c_uint),("fucn12",c_uint),("name",c_uint),("keytype",c_uint)]

class ssh2_userkey(Structure):
	_fields_ = [("ssh_signkey",c_uint),("data",c_uint),("comment",c_uint)]

class rsakey(Structure):
	#incomplete structure, we only need these fields
	_fields_ = [("bits",c_uint),("bytes",c_uint),("modulus",c_uint),("exponent",c_uint),("private_exponent",c_uint)]

#======================start minidump_helper class====================================================
class minidump_helper:

	def __init__(self, filename, mm64list_stream):
		if mm64list_stream.StreamType != 'Memory64ListStream':
			print "Types do not match: %s" % mm64list_stream.StreamType
			return None
		self.crashdump = filename
		self.liststream64 = mm64list_stream
		self.mmap64 = self._build_memorymap()

	def little2big(self, data):
		return struct.unpack('=l',data)[0]

	def get_filename(self):
		return self.crashdump

	def get_memorymap(self):
		return self.mmap64

	def get_baserva(self):
		return self.liststream64.DirectoryData.BaseRva

	def get_numberofmemoryranges(self):
		return self.liststream64.DirectoryData.NumberOfMemoryRanges

	def _build_memorymap(self):
		"""
			In a MINIDUMP_MEMORY_DESCRIPTOR64 structure the BaseRva
			points to the start of all the memory ranges, which are 
			consecutive after each other
			virtual_offset_rangestart : (physical_offset_start, physical_size)
		"""
		memorymap = {}
		totalsize = 0
		baserva = self.liststream64.DirectoryData.BaseRva
		mmdscrptr64 = self.liststream64.DirectoryData.MINIDUMP_MEMORY_DESCRIPTOR64
		numberofmemoryranges = self.liststream64.DirectoryData.NumberOfMemoryRanges
		for i in range(numberofmemoryranges):
			memorymap[mmdscrptr64[i].StartOfMemoryRange] = ((baserva + totalsize),mmdscrptr64[i].DataSize)
			totalsize += mmdscrptr64[i].DataSize
		return memorymap


	def find_memoryentry(self, offset):
		upperlimit = 0
		memlist = self.mmap64.keys()
		memlist.sort()
		for i in memlist:
			if offset > i:
				if offset < memlist[(memlist.index(i) + 1)]:
					return i
		return None

	def _read_chunk(self, offset, chunksize):
		#this could be done more efficient, suffices for now
		f = open(self.crashdump,'rb')
		f.seek(offset)
		data = f.read(chunksize)
		f.close()
		return data	

	def get_chunkdata(self, offset):
		if self.mmap64.has_key(offset):
			return self._read_chunk(self.mmap64[offset][0], self.mmap64[offset][1])
		else:
			resolved_offset = self.find_memoryentry(offset)
			if not resolved_offset:
				return None
			return self._read_chunk(self.mmap64[resolved_offset][0], self.mmap64[resolved_offset][1])
		return None

	def get_pointer32(self, offset, pwidth=4):
		memory_segment = self.find_memoryentry(offset)
		if memory_segment:
			memchunk = self.get_chunkdata(memory_segment)
			memchunk_off = (offset - memory_segment)
			return self.little2big(memchunk[memchunk_off:(memchunk_off+pwidth)])
		return None

	def get_hexstring(self, offset, pwidth=4):
		memory_segment = self.find_memoryentry(offset)
		if memory_segment:
			memchunk = self.get_chunkdata(memory_segment)
			memchunk_off = (offset - memory_segment)
			littleendian = struct.unpack('=L', memchunk[memchunk_off:(memchunk_off+pwidth)])[0]
			return '{:08x}'.format(littleendian)
		return None		
#======================end minidump_helper class====================================================

class tree234_helper:
	def __init__(self, first_node, mh_object):
		self.root = first_node
		self.mh_object = mh_object
		self.privatekeys = list()
		self._walktree(self.root)

	def _getstring(self, offset):
		finalstring = ""
		memory_segment = self.mh_object.find_memoryentry(offset)
		memchunk = self.mh_object.get_chunkdata(memory_segment)
		memchunk_off = (offset - memory_segment)
		for i in memchunk[memchunk_off:]:
			if ord(i) != 0:
				finalstring += i
			else:
				break
		return finalstring

	def _read_obj_ssh2usrkey(self, offset):
		memory_segment = self.mh_object.find_memoryentry(offset)
		memchunk = self.mh_object.get_chunkdata(memory_segment)
		memchunk_off = (offset - memory_segment)
		return ssh2_userkey.from_buffer_copy(memchunk[memchunk_off:(memchunk_off+sizeof(ssh2_userkey))])

	def _read_obj_rsakey(self, offset):
		memory_segment = self.mh_object.find_memoryentry(offset)
		memchunk = self.mh_object.get_chunkdata(memory_segment)
		memchunk_off = (offset - memory_segment)
		return rsakey.from_buffer_copy(memchunk[memchunk_off:(memchunk_off+sizeof(rsakey))])

	def _read_bignum(self, offset):
		bignum = list()
		bignum_size = self.mh_object.get_pointer32(offset)
		for i in range(bignum_size):
			offset = offset + 4
			bignum.append(self.mh_object.get_hexstring(offset))
		bignum.reverse()
		return long((''.join(map(str, bignum))),16)

	def _create_node234(self, offset):
		memory_segment = self.mh_object.find_memoryentry(offset)
		memchunk = self.mh_object.get_chunkdata(memory_segment)
		memchunk_off = (offset - memory_segment)
		node_data = memchunk[memchunk_off:(memchunk_off+sizeof(node234))]
		return node234.from_buffer_copy(node_data)

	def _create_privatekey(self, rsakey_object):
		modulus = self._read_bignum(rsakey_object.modulus)
		exponent = self._read_bignum(rsakey_object.exponent)
		private_exponent = self._read_bignum(rsakey_object.private_exponent)

		rawkey = (modulus,exponent,private_exponent)
		#construct the desired RSA key
		rsakey = RSA.construct(rawkey)
		#print the object, publickey, privatekey
		return rsakey.exportKey('PEM')		

	def _get_keys_from_elements(self, node, elementcount):
		for i in range(elementcount):
			obj_ssh2usrkey = self._read_obj_ssh2usrkey(node.elements[i])
			print "Key comment %s" % self._getstring(obj_ssh2usrkey.comment)
			obj_rsakey = self._read_obj_rsakey(obj_ssh2usrkey.data)
			print self._create_privatekey(obj_rsakey)

	def _walktree(self, node):
		childcount = node.count_kids()
		elementcount = node.count_elements()
		if elementcount != 0:
			self._get_keys_from_elements(node, elementcount)

		if childcount != 0:
			for i in range(childcount):
				self._walktree(self._create_node234(node.kids[i]))

def get_node(mh_object,offset):	
	memory_segment = mh_object.find_memoryentry(offset)
	memchunk = mh_object.get_chunkdata(memory_segment)
	memchunk_off = (offset - memory_segment)
	return memchunk[memchunk_off:(memchunk_off+sizeof(node234))]

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print "%s <dump_file> [<tree_start_offset>]" % sys.argv[0]
		print "Ex:"
		print "\t%s pageant.exe_150823_193939" % sys.argv[0]
		print "\t%s pageant.exe_150823_193939 00420D2C" % sys.argv[0]
		sys.exit()

	if len(sys.argv) == 3:
		START_TREE234_SSH2KEYS = int(sys.argv[2], 16)

	f = open(sys.argv[1],'rb')
	parsed_minidump = minidump.MINIDUMP_HEADER.parse_stream(f)
	f.close()
	for i in parsed_minidump.MINIDUMP_DIRECTORY:
		print "::listinfo %s" % i.StreamType 
		if i.StreamType == 'Memory64ListStream':
			print "::::Found correct stream"
			mh = minidump_helper(sys.argv[1], i)
			print "::::stream contains #%s" % mh.get_numberofmemoryranges()
			print "::::stream data baserva %s" % mh.get_baserva()
			pageant_sshtree_rootp = mh.get_pointer32(START_TREE234_SSH2KEYS)
			pageant_sshtree_root = mh.get_pointer32(pageant_sshtree_rootp)
			node_data = get_node(mh, pageant_sshtree_root)
			first_node = node234.from_buffer_copy(node_data)
			t = tree234_helper(first_node, mh)