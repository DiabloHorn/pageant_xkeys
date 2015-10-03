#!/usr/bin/env python
"""
DiabloHorn https://diablohorn.wordpress.com

Writes the raw memory from a minidump to a file
"""
import sys
import os

try:
	import minidump
except:
	print "You need the minidump library"
	print "Download http://moyix.blogspot.com.au/2008/05/parsing-windows-minidumps.html"
	sys.exit()

if __name__ == "__main__":
	if len(sys.argv) != 2:
		print "Usage %s %s" % (sys.argv[0], "<minidump_file>")
		sys.exit()

	minidump_filesize = os.path.getsize(sys.argv[1])
	rawmemory_filename = "%s.rawmem" % sys.argv[1]
	print ":::minidump filesize %s" % minidump_filesize
	f = open(sys.argv[1],'rb')
	parsed_minidump = minidump.MINIDUMP_HEADER.parse_stream(f)
	f.close()

	for i in parsed_minidump.MINIDUMP_DIRECTORY:
		if i.StreamType == 'Memory64ListStream':
			rawmemory_size = (minidump_filesize - i.DirectoryData.BaseRva)
			print ":::Found raw memory data stream"
			print ":::Start of raw memory %s" % i.DirectoryData.BaseRva
			print ":::Size of raw memory %s" % rawmemory_size
			print ":::Writing raw memory to  %s" % rawmemory_filename
			f = open(sys.argv[1],'rb')
			f.seek(i.DirectoryData.BaseRva)
			data = f.read(rawmemory_size)
			f.close()
			f = open(rawmemory_filename,'wb')
			f.write(data)
			f.close()