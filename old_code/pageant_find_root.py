#!/usr/bin/env python
"""
DiabloHorn https://diablohorn.wordpress.com
Finds the root of the tree, example:

0x410e53:       call    0x40d7d0
0x410e58:       mov     dword ptr [0x420d18], eax
0x410e5d:       mov     dword ptr [esp], 0x40f0a5
0x410e64:       call    0x40d7d0
0x410e69:       pop     ecx
0x410e6a:       mov     dword ptr [0x420d2c], eax

It should always be the last "mov"
You can play with the TARGET_CODE variable if it doesn't work out
"""

import sys

try:
	import minidump
except:
	print "You need the minidump library"
	print "Download http://moyix.blogspot.com.au/2008/05/parsing-windows-minidumps.html"
	sys.exit()

try:
	from capstone import *
except:
	print "You need the capstone engine"
	sys.exit()

PAGEANT_NAME = 'pageant.exe'
TARGET_CODE = ['call','mov','mov','call','pop','mov']
#this one gives more false positives
#TARGET_CODE = ['call','pop','mov']


def is_exec(minidumpmemoryinfo):
	memprotect = minidumpmemoryinfo.Protect
	memtype = minidumpmemoryinfo.Type
	memallocationprotect = minidumpmemoryinfo.AllocationProtect
	if memprotect.PAGE_EXECUTE_READ and memtype.MEM_IMAGE and memallocationprotect.PAGE_EXECUTE_WRITECOPY:
		return True
	return False

def find_exec_region(meminfoliststream, offsetmin, offsetmax):
	for i in range(meminfoliststream.DirectoryData.NumberOfEntries):
		if is_exec(meminfoliststream.DirectoryData.MINIDUMP_MEMORY_INFO[i]):
			baseaddr = meminfoliststream.DirectoryData.MINIDUMP_MEMORY_INFO[i].BaseAddress
			if baseaddr >= offsetmin and baseaddr <= offsetmax:
				return meminfoliststream.DirectoryData.MINIDUMP_MEMORY_INFO[i]

def get_module_baseinfo(moduleliststream, modulename):
	for module in moduleliststream.DirectoryData.MINIDUMP_MODULE:
		if modulename in module.ModuleName.lower():
			return (module.BaseOfImage, (module.BaseOfImage+module.SizeOfImage))

def read_physical_chunk(filename, offset, size):
	with open(filename,'rb') as f:
		f.seek(offset)
		return f.read(size)

def get_code_location(mem64liststream, offset, size):
	totalsize = 0
	baserva = mem64liststream.DirectoryData.BaseRva
	mmdscrptr64 = mem64liststream.DirectoryData.MINIDUMP_MEMORY_DESCRIPTOR64
	numberofmemoryranges = mem64liststream.DirectoryData.NumberOfMemoryRanges
	for i in range(numberofmemoryranges):
		#FIXME: this is code that *might* need fixing
		#replace with range search if it doesn't work
		# offset >= memrange and offset <= memrange 
		if offset == mmdscrptr64[i].StartOfMemoryRange:
			return ((baserva+totalsize), mmdscrptr64[i].DataSize)
		totalsize +=  mmdscrptr64[i].DataSize

def extract_code_blob(filename, mem64liststream, offset, size):
	o,s = get_code_location(mem64liststream, offset, size)
	return read_physical_chunk(filename, o, s)


def find_target_code(fifo_data):
	for i, j in zip(fifo_data, TARGET_CODE):
		if i.mnemonic != j:
			return False
	return True

if __name__ == "__main__":
	if len(sys.argv) != 2:
		print "%s <dump_file>" % sys.argv[0]
		sys.exit()

	dumpfilename = sys.argv[1]
	f = open(dumpfilename,'rb')
	parsed_minidump = minidump.MINIDUMP_HEADER.parse_stream(f)
	f.close()
	for i in parsed_minidump.MINIDUMP_DIRECTORY:
		if i.StreamType == 'ModuleListStream':
			minidump_moduleliststream = i
		if i.StreamType == 'MemoryInfoListStream':
			minidump_memoryinfoliststream = i
		if i.StreamType == 'Memory64ListStream':
			minidump_memory64liststream = i
	
	modulemin, modulemax = get_module_baseinfo(minidump_moduleliststream,PAGEANT_NAME)
	print "module min %s" % hex(modulemin)
	print "module max %s" % hex(modulemax)

	module_code = find_exec_region(minidump_memoryinfoliststream, modulemin, modulemax)
	print "code start %s" % hex(module_code.BaseAddress)
	print "code region size %s" % hex(module_code.RegionSize)

	binary_code = extract_code_blob(dumpfilename, minidump_memory64liststream, module_code.BaseAddress, module_code.RegionSize)
	md = Cs(CS_ARCH_X86, CS_MODE_32)
	md.detail = True
	myfifo = list()
	for disasm_object in md.disasm(binary_code, module_code.BaseAddress):
		myfifo.append(disasm_object)
		if (len(myfifo) % len(TARGET_CODE)) == 0:
			if find_target_code(myfifo):
				print "found"
				for i in range(len(myfifo)):
					print "0x%x:\t%s\t%s" % (myfifo[i].address, myfifo[i].mnemonic, myfifo[i].op_str)
				print "==========="
				myfifo.pop(0)
			else:
				myfifo.pop(0)
#======================start root finder class========================================================
# not gonna work due to possibility of node with no children/parent and just elements
# kinda hard to validate that option :(
# feel free to improve and make it work, might work for the normal tree stuff
"""
class rootfinder:
	def __init__(self, mh_object):
		self.crashdump = mh_object.get_filename()
		self.mho = mh_object
		self.mem_start = self.mho.get_baserva()
		self.mem_size = (os.path.getsize(self.crashdump) - self.mem_start)

	def _search_node(self):
		chunksize = sizeof(node234)
		for i in range(self.mem_start,self.mem_size,4):
			progress = (i / self.mem_size) * 100
			if progress > 5:
				print "%s" % progress 
			data = self.mho._read_chunk(i, chunksize)
			mynode = node234.from_buffer_copy(data)
			#print mynode
			if self._verify_node(mynode):
				return self._walk_to_root(mynode)
	
	def _read_node(self, offset):
		memory_segment = self.mho.find_memoryentry(offset)
		memchunk = self.mho.get_chunkdata(memory_segment)
		memchunk_off = (offset - memory_segment)
		node_data = memchunk[memchunk_off:(memchunk_off+sizeof(node234))]
		return node234.from_buffer_copy(node_data)

	def __verify_parent(self, unknown_node):
		#print "Vrfy parent %s" % unknown_node
		try:
			parent_node = self._read_node(unknown_node.parent)
		except:
			return False

		if parent_node.parent == unknown_node.parent:
			return False

		for i in parent_node.kids:
			if i == unknown_node.parent:
				#print unknown_node
				#print parent_node
				#print ''
				return True
		return False		

	def __verify_children(self, unknown_node):
		count = 0
		#print "Vrfy child %s" % unknown_node
		for i in unknown_node.kids:
			count += i
			if i != 0:
				try:
					child_node = self._read_node(i)
				except:
					return False

				if not self.__verify_parent(child_node):
					return False
		if count == 0:
			return False
		return True

	def _verify_node(self, unknown_node):
		#generic node verification
		#We verify by:
		#	read child
		#		check child_parent is this node			
		#	read parent
		#		check parent_kids is this node
		if self.__verify_children(unknown_node):
			if unknown_node.parent == 0:
				#possible root node
				#we skip it to make it 'easier' for ourselfs
				return False
			else:
				return self.__verify_parent(unknown_node)
		return False

	def _walk_to_root(self, verified_node):
		#Walk parent until we find a zeroed parent
		print verified_node
		#while True:
		#	parent_node = self._read_node(verified_node.parent)
		
"""
#======================end root finder class==========================================================