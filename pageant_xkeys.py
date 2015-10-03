#!/usr/bin/env python
"""
DiabloHorn https://diablohorn.wordpress.com

List and export unencrypted SSH keys from a pageant minidump file
[x] Supported
[-] Not supported

[x] SSHv2 keys
    [x] RSA keys
    [x] DSA keys
[x] SSHv1 keys
    [x] RSA keys
[-] passphrases #short term only, not implementing

"""
import sys
import struct
import argparse
import hashlib
from ctypes import *

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
    print "pip install capstone"
    sys.exit()

try:
    from Crypto.PublicKey import RSA, DSA
    from Crypto.Util import asn1
except:
    print "You need the PyCrypto library"
    print "pip install pycrypto"
    sys.exit()

DEBUGPRINT = True

def dbgprint_line(selfobject):
    return "{*D*} [%s::%s]" % (selfobject.__class__.__name__, sys._getframe().f_back.f_code.co_name)
#====================================================================================================
#                                       start of structures
#====================================================================================================
class node234(Structure):
    """
        struct node234_Tag {
            node234 *parent;
            node234 *kids[4];
            int counts[4];
            void *elems[3];
        };
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
    """
        struct ssh_signkey {
            void *(*newkey) (char *data, int len);
            void (*freekey) (void *key);
            char *(*fmtkey) (void *key);
            unsigned char *(*public_blob) (void *key, int *len);
            unsigned char *(*private_blob) (void *key, int *len);
            void *(*createkey) (unsigned char *pub_blob, int pub_len,
                    unsigned char *priv_blob, int priv_len);
            void *(*openssh_createkey) (unsigned char **blob, int *len);
            int (*openssh_fmtkey) (void *key, unsigned char *blob, int len);
            int (*pubkey_bits) (void *blob, int len);
            char *(*fingerprint) (void *key);
            int (*verifysig) (void *key, char *sig, int siglen,
                      char *data, int datalen);
            unsigned char *(*sign) (void *key, char *data, int datalen,
                        int *siglen);
            char *name;
            char *keytype;             /* for host key cache */
        };    
    """
    _fields_ = [("fucn1",c_uint),("fucn2",c_uint),("fucn3",c_uint),("fucn4",c_uint),("fucn5",c_uint),
                ("fucn6",c_uint),("fucn7",c_uint),("fucn8",c_uint),("fucn9",c_uint),("fucn10",c_uint),
                ("fucn11",c_uint),("fucn12",c_uint),("name",c_uint),("keytype",c_uint)]

class ssh2_userkey(Structure):
    """
        struct ssh2_userkey {
            const struct ssh_signkey *alg;     /* the key algorithm */
            void *data;                /* the key data */
            char *comment;             /* the key comment */
        };    
    """
    _fields_ = [("ssh_signkey",c_uint),("data",c_uint),("comment",c_uint)]

class rsakey(Structure):
    """
        struct RSAKey {
            int bits;
            int bytes;
        #ifdef MSCRYPTOAPI
            unsigned long exponent;
            unsigned char *modulus;
        #else
            Bignum modulus;
            Bignum exponent;
            Bignum private_exponent;
            Bignum p;
            Bignum q;
            Bignum iqmp;
        #endif
            char *comment;
        };    
    """

    _fields_ = [("bits",c_uint),("bytes",c_uint),("modulus",c_uint),("exponent",c_uint),("private_exponent",c_uint),
                ("p",c_uint),("q",c_uint),("iqmp",c_uint),("comment",c_uint)]

class dsakey(Structure):
    """
        struct dss_key {
            Bignum p, q, g, y, x;
        };    
    """

    _fields_ = [("p",c_uint),("q",c_uint),("g",c_uint),("y",c_uint),("x",c_uint)]
#====================================================================================================
#                                       end of structures
#====================================================================================================
#                                       start of classes
#====================================================================================================
class minidump_helper:
    """helper class to perform minidump operations"""
    def __init__(self, filename):
        self.crashdump = self._open(filename)
        if not self.crashdump:
            return None
        self.crashdump_parsed = minidump.MINIDUMP_HEADER.parse_stream(self.crashdump)
        self._build_memorymap()


    def _open(self,filename):
        if DEBUGPRINT:
            print dbgprint_line(self) 
        filehandle = None
        try:
            filehandle = open(filename, 'rb')
        except:
            return None
        return filehandle

    def get_stream(self, streamname):
        for i in self.crashdump_parsed.MINIDUMP_DIRECTORY:            
            if i.StreamType == streamname:
                if DEBUGPRINT:
                    print "%s %s" % (dbgprint_line(self), i.StreamType)
                return i

    def _build_memorymap(self):
        if DEBUGPRINT:
            print dbgprint_line(self) 
        """
            In a MINIDUMP_MEMORY_DESCRIPTOR64 structure the BaseRva
            points to the start of all the memory ranges, which are 
            consecutive after each other
            virtual_offset_rangestart : (physical_offset_start, physical_size)
        """        
        memory64liststream = self.get_stream('Memory64ListStream')
        self.memorymap = {}
        totalsize = 0
        baserva = memory64liststream.DirectoryData.BaseRva
        mmdscrptr64 = memory64liststream.DirectoryData.MINIDUMP_MEMORY_DESCRIPTOR64
        numberofmemoryranges = memory64liststream.DirectoryData.NumberOfMemoryRanges
        for i in range(numberofmemoryranges):
            self.memorymap[mmdscrptr64[i].StartOfMemoryRange] = ((baserva + totalsize),mmdscrptr64[i].DataSize)
            totalsize += mmdscrptr64[i].DataSize

    def little2big(self, data):
        if DEBUGPRINT:
            print dbgprint_line(self) 
        return struct.unpack('=l',data)[0]

    def _read_chunk(self, physicaloffset, chunksize):
        #if DEBUGPRINT:
        #    print dbgprint_line(self) 
        self.crashdump.seek(physicaloffset)
        return self.crashdump.read(chunksize)

    def virtual2physical(self, virtualoffset):
        #if DEBUGPRINT:
        #    print dbgprint_line(self) 
        """
            get list of all virtual memory ranges
            find virtuall offset in corresponding memory range
            calculate relative_offset = (virtualoffset - memory range)
            check relative_offset not bigger than memory range sizeof
            return memory range physicaloffset + relative_offset
        """
        upperlimit = 0
        memlist = self.memorymap.keys()
        memlist.sort()
        for i in memlist:
            if virtualoffset >= i:
                if virtualoffset <= memlist[(memlist.index(i) + 1)]:
                    relative_virtualoffset = (virtualoffset - i)
                    if relative_virtualoffset > self.memorymap[i][1]:
                        return None
                    return self.memorymap[i][0] + relative_virtualoffset 
        return None

    def read_struct_object(self, virtualoffset, obj):
        if DEBUGPRINT:
            print dbgprint_line(self) 
        physicaloffset = self.virtual2physical(virtualoffset)
        if not physicaloffset:
            return None
        data = self._read_chunk(physicaloffset,sizeof(obj))
        return obj.from_buffer_copy(data)

    def read_int32(self, virtualoffset):
        if DEBUGPRINT:
            print dbgprint_line(self)      
        physicaloffset = self.virtual2physical(virtualoffset)
        if not physicaloffset:
            return None
        rawbytes = self._read_chunk(physicaloffset,4)
        return self.little2big(rawbytes)

    def read_string(self, virtualoffset):
        finalstring = ""
        physicaloffset = self.virtual2physical(virtualoffset)
        #heh this can and will break?, to lazy to factor this in
        data = self._read_chunk(physicaloffset, 100)
        for i in data:
            if ord(i) != 0:
                finalstring += i
            else:
                break
        return finalstring

    def read_hexstring32(self, virtualoffset, width=4):
        physicaloffset = self.virtual2physical(virtualoffset)
        data = self._read_chunk(physicaloffset,width)
        littleendian = struct.unpack('=L', data)[0]
        return '{:08x}'.format(littleendian)

    def read_bignum(self, virtualoffset):
        bignum = list()
        bignum_size = self.read_int32(virtualoffset)
        for i in range(bignum_size):
            virtualoffset = virtualoffset + 4
            bignum.append(self.read_hexstring32(virtualoffset))
        bignum.reverse()
        return long((''.join(map(str, bignum))),16)

class find_offsets:

    def __init__(self, mh_object):
        self.mh = mh_object
        self.modulename = 'pageant.exe'
        self.target_code = ['call','mov','mov','call','pop','mov']

    def _module_base_info(self):
        if DEBUGPRINT:
            print dbgprint_line(self) 
        """Get the base address (start offset) of the module and the end offset"""
        moduleliststream = self.mh.get_stream('ModuleListStream')
        for module in moduleliststream.DirectoryData.MINIDUMP_MODULE:
            if self.modulename in module.ModuleName.lower():
                return (module.BaseOfImage, (module.BaseOfImage+module.SizeOfImage))

    def _is_exec(self, minidumpmemoryinfo):
        #if DEBUGPRINT:
        #    print dbgprint_line(self)         
        memprotect = minidumpmemoryinfo.Protect
        memtype = minidumpmemoryinfo.Type
        memallocationprotect = minidumpmemoryinfo.AllocationProtect
        if memprotect.PAGE_EXECUTE_READ and memtype.MEM_IMAGE and memallocationprotect.PAGE_EXECUTE_WRITECOPY:
            return True
        return False

    def find_exec_region(self, offsetmin, offsetmax):
        if DEBUGPRINT:
            print dbgprint_line(self) 
        meminfoliststream = self.mh.get_stream('MemoryInfoListStream')
        for i in range(meminfoliststream.DirectoryData.NumberOfEntries):
            if self._is_exec(meminfoliststream.DirectoryData.MINIDUMP_MEMORY_INFO[i]):
                baseaddr = meminfoliststream.DirectoryData.MINIDUMP_MEMORY_INFO[i].BaseAddress
                if baseaddr >= offsetmin and baseaddr <= offsetmax:
                    return meminfoliststream.DirectoryData.MINIDUMP_MEMORY_INFO[i]

    def find_target_code(self, fifo_data):
        #if DEBUGPRINT:
        #    print dbgprint_line(self) 
        for i, j in zip(fifo_data, self.target_code):
            if i.mnemonic != j:
                return False
        return True

    def blob2asm(self, binary_code, baseaddr):
        if DEBUGPRINT:
            print dbgprint_line(self)       
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True
        myfifo = list()
        for disasm_object in md.disasm(binary_code, baseaddr):
            myfifo.append(disasm_object)
            if len(myfifo) == len(self.target_code):
                if self.find_target_code(myfifo):
                    if DEBUGPRINT:
                        for i in range(len(myfifo)):
                            print "%s 0x%x: %s %s" % (dbgprint_line(self), myfifo[i].address, myfifo[i].mnemonic, myfifo[i].op_str)
                    return myfifo
                else:
                    myfifo.pop(0)

    def get_sshv1(self):
        if DEBUGPRINT:
            print dbgprint_line(self) 
        startoffset, endoffset = self._module_base_info()
        codeblock_info = self.find_exec_region(startoffset,endoffset)
        physicaloffset = self.mh.virtual2physical(codeblock_info.BaseAddress)
        codeblob = self.mh._read_chunk(physicaloffset, codeblock_info.RegionSize)
        asmblock = self.blob2asm(codeblob, codeblock_info.BaseAddress)
        return asmblock[1].operands[0].value.mem.disp

    def get_sshv2(self):
        if DEBUGPRINT:
            print dbgprint_line(self) 
        startoffset, endoffset = self._module_base_info()
        codeblock_info = self.find_exec_region(startoffset,endoffset)
        physicaloffset = self.mh.virtual2physical(codeblock_info.BaseAddress)
        codeblob = self.mh._read_chunk(physicaloffset, codeblock_info.RegionSize)
        asmblock = self.blob2asm(codeblob, codeblock_info.BaseAddress)
        return asmblock[5].operands[0].value.mem.disp

class tree234_helper:
    """helper class to perform tree operatoins"""
    def __init__(self, rootnode_offset, mh_object):
        self.mh = mh_object
        self.root = self.mh.read_struct_object(rootnode_offset, node234)
        self.elements = list()

    def walk(self, node):
        if DEBUGPRINT:
            print dbgprint_line(self)
        if node:
            childcount = node.count_kids()
            elementcount = node.count_elements()
            if elementcount != 0:
                self.elements.append(node.elements)

            if childcount != 0:
                for i in range(childcount):
                    self.walk(self.mh.read_struct_object(node.kids[i], node234))
        
        return self.elements

class pageant_keys:
    """class that extract the key information from the dump"""

    def __init__(self, arguments):
        self.mh = minidump_helper(arguments.dumpfile)

        if not self.mh:
            return None

        self.offsetfinder = find_offsets(self.mh)

    def create_privatekey_rsa(self, rsakey_object):
        modulus = self.mh.read_bignum(rsakey_object.modulus)
        exponent = self.mh.read_bignum(rsakey_object.exponent)
        private_exponent = self.mh.read_bignum(rsakey_object.private_exponent)
        rawkey = (modulus,exponent,private_exponent)
        #construct the desired RSA key
        rsakey = RSA.construct(rawkey)
        #print the object, publickey, privatekey
        return rsakey

    def create_privatekey_dsa_pem(self, dsakey_object):
        """
            http://stackoverflow.com/questions/5938664/how-to-generate-the-pem-serialization-for-the-public-rsa-dsa-key
        """
        dsa_p = self.mh.read_bignum(dsakey_object.p)
        dsa_q = self.mh.read_bignum(dsakey_object.q)
        dsa_g = self.mh.read_bignum(dsakey_object.g)
        dsa_y = self.mh.read_bignum(dsakey_object.y)
        dsa_x = self.mh.read_bignum(dsakey_object.x)
        rawkey = (dsa_y,dsa_g,dsa_p,dsa_q,dsa_x)
        dsakey = DSA.construct(rawkey)
        seq = asn1.DerSequence()
        seq[:] = [ 0, dsakey.p, dsakey.q, dsakey.g, dsakey.y, dsakey.x ]
        exported_key = "-----BEGIN DSA PRIVATE KEY-----\n%s-----END DSA PRIVATE KEY-----" % seq.encode().encode("base64")
        return exported_key


    def _export_sshv1(self):
        res = list()
        if DEBUGPRINT:
            print dbgprint_line(self)       
        first_resolve = self.mh.read_int32(self.offsetfinder.get_sshv1())
        tree_root = self.mh.read_int32(first_resolve)
        key_tree = tree234_helper(tree_root, self.mh)
        tree_elements = key_tree.walk(key_tree.root)        
        for element in tree_elements:
            for i in element:
                if i != 0:
                    obj_rsakey = self.mh.read_struct_object(i,rsakey)
                    final_rsakey = self.create_privatekey_rsa(obj_rsakey)
                    res.append(final_rsakey.exportKey('PEM'))
        return res

    def _export_sshv2(self):
        res = list()

        if DEBUGPRINT:
            print dbgprint_line(self)
        first_resolve = self.mh.read_int32(self.offsetfinder.get_sshv2())
        tree_root = self.mh.read_int32(first_resolve)
        key_tree = tree234_helper(tree_root, self.mh)
        tree_elements = key_tree.walk(key_tree.root)
        for element in tree_elements:
            for i in element:
                if i != 0: #todo modulus.bit_length()
                    obj_ssh2usrkey = self.mh.read_struct_object(i,ssh2_userkey)
                    obj_signkey = self.mh.read_struct_object(obj_ssh2usrkey.ssh_signkey,ssh_signkey)
                    xkeytype = self.mh.read_string(obj_signkey.keytype)
                    if xkeytype == 'rsa2':
                        obj_rsakey = self.mh.read_struct_object(obj_ssh2usrkey.data,rsakey)
                        final_rsakey = self.create_privatekey_rsa(obj_rsakey)
                        res.append(final_rsakey.exportKey('PEM'))
                    elif xkeytype == 'dss':
                        obj_dsakey = self.mh.read_struct_object(obj_ssh2usrkey.data,dsakey)
                        final_dsakey = self.create_privatekey_dsa_pem(obj_dsakey)
                        res.append(final_dsakey)

        return res

    def export_keys(self):
        if DEBUGPRINT:
            print dbgprint_line(self)
        allkeys = self._export_sshv1()
        allkeys.extend(self._export_sshv2())
        for i in range(len(allkeys)):
            filename = "%s.txt" % i
            with open(filename,'w') as f:
                f.write(allkeys[i])

    def _list_sshv1(self):
        res = list()
        if DEBUGPRINT:
            print dbgprint_line(self)       
        first_resolve = self.mh.read_int32(self.offsetfinder.get_sshv1())
        tree_root = self.mh.read_int32(first_resolve)
        key_tree = tree234_helper(tree_root, self.mh)
        tree_elements = key_tree.walk(key_tree.root)        
        for element in tree_elements:
            for i in element:
                if i != 0:
                    obj_rsakey = self.mh.read_struct_object(i,rsakey)
                    xkeycomment = self.mh.read_string(obj_rsakey.comment)
                    res.append(("       ", "rsa1", xkeycomment))
        return res

    def _list_sshv2(self):
        res = list()

        if DEBUGPRINT:
            print dbgprint_line(self)
        first_resolve = self.mh.read_int32(self.offsetfinder.get_sshv2())
        tree_root = self.mh.read_int32(first_resolve)
        key_tree = tree234_helper(tree_root, self.mh)
        tree_elements = key_tree.walk(key_tree.root)
        for element in tree_elements:
            for i in element:
                if i != 0: #todo modulus.bit_length()
                    obj_ssh2usrkey = self.mh.read_struct_object(i,ssh2_userkey)
                    obj_rsakey = self.mh.read_struct_object(obj_ssh2usrkey.data,rsakey)
                    obj_signkey = self.mh.read_struct_object(obj_ssh2usrkey.ssh_signkey,ssh_signkey)
                    xkeyname = self.mh.read_string(obj_signkey.name)
                    xkeytype = self.mh.read_string(obj_signkey.keytype)
                    xkeycomment = self.mh.read_string(obj_ssh2usrkey.comment)
                    res.append((xkeyname, xkeytype, xkeycomment))
        return res


    def list_keys(self):
        if DEBUGPRINT:
            print dbgprint_line(self)
        allkeys = self._list_sshv1()
        allkeys.extend(self._list_sshv2())
        for i in allkeys:
            print "%s %s %s" % i
        pass
#====================================================================================================
#                                       end of classes
#====================================================================================================

def hexint(data):
    """self defined to handle hex string on commandline"""
    return int(data,16)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()        
    parser.add_argument("dumpfile", help="minidump file containing the pageant process memory")
    parser.add_argument("--listkeys", action="store_true", help="List the available keys")
    args = parser.parse_args()

    pk = pageant_keys(args)
    
    if args.listkeys:
        pk.list_keys()
        sys.exit()

    pk.export_keys()