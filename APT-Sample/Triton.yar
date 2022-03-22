
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_Triton 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_Triton {
	meta: 
		 description= "APT_Sample_Triton Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-22_12-23-13" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "4e5797312ed52d9eb80ec19848cadc95"
		 hash2= "d259dc2a015734cdb39df2c0dd2a5ab5"

	strings:

	
 		 $a1= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/_abcoll.pyUT" fullword ascii
		 $a2= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/abc.pyUT" fullword ascii
		 $a3= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/atexit.pyUT" fullword ascii
		 $a4= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/base64.pyUT" fullword ascii
		 $a5= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/bdb.pyUT" fullword ascii
		 $a6= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/bz2.pyUT" fullword ascii
		 $a7= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/cmd.pyUT" fullword ascii
		 $a8= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/codecs.pyUT" fullword ascii
		 $a9= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/copy.pyUT" fullword ascii
		 $a10= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/crc.pyUT" fullword ascii
		 $a11= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/difflib.pyUT" fullword ascii
		 $a12= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/dis.pyUT" fullword ascii
		 $a13= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/doctest.pyUT" fullword ascii
		 $a14= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/encodings/UT" fullword ascii
		 $a15= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/fnmatch.pyUT" fullword ascii
		 $a16= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/getopt.pyUT" fullword ascii
		 $a17= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/gettext.pyUT" fullword ascii
		 $a18= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/hashlib.pyUT" fullword ascii
		 $a19= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/heapq.pyUT" fullword ascii
		 $a20= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/inspect.pyUT" fullword ascii
		 $a21= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/keyword.pyUT" fullword ascii
		 $a22= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/locale.pyUT" fullword ascii
		 $a23= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/logging/UT" fullword ascii
		 $a24= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/ntpath.pyUT" fullword ascii
		 $a25= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/opcode.pyUT" fullword ascii
		 $a26= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/pdb.pyUT" fullword ascii
		 $a27= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/pickle.pyUT" fullword ascii
		 $a28= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/pprint.pyUT" fullword ascii
		 $a29= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/quopri.pyUT" fullword ascii
		 $a30= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/random.pyUT" fullword ascii
		 $a31= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/repr.pyUT" fullword ascii
		 $a32= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/select.pyUT" fullword ascii
		 $a33= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/shlex.pyUT" fullword ascii
		 $a34= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/_socket.pyUT" fullword ascii
		 $a35= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/socket.pyUT" fullword ascii
		 $a36= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/sre.pyUT" fullword ascii
		 $a37= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/_ssl.pyUT" fullword ascii
		 $a38= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/ssl.pyUT" fullword ascii
		 $a39= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/stat.pyUT" fullword ascii
		 $a40= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/string.pyUT" fullword ascii
		 $a41= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/struct.pyUT" fullword ascii
		 $a42= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/token.pyUT" fullword ascii
		 $a43= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/TsBase.pyUT" fullword ascii
		 $a44= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/TsHi.pyUT" fullword ascii
		 $a45= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/TsLow.pyUT" fullword ascii
		 $a46= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/types.pyUT" fullword ascii
		 $a47= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/unittest/UT" fullword ascii
		 $a48= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/weakref.pyUT" fullword ascii
		 $a49= "TRISIS-TRITON-HATMAN-master/decompiled_code/script_test.pyUT" fullword ascii
		 $a50= "TRISIS-TRITON-HATMAN-master/symbolic_execution/TritonFull.pyUT" fullword ascii

		 $hex1= {5452495349532d5452}

	condition:
		5 of them
}
