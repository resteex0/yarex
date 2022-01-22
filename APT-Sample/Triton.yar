
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
		 date = "2022-01-22_17-57-14" 
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

		 $hex1= {246131303d20225452}
		 $hex2= {246131313d20225452}
		 $hex3= {246131323d20225452}
		 $hex4= {246131333d20225452}
		 $hex5= {246131343d20225452}
		 $hex6= {246131353d20225452}
		 $hex7= {246131363d20225452}
		 $hex8= {246131373d20225452}
		 $hex9= {246131383d20225452}
		 $hex10= {246131393d20225452}
		 $hex11= {2461313d2022545249}
		 $hex12= {246132303d20225452}
		 $hex13= {246132313d20225452}
		 $hex14= {246132323d20225452}
		 $hex15= {246132333d20225452}
		 $hex16= {246132343d20225452}
		 $hex17= {246132353d20225452}
		 $hex18= {246132363d20225452}
		 $hex19= {246132373d20225452}
		 $hex20= {246132383d20225452}
		 $hex21= {246132393d20225452}
		 $hex22= {2461323d2022545249}
		 $hex23= {246133303d20225452}
		 $hex24= {246133313d20225452}
		 $hex25= {246133323d20225452}
		 $hex26= {246133333d20225452}
		 $hex27= {246133343d20225452}
		 $hex28= {246133353d20225452}
		 $hex29= {246133363d20225452}
		 $hex30= {246133373d20225452}
		 $hex31= {246133383d20225452}
		 $hex32= {246133393d20225452}
		 $hex33= {2461333d2022545249}
		 $hex34= {246134303d20225452}
		 $hex35= {246134313d20225452}
		 $hex36= {246134323d20225452}
		 $hex37= {246134333d20225452}
		 $hex38= {246134343d20225452}
		 $hex39= {246134353d20225452}
		 $hex40= {246134363d20225452}
		 $hex41= {246134373d20225452}
		 $hex42= {246134383d20225452}
		 $hex43= {246134393d20225452}
		 $hex44= {2461343d2022545249}
		 $hex45= {246135303d20225452}
		 $hex46= {2461353d2022545249}
		 $hex47= {2461363d2022545249}
		 $hex48= {2461373d2022545249}
		 $hex49= {2461383d2022545249}
		 $hex50= {2461393d2022545249}

	condition:
		33 of them
}
