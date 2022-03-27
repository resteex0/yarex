
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
		 date = "2022-03-27_09-25-21" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "4e5797312ed52d9eb80ec19848cadc95"
		 hash2= "d259dc2a015734cdb39df2c0dd2a5ab5"

	strings:

	
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
		 $a1= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/_abcoll.pyUT" fullword ascii
		 $a20= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/inspect.pyUT" fullword ascii
		 $a21= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/keyword.pyUT" fullword ascii
		 $a22= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/locale.pyUT" fullword ascii
		 $a23= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/logging/UT" fullword ascii
		 $a24= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/ntpath.pyUT" fullword ascii
		 $a25= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/opcode.pyUT" fullword ascii
		 $a26= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/pdb.pyUT" fullword ascii
		 $a27= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/pickle.pyUT" fullword ascii
		 $a28= "TRISIS-TRITON-HATMAN-master/decompiled_code/library/pprint.pyUT" fullword ascii

		 $hex1= {54??52??49??53??49??53??2d??54??52??49??54??4f??4e??2d??48??41??54??4d??41??4e??2d??6d??61??73??74??65??72??2f??64??65??}

	condition:
		11 of them
}
