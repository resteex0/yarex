
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Werdlod 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Werdlod {
	meta: 
		 description= "vx_underground2_Werdlod Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-17-56" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0f2830c242ad43268ef1165b020dc2ef"
		 hash2= "221a1377ccd41553b16ba2a09546683c"
		 hash3= "3db100e20ef6741bd4d1ef2efe3a75aa"
		 hash4= "749b30a0650bc39ed09d0cd775a97c3d"
		 hash5= "accbe79ecfe8275457001a45f30a44fb"
		 hash6= "e13aabaa3a6357d215f9620315fc047f"

	strings:

	
 		 $a1= "lkRTCLVX_]11gnF]DQa_X45ogFMWRP]T125jhBa@WUY0859lnRU]R^5jhPa@QP" fullword ascii
		 $a2= "pYWZWTWVPXX^YZoCEFFDMCNKHKjdlljUVPcWQRRXQ_R__^H@@FABDwKMNNLEKF" fullword ascii

		 $hex1= {2461313d20226c6b52}
		 $hex2= {2461323d2022705957}

	condition:
		1 of them
}
