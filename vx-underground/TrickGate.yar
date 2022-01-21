
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_TrickGate 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_TrickGate {
	meta: 
		 description= "vx_underground2_TrickGate Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-17-43" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "442f1e3d2825d51810bf9929f46439d2"
		 hash2= "6e49d82395b641a449c85bfa37dbbbc2"
		 hash3= "8da11d870336c1c32ba521fd62e6f55b"

	strings:

	
 		 $s1= "S-1-5-21-324232331-3064657245-3647568631-1001" fullword wide
		 $a1= "E0TBFVnuIO8kUNWtxKyf6am49vPAQJ/ZiH3p+bsYh7lwjo5rMXGLc1qd2SCRgDze" fullword ascii

		 $hex1= {2461313d2022453054}
		 $hex2= {2473313d2022532d31}

	condition:
		1 of them
}
