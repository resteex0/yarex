
/*
   YARA Rule Set
   Author: resteex
   Identifier: Gauss 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Gauss {
	meta: 
		 description= "Gauss Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_11-05-25" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "08d7ddb11e16b86544e0c3e677a60e10"
		 hash2= "23d956c297c67d94f591fcb574d9325f"
		 hash3= "4fb4d2eb303160c5f419cec2e9f57850"
		 hash4= "9ca4a49135bccdb09931cf0dbe25b5a9"
		 hash5= "c3b8ad4eca93114947c777b19d3c6059"
		 hash6= "cbb982032aed60b133225a2715d94458"
		 hash7= "de2d0d6c340c75eb415f726338835125"
		 hash8= "e379270f53ba148d333134011aa3600c"
		 hash9= "ed2b439708f204666370337af2a9e18f"
		 hash10= "ed5559b0c554055380d75c1d7f9c4424"
		 hash11= "ef83394d9600f6d2808e0e99b5f932ca"
		 hash12= "fa54a8d31e1434539fbb9a412f4d32ff"

	strings:

	
 		 $a1= "cwwZZwwZZwwZZwwZZwwZZwwZZwwZZwwZZwwZZwwZZwwZZwwZZwwZZwwAA))PPaa" fullword ascii
		 $a2= "rswvvr0001>887STT[oiifT_/.!''(LKKDpvvyK@015440rrrsy}}wCEEO}{" fullword ascii
		 $a3= "Y." fullword ascii

		 $hex1= {2461313d2022637777}
		 $hex2= {2461323d2022727377}
		 $hex3= {2461333d2022592220}

	condition:
		1 of them
}
