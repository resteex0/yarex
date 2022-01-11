
/*
   YARA Rule Set
   Author: resteex
   Identifier: W32_Nimda_A 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W32_Nimda_A {
	meta: 
		 description= "W32_Nimda_A Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-31-17" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "06f46062e7d56457252a9a3e3a73405a"
		 hash2= "087b30cdde1487f4f90abd2659edd19d"
		 hash3= "36d433dc87fdbffababde57ef3c3c130"
		 hash4= "79e362c5ba84ad7722d133c2a348c52b"
		 hash5= "844855b2ec58f20718cff30d874ab43e"
		 hash6= "a2b2a4df2fe6a1d85e9032e3e50b365f"

	strings:

	
 		 $s1= "_VBA_PROJECT_CUR" fullword wide
		 $a1= "*******************************************************" fullword ascii
		 $a2= "***************************************************************************" fullword ascii
		 $a3= "---------------------------------------------------------------------" fullword ascii
		 $a4= "=====================================================================" fullword ascii
		 $a5= "header-stop-viruses.gifPK" fullword ascii
		 $a6= "investor_relations.gifGIF89a" fullword ascii
		 $a7= "JanFebMarAprMayJunJulAugSepOctNovDec" fullword ascii
		 $a8= "SetUnhandledExceptionFilter" fullword ascii
		 $a9= "WritePrivateProfileStringA" fullword ascii

		 $hex1= {2461313d2022303436}
		 $hex2= {2461323d2022303436}
		 $hex3= {2461333d20222d2d2d}
		 $hex4= {2461343d20223d3d3d}
		 $hex5= {2461353d2022686561}
		 $hex6= {2461363d2022696e76}
		 $hex7= {2461373d20224a616e}
		 $hex8= {2461383d2022536574}
		 $hex9= {2461393d2022577269}
		 $hex10= {2473313d20225f5642}

	condition:
		1 of them
}
