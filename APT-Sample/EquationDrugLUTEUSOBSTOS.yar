
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_EquationDrugLUTEUSOBSTOS 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_EquationDrugLUTEUSOBSTOS {
	meta: 
		 description= "APT_Sample_EquationDrugLUTEUSOBSTOS Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-29_06-37-04" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "4556ce5eb007af1de5bd3b457f0b216d"

	strings:

	
 		 $s1= "CcnFormSyncExFBC" fullword wide
		 $s2= "system32win32k.sys" fullword wide

		 $hex1= {43??63??6e??46??6f??72??6d??53??79??6e??63??45??78??46??42??43??0a??}
		 $hex2= {73??79??73??74??65??6d??33??32??77??69??6e??33??32??6b??2e??73??79??73??0a??}

	condition:
		2 of them
}
