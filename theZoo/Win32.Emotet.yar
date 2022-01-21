
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Win32_Emotet 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Win32_Emotet {
	meta: 
		 description= "theZoo_Win32_Emotet Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-36-26" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8baa9b809b591a11af423824f4d9726a"

	strings:

	
 		 $s1= "57576736879580478257258376974939" fullword wide
		 $s2= "Remounter (2)RemounterVeladonACCOJ.vbp" fullword wide

		 $hex1= {2473313d2022353735}
		 $hex2= {2473323d202252656d}

	condition:
		1 of them
}
