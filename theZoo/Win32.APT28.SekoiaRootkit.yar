
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_APT28_SekoiaRootkit 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_APT28_SekoiaRootkit {
	meta: 
		 description= "Win32_APT28_SekoiaRootkit Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-38-35" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "f8c8f6456c5a52ef24aa426e6b121685"

	strings:

	
 		 $s1= "??C:WindowsSystem32sysprepCRYPTBASE.dll" fullword wide
		 $s2= "FsFltParametersc1" fullword wide
		 $s3= "FsFltParametersc3" fullword wide
		 $a1= "??C:WindowsSystem32sysprepCRYPTBASE.dll" fullword ascii

		 $hex1= {2461313d20223f3f43}
		 $hex2= {2473313d20223f3f43}
		 $hex3= {2473323d2022467346}
		 $hex4= {2473333d2022467346}

	condition:
		1 of them
}
