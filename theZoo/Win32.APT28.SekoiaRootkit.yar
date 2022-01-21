
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Win32_APT28_SekoiaRootkit 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Win32_APT28_SekoiaRootkit {
	meta: 
		 description= "theZoo_Win32_APT28_SekoiaRootkit Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-36-14" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "f8c8f6456c5a52ef24aa426e6b121685"

	strings:

	
 		 $s1= "??C:WindowsSystem32sysprepCRYPTBASE.dll" fullword wide
		 $a1= "d:!worketchideinstaller_kis2013BinDebugwin7x64fsflt.pdb" fullword ascii

		 $hex1= {2461313d2022643a21}
		 $hex2= {2473313d20223f3f43}

	condition:
		1 of them
}
