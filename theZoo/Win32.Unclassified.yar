
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Win32_Unclassified 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Win32_Unclassified {
	meta: 
		 description= "theZoo_Win32_Unclassified Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-37-01" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1c234a8879840da21f197b2608a164c9"

	strings:

	
 		 $s1= "System.Reflection.Assembly" fullword wide
		 $s2= "System.Security.Cryptography.RijndaelManaged" fullword wide
		 $s3= "System.Security.Cryptography.SymmetricAlgorithm" fullword wide

		 $hex1= {2473313d2022537973}
		 $hex2= {2473323d2022537973}
		 $hex3= {2473333d2022537973}

	condition:
		2 of them
}
