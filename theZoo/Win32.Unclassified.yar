
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Unclassified 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Unclassified {
	meta: 
		 description= "Win32_Unclassified Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-55-14" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1c234a8879840da21f197b2608a164c9"

	strings:

	
 		 $s1= "Assembly Version" fullword wide
		 $s2= "FileDescription" fullword wide
		 $s3= "OriginalFilename" fullword wide
		 $s4= "System.Reflection.Assembly" fullword wide
		 $s5= "System.Security.Cryptography.RijndaelManaged" fullword wide
		 $s6= "System.Security.Cryptography.SymmetricAlgorithm" fullword wide
		 $s7= "TransformFinalBlock" fullword wide
		 $s8= "VS_VERSION_INFO" fullword wide
		 $a1= "System.Security.Cryptography.RijndaelManaged" fullword ascii
		 $a2= "System.Security.Cryptography.SymmetricAlgorithm" fullword ascii

		 $hex1= {2461313d2022537973}
		 $hex2= {2461323d2022537973}
		 $hex3= {2473313d2022417373}
		 $hex4= {2473323d202246696c}
		 $hex5= {2473333d20224f7269}
		 $hex6= {2473343d2022537973}
		 $hex7= {2473353d2022537973}
		 $hex8= {2473363d2022537973}
		 $hex9= {2473373d2022547261}
		 $hex10= {2473383d202256535f}

	condition:
		1 of them
}
