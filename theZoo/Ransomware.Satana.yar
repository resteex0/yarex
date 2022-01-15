
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Satana 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Satana {
	meta: 
		 description= "Ransomware_Satana Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-37-52" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "108756f41d114eb93e136ba2feb838d0"
		 hash2= "46bfd4f1d581d7c0121d2b19a005d3df"

	strings:

	
 		 $s1= "MicrosoftWindows" fullword wide
		 $s2= "%PROCESSOR_ARCHITECTURE%" fullword wide
		 $s3= "%PROCESSOR_IDENTIFIER%" fullword wide
		 $s4= "%PROCESSOR_LEVEL%" fullword wide
		 $s5= "%PROCESSOR_REVISION%" fullword wide
		 $s6= "%sVSSADMIN.EXE" fullword wide

		 $hex1= {2473313d20224d6963}
		 $hex2= {2473323d2022255052}
		 $hex3= {2473333d2022255052}
		 $hex4= {2473343d2022255052}
		 $hex5= {2473353d2022255052}
		 $hex6= {2473363d2022257356}

	condition:
		2 of them
}
