
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win64_Trojan_GreenBug 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win64_Trojan_GreenBug {
	meta: 
		 description= "Win64_Trojan_GreenBug Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_22-52-50" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "786e61331a1e84b7fe26c254de0280ad"

	strings:

	
 		 $s1= "MicrosoftWindowsCRMFiles" fullword wide
		 $s2= "MicrosoftwindowsTmp98871" fullword wide
		 $s3= "MicrosoftWindowsTmp9932u1.bat" fullword wide
		 $s4= "MicrosoftWindowsTmpFiles" fullword wide
		 $s5= "MicrosoftWindowsTmpFiles" fullword wide
		 $s6= "MicrosoftWindowsTmpFiles" fullword wide
		 $s7= "spanish-dominican republic" fullword wide

		 $hex1= {2473313d20224d6963}
		 $hex2= {2473323d20224d6963}
		 $hex3= {2473333d20224d6963}
		 $hex4= {2473343d20224d6963}
		 $hex5= {2473353d20224d6963}
		 $hex6= {2473363d20224d6963}
		 $hex7= {2473373d2022737061}

	condition:
		4 of them
}
