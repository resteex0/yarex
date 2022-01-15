
/*
   YARA Rule Set
   Author: resteex
   Identifier: SkypeWorm 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_SkypeWorm {
	meta: 
		 description= "SkypeWorm Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-18-45" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "4bdbb78ef4f1197929085619c0ba7619"
		 hash2= "94a261b4c1a4c47bdb3eb1f5dc16f91c"
		 hash3= "e05b14620ef6362a04965c4703d70563"
		 hash4= "f4038aed92ad1cc6c347daa01afe41d2"

	strings:

	
 		 $s1= "CryptProtectMemory failed" fullword wide
		 $s2= "CryptUnprotectMemory failed" fullword wide
		 $s3= "SeCreateSymbolicLinkPrivilege" fullword wide
		 $s4= "SoftwareMicrosoftWindowsCurrentVersion" fullword wide
		 $s5= "spanish-dominican republic" fullword wide
		 $s6= "__tmp_rar_sfx_access_check_%u" fullword wide

		 $hex1= {2473313d2022437279}
		 $hex2= {2473323d2022437279}
		 $hex3= {2473333d2022536543}
		 $hex4= {2473343d2022536f66}
		 $hex5= {2473353d2022737061}
		 $hex6= {2473363d20225f5f74}

	condition:
		4 of them
}
