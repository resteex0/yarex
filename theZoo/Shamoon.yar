
/*
   YARA Rule Set
   Author: resteex
   Identifier: Shamoon 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Shamoon {
	meta: 
		 description= "Shamoon Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-37-59" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "b14299fd4d1cbfb4cc7486d978398214"
		 hash2= "d214c717a357fe3a455610b197c390aa"

	strings:

	
 		 $s1= "5.2.3790.0 (srv03_rtm.030324-2048)" fullword wide
		 $s2= "FileDescription" fullword wide
		 $s3= "infnetft429.pnf" fullword wide
		 $s4= "@LanmanWorkstation" fullword wide
		 $s5= "Microsoft Corporation" fullword wide
		 $s6= "OriginalFilename" fullword wide
		 $s7= "PROCESSOR_ARCHITECTURE" fullword wide
		 $s8= "system32csrss.exe" fullword wide
		 $s9= "system32kernel32.dll" fullword wide
		 $s10= "SYSTEMCurrentControlSetControlSession ManagerEnvironment" fullword wide
		 $s11= "SYSTEMCurrentControlSetServicesTrkSvr" fullword wide
		 $s12= "VS_VERSION_INFO" fullword wide
		 $a1= "SYSTEMCurrentControlSetControlSession ManagerEnvironment" fullword ascii
		 $a2= "SYSTEMCurrentControlSetServicesTrkSvr" fullword ascii

		 $hex1= {2461313d2022535953}
		 $hex2= {2461323d2022535953}
		 $hex3= {247331303d20225359}
		 $hex4= {247331313d20225359}
		 $hex5= {247331323d20225653}
		 $hex6= {2473313d2022352e32}
		 $hex7= {2473323d202246696c}
		 $hex8= {2473333d2022696e66}
		 $hex9= {2473343d2022404c61}
		 $hex10= {2473353d20224d6963}
		 $hex11= {2473363d20224f7269}
		 $hex12= {2473373d202250524f}
		 $hex13= {2473383d2022737973}
		 $hex14= {2473393d2022737973}

	condition:
		4 of them
}
