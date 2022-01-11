
/*
   YARA Rule Set
   Author: resteex
   Identifier: Nitlove 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Nitlove {
	meta: 
		 description= "Nitlove Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-26-50" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "b3962f61a4819593233aa5893421c4d1"

	strings:

	
 		 $s1= "(C) 2007-2014 TeamSpeak Systems GmbH" fullword wide
		 $s2= "FileDescription" fullword wide
		 $s3= "TeamSpeak 3 Client Updater" fullword wide
		 $s4= "TeamSpeak Systems GmbH" fullword wide
		 $s5= "VS_VERSION_INFO" fullword wide
		 $a1= "abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a2= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" fullword ascii
		 $a3= "GetUserObjectInformationA" fullword ascii
		 $a4= "GetUserObjectInformationW" fullword ascii
		 $a5= "InitializeCriticalSectionAndSpinCount" fullword ascii
		 $a6= "JanFebMarAprMayJunJulAugSepOctNovDec" fullword ascii
		 $a7= "SetProcessShutdownParameters" fullword ascii
		 $a8= "SetUnhandledExceptionFilter" fullword ascii
		 $a9= "WTSGetActiveConsoleSessionId" fullword ascii

		 $hex1= {2461313d2022616263}
		 $hex2= {2461323d2022414243}
		 $hex3= {2461333d2022476574}
		 $hex4= {2461343d2022476574}
		 $hex5= {2461353d2022496e69}
		 $hex6= {2461363d20224a616e}
		 $hex7= {2461373d2022536574}
		 $hex8= {2461383d2022536574}
		 $hex9= {2461393d2022575453}
		 $hex10= {2473313d2022284329}
		 $hex11= {2473323d202246696c}
		 $hex12= {2473333d2022546561}
		 $hex13= {2473343d2022546561}
		 $hex14= {2473353d202256535f}

	condition:
		1 of them
}
