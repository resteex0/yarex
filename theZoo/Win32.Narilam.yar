
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Narilam 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Narilam {
	meta: 
		 description= "Win32_Narilam Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-54-56" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8e63c306e95843eccab53dad31b3a98b"

	strings:

	
 		 $s1= "Assertion failed" fullword wide
		 $s2= "August September" fullword wide
		 $s3= "FileDescription" fullword wide
		 $s4= "Invalid argument" fullword wide
		 $s5= "Invalid filename" fullword wide
		 $s6= "Invalid ImageList" fullword wide
		 $s7= "ISAUTOINCREMENT" fullword wide
		 $s8= "LegalTrademarks" fullword wide
		 $s9= "Microsoft Corporation" fullword wide
		 $s10= "OriginalFilename" fullword wide
		 $s11= "Privileged instruction" fullword wide
		 $s12= "RDSServer.DataFactory" fullword wide
		 $s13= "Tuesday Wednesday" fullword wide
		 $s14= "Untitled Application" fullword wide
		 $s15= "Variant overflow" fullword wide
		 $s16= "VS_VERSION_INFO" fullword wide

		 $hex1= {247331303d20224f72}
		 $hex2= {247331313d20225072}
		 $hex3= {247331323d20225244}
		 $hex4= {247331333d20225475}
		 $hex5= {247331343d2022556e}
		 $hex6= {247331353d20225661}
		 $hex7= {247331363d20225653}
		 $hex8= {2473313d2022417373}
		 $hex9= {2473323d2022417567}
		 $hex10= {2473333d202246696c}
		 $hex11= {2473343d2022496e76}
		 $hex12= {2473353d2022496e76}
		 $hex13= {2473363d2022496e76}
		 $hex14= {2473373d2022495341}
		 $hex15= {2473383d20224c6567}
		 $hex16= {2473393d20224d6963}

	condition:
		2 of them
}
