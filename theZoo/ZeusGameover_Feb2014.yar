
/*
   YARA Rule Set
   Author: resteex
   Identifier: ZeusGameover_Feb2014 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_ZeusGameover_Feb2014 {
	meta: 
		 description= "ZeusGameover_Feb2014 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-39-41" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "19c68862d3a53ea1746180b40bf32226"
		 hash2= "7bc463a32d6c0fb888cd76cc07ee69b5"
		 hash3= "7fe11cfcd7c66f7727cfc4613e755389"
		 hash4= "b227e7c0d9995715f331592750d6ebc2"

	strings:

	
 		 $s1= "2q3wet Corporation" fullword wide
		 $s2= "AVarFileInfoTranslation" fullword wide
		 $s3= "CiceroUIWndFrame" fullword wide
		 $s4= "ConsoleWindowClass" fullword wide
		 $s5= "CSeTcbPrivilege" fullword wide
		 $s6= "DavesFrameClass" fullword wide
		 $s7= "FileDescription" fullword wide
		 $s8= "Gsystem32cGcript.Gxe" fullword wide
		 $s9= "OriginalFilename" fullword wide
		 $s10= "ProfileImagePath" fullword wide
		 $s11= "&Select Columns..." fullword wide
		 $s12= "SeSecurityPrivilege" fullword wide
		 $s13= "SeShutdownPrivilege" fullword wide
		 $s14= "Set &Affinity..." fullword wide
		 $s15= "S:(ML;CIOI;NRNWNX;;;LW)" fullword wide
		 $s16= "S:(ML;;NRNWNX;;;LW)" fullword wide
		 $s17= "SOFTWAREMicrosoftWindows NTCurrentVersionProfileList%s" fullword wide
		 $s18= "StringFileInfo%04x%04x%s" fullword wide
		 $s19= "SysTabControl32" fullword wide
		 $s20= "Tile &Horizontally" fullword wide
		 $s21= "Tile &Vertically" fullword wide
		 $s22= "VS_VERSION_INFO" fullword wide
		 $s23= "Windows TaskManager" fullword wide
		 $a1= "SOFTWAREMicrosoftWindows NTCurrentVersionProfileList%s" fullword ascii

		 $hex1= {2461313d2022534f46}
		 $hex2= {247331303d20225072}
		 $hex3= {247331313d20222653}
		 $hex4= {247331323d20225365}
		 $hex5= {247331333d20225365}
		 $hex6= {247331343d20225365}
		 $hex7= {247331353d2022533a}
		 $hex8= {247331363d2022533a}
		 $hex9= {247331373d2022534f}
		 $hex10= {247331383d20225374}
		 $hex11= {247331393d20225379}
		 $hex12= {2473313d2022327133}
		 $hex13= {247332303d20225469}
		 $hex14= {247332313d20225469}
		 $hex15= {247332323d20225653}
		 $hex16= {247332333d20225769}
		 $hex17= {2473323d2022415661}
		 $hex18= {2473333d2022436963}
		 $hex19= {2473343d2022436f6e}
		 $hex20= {2473353d2022435365}
		 $hex21= {2473363d2022446176}
		 $hex22= {2473373d202246696c}
		 $hex23= {2473383d2022477379}
		 $hex24= {2473393d20224f7269}

	condition:
		8 of them
}
