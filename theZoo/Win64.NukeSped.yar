
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win64_NukeSped 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win64_NukeSped {
	meta: 
		 description= "Win64_NukeSped Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-39-31" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "379d680a2accaa48444524968d1aa782"
		 hash2= "cebc3a9192d6b516e7937038acb689b0"
		 hash3= "e1068cacba806002b1cba6ebfb35e4f4"

	strings:

	
 		 $s1= "%04d-%02d-%02d %02d:%02d:%02d" fullword wide
		 $s2= "%08x-%04d-%02d-%04x%04x" fullword wide
		 $s3= "6.1.7600.16385 (win7_rtm.090713-1255)" fullword wide
		 $s4= "FileDescription" fullword wide
		 $s5= "HARDWAREDESCRIPTIONSystemCentralProcessor0" fullword wide
		 $s6= "Microsoft Corporation" fullword wide
		 $s7= "OriginalFilename" fullword wide
		 $s8= "PROCESSOR_ARCHITECTURE" fullword wide
		 $s9= "ProcessorNameString" fullword wide
		 $s10= "SeAssignPrimaryTokenPrivilege" fullword wide
		 $s11= "SeIncreaseQuotaPrivilege" fullword wide
		 $s12= "SeTakeOwnershipPrivilege" fullword wide
		 $s13= "SOFTWAREMICROSOFTWINDOWS NTCURRENTVERSION" fullword wide
		 $s14= "SYSTEMCurrentControlSetControlSession ManagerEnvironment" fullword wide
		 $s15= "VS_VERSION_INFO" fullword wide
		 $s16= "winsta0default" fullword wide
		 $a1= "6.1.7600.16385 (win7_rtm.090713-1255)" fullword ascii
		 $a2= "HARDWAREDESCRIPTIONSystemCentralProcessor0" fullword ascii
		 $a3= "SOFTWAREMICROSOFTWINDOWS NTCURRENTVERSION" fullword ascii
		 $a4= "SYSTEMCurrentControlSetControlSession ManagerEnvironment" fullword ascii

		 $hex1= {2461313d2022362e31}
		 $hex2= {2461323d2022484152}
		 $hex3= {2461333d2022534f46}
		 $hex4= {2461343d2022535953}
		 $hex5= {247331303d20225365}
		 $hex6= {247331313d20225365}
		 $hex7= {247331323d20225365}
		 $hex8= {247331333d2022534f}
		 $hex9= {247331343d20225359}
		 $hex10= {247331353d20225653}
		 $hex11= {247331363d20227769}
		 $hex12= {2473313d2022253034}
		 $hex13= {2473323d2022253038}
		 $hex14= {2473333d2022362e31}
		 $hex15= {2473343d202246696c}
		 $hex16= {2473353d2022484152}
		 $hex17= {2473363d20224d6963}
		 $hex18= {2473373d20224f7269}
		 $hex19= {2473383d202250524f}
		 $hex20= {2473393d202250726f}

	condition:
		6 of them
}
