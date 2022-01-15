
/*
   YARA Rule Set
   Author: resteex
   Identifier: Trojan_Destover_SonySigned 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Trojan_Destover_SonySigned {
	meta: 
		 description= "Trojan_Destover_SonySigned Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-54-08" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "e904bf93403c0fb08b9683a9e858c73e"

	strings:

	
 		 $s1= "203.131.222.102" fullword wide
		 $s2= "208.105.226.235" fullword wide
		 $s3= "Datacenter(Core) " fullword wide
		 $s4= "Datacenter(Itanium) " fullword wide
		 $s5= "Enterprise(Core) " fullword wide
		 $s6= "Enterprise(Itanium) " fullword wide
		 $s7= "FileDescription" fullword wide
		 $s8= "igfxstartup Module" fullword wide
		 $s9= "LegalTrademarks" fullword wide
		 $s10= "Microsoft Corporation" fullword wide
		 $s11= "OriginalFilename" fullword wide
		 $s12= "Parameter Error" fullword wide
		 $s13= "Server2003(R2) " fullword wide
		 $s14= "Server2008(R2) " fullword wide
		 $s15= "Server2012(R2) " fullword wide
		 $s16= "Standard(Core) " fullword wide
		 $s17= "VS_VERSION_INFO" fullword wide

		 $hex1= {247331303d20224d69}
		 $hex2= {247331313d20224f72}
		 $hex3= {247331323d20225061}
		 $hex4= {247331333d20225365}
		 $hex5= {247331343d20225365}
		 $hex6= {247331353d20225365}
		 $hex7= {247331363d20225374}
		 $hex8= {247331373d20225653}
		 $hex9= {2473313d2022323033}
		 $hex10= {2473323d2022323038}
		 $hex11= {2473333d2022446174}
		 $hex12= {2473343d2022446174}
		 $hex13= {2473353d2022456e74}
		 $hex14= {2473363d2022456e74}
		 $hex15= {2473373d202246696c}
		 $hex16= {2473383d2022696766}
		 $hex17= {2473393d20224c6567}

	condition:
		2 of them
}
