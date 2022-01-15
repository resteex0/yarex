
/*
   YARA Rule Set
   Author: resteex
   Identifier: Trojan_Ransom_Petya 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Trojan_Ransom_Petya {
	meta: 
		 description= "Trojan_Ransom_Petya Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-54-11" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8ed9a60127aee45336102bf12059a850"

	strings:

	
 		 $s1= "binmscordmp.exe" fullword wide
		 $s2= "DbgJITDebugLaunchSetting %s" fullword wide
		 $s3= "DbgManagedDebugger %s" fullword wide
		 $s4= "FileDescription" fullword wide
		 $s5= "InprocServer32" fullword wide
		 $s6= "Microsoft Corporation" fullword wide
		 $s7= ".NET application" fullword wide
		 $s8= "OriginalFilename" fullword wide
		 $s9= "PrevDbgJITDebugLaunchSetting %s" fullword wide
		 $s10= "PrevDbgManagedDebugger %s" fullword wide
		 $s11= "PreVisualStudio7Auto %s" fullword wide
		 $s12= "PreVisualStudio7Debugger %s" fullword wide
		 $s13= "SOFTWAREMicrosoft.NETFramework" fullword wide
		 $s14= "VS_VERSION_INFO" fullword wide

		 $hex1= {247331303d20225072}
		 $hex2= {247331313d20225072}
		 $hex3= {247331323d20225072}
		 $hex4= {247331333d2022534f}
		 $hex5= {247331343d20225653}
		 $hex6= {2473313d202262696e}
		 $hex7= {2473323d2022446267}
		 $hex8= {2473333d2022446267}
		 $hex9= {2473343d202246696c}
		 $hex10= {2473353d2022496e70}
		 $hex11= {2473363d20224d6963}
		 $hex12= {2473373d20222e4e45}
		 $hex13= {2473383d20224f7269}
		 $hex14= {2473393d2022507265}

	condition:
		1 of them
}
