
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
		 date = "2022-01-20_04-43-51" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8ed9a60127aee45336102bf12059a850"

	strings:

	
 		 $s1= "DbgJITDebugLaunchSetting %s" fullword wide
		 $s2= "PrevDbgJITDebugLaunchSetting %s" fullword wide
		 $s3= "PrevDbgManagedDebugger %s" fullword wide
		 $s4= "PreVisualStudio7Debugger %s" fullword wide
		 $s5= "SOFTWAREMicrosoft.NETFramework" fullword wide
		 $a1= "clsid{834128A2-51F4-11D0-8F20-00805F2CD064}LocalServer32" fullword ascii
		 $a2= "I:VS70Builds3077vsbuiltretailBini386optmdm.pdb" fullword ascii
		 $a3= "SoftwareMicrosoftWindowsCurrentVersionExplorerShell Folders" fullword ascii

		 $hex1= {2461313d2022636c73}
		 $hex2= {2461323d2022493a56}
		 $hex3= {2461333d2022536f66}
		 $hex4= {2473313d2022446267}
		 $hex5= {2473323d2022507265}
		 $hex6= {2473333d2022507265}
		 $hex7= {2473343d2022507265}
		 $hex8= {2473353d2022534f46}

	condition:
		5 of them
}
