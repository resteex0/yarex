
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Trojan_Ransom_Petya 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Trojan_Ransom_Petya {
	meta: 
		 description= "theZoo_Trojan_Ransom_Petya Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-35-52" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8ed9a60127aee45336102bf12059a850"

	strings:

	
 		 $s1= "DbgJITDebugLaunchSetting %s" fullword wide
		 $s2= "PrevDbgJITDebugLaunchSetting %s" fullword wide
		 $s3= "PrevDbgManagedDebugger %s" fullword wide
		 $s4= "PreVisualStudio7Debugger %s" fullword wide
		 $s5= "SOFTWAREMicrosoft.NETFramework" fullword wide
		 $a1= "SoftwareMicrosoftWindowsCurrentVersionExplorerShell Folders" fullword ascii

		 $hex1= {2461313d2022536f66}
		 $hex2= {2473313d2022446267}
		 $hex3= {2473323d2022507265}
		 $hex4= {2473333d2022507265}
		 $hex5= {2473343d2022507265}
		 $hex6= {2473353d2022534f46}

	condition:
		4 of them
}
