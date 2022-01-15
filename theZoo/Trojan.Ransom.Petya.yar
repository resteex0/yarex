
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
		 date = "2022-01-14_22-51-52" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8ed9a60127aee45336102bf12059a850"

	strings:

	
 		 $s1= "DbgJITDebugLaunchSetting %s" fullword wide
		 $s2= "PrevDbgJITDebugLaunchSetting %s" fullword wide
		 $s3= "PrevDbgManagedDebugger %s" fullword wide
		 $s4= "PreVisualStudio7Debugger %s" fullword wide
		 $s5= "SOFTWAREMicrosoft.NETFramework" fullword wide

		 $hex1= {2473313d2022446267}
		 $hex2= {2473323d2022507265}
		 $hex3= {2473333d2022507265}
		 $hex4= {2473343d2022507265}
		 $hex5= {2473353d2022534f46}

	condition:
		3 of them
}
