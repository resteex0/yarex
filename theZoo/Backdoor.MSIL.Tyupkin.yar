
/*
   YARA Rule Set
   Author: resteex
   Identifier: Backdoor_MSIL_Tyupkin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Backdoor_MSIL_Tyupkin {
	meta: 
		 description= "Backdoor_MSIL_Tyupkin Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_22-50-54" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "162ad6dbd50f3be407f49f65b938512a"
		 hash2= "250b77dfbb1b666e95b3bcda082de287"
		 hash3= "32d5cca418b81e002bb3fdd8e4062bc9"
		 hash4= "69be938abe7f28615d933d5ce155057c"
		 hash5= "700e91a24f5cadd0cb7507f0d0077b26"
		 hash6= "af945758905e0615a10fe23070998b9b"

	strings:

	
 		 $s1= "C:windowssystem32configswin.sys" fullword wide
		 $s2= "C:windowssystem32driversswin.sys" fullword wide
		 $s3= "C:WINXPPROsystem32configswin.sys" fullword wide
		 $s4= "C:WINXPPROsystem32driversswin.sys" fullword wide
		 $s5= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s6= "SYSTEMControlSet001Servicesscsrvc" fullword wide
		 $s7= "SYSTEMControlSet002Servicesscsrvc" fullword wide
		 $s8= "SYSTEMControlSet003Servicesscsrvc" fullword wide
		 $s9= "SYSTEMCurrentControlSetServicesscsrvc" fullword wide

		 $hex1= {2473313d2022433a77}
		 $hex2= {2473323d2022433a77}
		 $hex3= {2473333d2022433a57}
		 $hex4= {2473343d2022433a57}
		 $hex5= {2473353d2022536f66}
		 $hex6= {2473363d2022535953}
		 $hex7= {2473373d2022535953}
		 $hex8= {2473383d2022535953}
		 $hex9= {2473393d2022535953}

	condition:
		6 of them
}
