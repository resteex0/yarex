
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
		 date = "2022-01-14_21-37-17" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "162ad6dbd50f3be407f49f65b938512a"
		 hash2= "250b77dfbb1b666e95b3bcda082de287"
		 hash3= "32d5cca418b81e002bb3fdd8e4062bc9"
		 hash4= "69be938abe7f28615d933d5ce155057c"
		 hash5= "700e91a24f5cadd0cb7507f0d0077b26"
		 hash6= "af945758905e0615a10fe23070998b9b"

	strings:

	
 		 $s1= "5AGHMPRWYAIPRvx}" fullword wide
		 $s2= "]^_a`b`kjmlon" fullword wide
		 $s3= "`a^hcegjmlprt" fullword wide
		 $s4= "[][^[`_a_jilknm" fullword wide
		 $s5= "C:windowssystem32configswin.sys" fullword wide
		 $s6= "C:windowssystem32driversswin.sys" fullword wide
		 $s7= "C:WINXPPROsystem32configswin.sys" fullword wide
		 $s8= "C:WINXPPROsystem32driversswin.sys" fullword wide
		 $s9= "DELETING APPLICATION..." fullword wide
		 $s10= "LOVUTKJNQSXZ|uz{wy~" fullword wide
		 $s11= "SeBackupPrivilege" fullword wide
		 $s12= "SeIncreaseQuotaPrivilege" fullword wide
		 $s13= "SeRestorePrivilege" fullword wide
		 $s14= "SeShutdownPrivilege" fullword wide
		 $s15= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s16= "SummaryInformation" fullword wide
		 $s17= "SYSTEMControlSet001Servicesscsrvc" fullword wide
		 $s18= "SYSTEMControlSet002Servicesscsrvc" fullword wide
		 $s19= "SYSTEMControlSet003Servicesscsrvc" fullword wide
		 $s20= "SYSTEMCurrentControlSetServicesscsrvc" fullword wide
		 $s21= "YXZX[X]^fehgji" fullword wide
		 $a1= "C:windowssystem32configswin.sys" fullword ascii
		 $a2= "C:windowssystem32driversswin.sys" fullword ascii
		 $a3= "C:WINXPPROsystem32configswin.sys" fullword ascii
		 $a4= "C:WINXPPROsystem32driversswin.sys" fullword ascii
		 $a5= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword ascii
		 $a6= "SYSTEMControlSet001Servicesscsrvc" fullword ascii
		 $a7= "SYSTEMControlSet002Servicesscsrvc" fullword ascii
		 $a8= "SYSTEMControlSet003Servicesscsrvc" fullword ascii
		 $a9= "SYSTEMCurrentControlSetServicesscsrvc" fullword ascii

		 $hex1= {2461313d2022433a77}
		 $hex2= {2461323d2022433a77}
		 $hex3= {2461333d2022433a57}
		 $hex4= {2461343d2022433a57}
		 $hex5= {2461353d2022536f66}
		 $hex6= {2461363d2022535953}
		 $hex7= {2461373d2022535953}
		 $hex8= {2461383d2022535953}
		 $hex9= {2461393d2022535953}
		 $hex10= {247331303d20224c4f}
		 $hex11= {247331313d20225365}
		 $hex12= {247331323d20225365}
		 $hex13= {247331333d20225365}
		 $hex14= {247331343d20225365}
		 $hex15= {247331353d2022536f}
		 $hex16= {247331363d20225375}
		 $hex17= {247331373d20225359}
		 $hex18= {247331383d20225359}
		 $hex19= {247331393d20225359}
		 $hex20= {2473313d2022354147}
		 $hex21= {247332303d20225359}
		 $hex22= {247332313d20225958}
		 $hex23= {2473323d20225d5e5f}
		 $hex24= {2473333d202260615e}
		 $hex25= {2473343d20225b5d5b}
		 $hex26= {2473353d2022433a77}
		 $hex27= {2473363d2022433a77}
		 $hex28= {2473373d2022433a57}
		 $hex29= {2473383d2022433a57}
		 $hex30= {2473393d202244454c}

	condition:
		10 of them
}
