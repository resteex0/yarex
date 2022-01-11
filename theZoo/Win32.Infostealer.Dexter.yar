
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Infostealer_Dexter 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Infostealer_Dexter {
	meta: 
		 description= "Win32_Infostealer_Dexter Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-32-41" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "140d24af0c2b3a18529df12dfbc5f6de"
		 hash2= "7d419cd096fec8bcf945e00e70a9bc41"

	strings:

	
 		 $s1= "Internet Exploreriexplore.exe" fullword wide
		 $s2= "Java Security Plugin" fullword wide
		 $s3= "Sun Java Security Plugin" fullword wide
		 $a1= "0@0D0H0L0P0T0X00`0d0h0l0H1x1" fullword ascii
		 $a2= "7$7)737A7J7P7V7[7b7h7v7~7" fullword ascii
		 $a3= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" fullword ascii
		 $a4= "Content-Type:application/x-www-form-urlencoded" fullword ascii
		 $a5= ".DEFAULTSOFTWAREMicrosoftWindowsCurrentVersionRun" fullword ascii
		 $a6= "InitializeCriticalSection" fullword ascii
		 $a7= "NtQueryInformationProcess" fullword ascii
		 $a8= "RtlGetCompressionWorkSpaceSize" fullword ascii
		 $a9= "RtlTimeToSecondsSince1970" fullword ascii
		 $a10= "SoftwareMicrosoftWindowsCurrentVersionPoliciesAssociations" fullword ascii
		 $a11= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword ascii
		 $a12= "/w19218317418621031041543/gateway.php" fullword ascii
		 $a13= "WindowsServiceStabilityMutex" fullword ascii

		 $hex1= {246131303d2022536f}
		 $hex2= {246131313d2022536f}
		 $hex3= {246131323d20222f77}
		 $hex4= {246131333d20225769}
		 $hex5= {2461313d2022304030}
		 $hex6= {2461323d2022372437}
		 $hex7= {2461333d2022414243}
		 $hex8= {2461343d2022436f6e}
		 $hex9= {2461353d20222e4445}
		 $hex10= {2461363d2022496e69}
		 $hex11= {2461373d20224e7451}
		 $hex12= {2461383d202252746c}
		 $hex13= {2461393d202252746c}
		 $hex14= {2473313d2022496e74}
		 $hex15= {2473323d20224a6176}
		 $hex16= {2473333d202253756e}

	condition:
		2 of them
}
