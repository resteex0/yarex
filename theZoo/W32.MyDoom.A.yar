
/*
   YARA Rule Set
   Author: resteex
   Identifier: W32_MyDoom_A 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W32_MyDoom_A {
	meta: 
		 description= "W32_MyDoom_A Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-31-16" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "10a5ce311f8f925a5d180d01aa62b560"
		 hash2= "2eb21132d838154920b4808820d6a63d"
		 hash3= "53df39092394741514bc050f3d6a06a9"
		 hash4= "6cee152928b02f883867a51c89633106"
		 hash5= "91800f7d2ca85deedba2735c8b4505ce"

	strings:

	
 		 $s1= "n of mass destruction_files' is a directory" fullword wide
		 $s2= "strings: Warning: 'theZoo/malware/Binaries/W32.MyDoom.A/W32.MyDoom.A/Netcraft www_sco_com is a weapo" fullword wide
		 $s3= "strings: Warning: 'theZoo/malware/Binaries/W32.MyDoom.A/W32.MyDoom.A/W32.Mydoom2_files' is a directo" fullword wide
		 $s4= "strings: Warning: 'theZoo/malware/Binaries/W32.MyDoom.A/W32.MyDoom.A/W32.Mydoom_files' is a director" fullword wide
		 $a1= "1.3.6.1.4.1.2213.12.1.111.2.10" fullword ascii
		 $a2= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" fullword ascii
		 $a3= "HKEY_CURRENT_USERSoftwareMicrosoftWindowsCurrentVersionRun\\TaskMon|" fullword ascii
		 $a4= "HKEY_LOCAL_MACHINESOFTWAREMicrosoftWindowsCurrentVersionRun\\DVP" fullword ascii
		 $a5= "HKEY_LOCAL_MACHINESOFTWAREMicrosoftWindowsCurrentVersionRun\\DVP|" fullword ascii
		 $a6= "HKEY_LOCAL_MACHINESoftwareMicrosoftWindowsCurrentVersionRun\\TaskMon|" fullword ascii
		 $a7= "HKEY_LOCAL_MACHINESystemCurrentControlSetControlSessionManagerKnownVxDs\\DVP|" fullword ascii
		 $a8= "HKEY_LOCAL_MACHINESYSTEMCurrentControlSetServices" fullword ascii
		 $a9= "HKEY_LOCAL_MACHINESystemCurrentControlSetServicesEventLog" fullword ascii
		 $a10= "InitializeCriticalSection" fullword ascii
		 $a11= "?IsProcessorFeaturePresent" fullword ascii
		 $a12= "JanFebMarAprMayJunJulAugSepOctNovDec" fullword ascii
		 $a13= "QueryPerformanceFrequency" fullword ascii
		 $a14= "REGISTRYMachineSYSTEMCurrentControlSetServices" fullword ascii
		 $a15= "SetUnhandledExceptionFilter" fullword ascii
		 $a16= "SoftwareMicrosoftWindowsCurrentVersion" fullword ascii
		 $a17= "StringFileInfo040904B0FileDescription" fullword ascii
		 $a18= "StringFileInfo040904B0ProductVersion" fullword ascii
		 $a19= "SYSTEMCurrentControlSetServices" fullword ascii

		 $hex1= {246131303d2022496e}
		 $hex2= {246131313d20223f49}
		 $hex3= {246131323d20224a61}
		 $hex4= {246131333d20225175}
		 $hex5= {246131343d20225245}
		 $hex6= {246131353d20225365}
		 $hex7= {246131363d2022536f}
		 $hex8= {246131373d20225374}
		 $hex9= {246131383d20225374}
		 $hex10= {246131393d20225359}
		 $hex11= {2461313d2022312e33}
		 $hex12= {2461323d2022414243}
		 $hex13= {2461333d2022484b45}
		 $hex14= {2461343d2022484b45}
		 $hex15= {2461353d2022484b45}
		 $hex16= {2461363d2022484b45}
		 $hex17= {2461373d2022484b45}
		 $hex18= {2461383d2022484b45}
		 $hex19= {2461393d2022484b45}
		 $hex20= {2473313d20226e206f}
		 $hex21= {2473323d2022737472}
		 $hex22= {2473333d2022737472}
		 $hex23= {2473343d2022737472}

	condition:
		2 of them
}
