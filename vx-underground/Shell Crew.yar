
/*
   YARA Rule Set
   Author: resteex
   Identifier: Shell_Crew 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Shell_Crew {
	meta: 
		 description= "Shell_Crew Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-18-41" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "106e63dbda3a76beeb53a8bbd8f98927"
		 hash2= "128c17340cb5add26bf60dfe2af37700"
		 hash3= "1ae0c39cb9684652c017161f8a5aca78"
		 hash4= "2dce7fc3f52a692d8a84a0c182519133"
		 hash5= "2f05c07e3f925265cd45ef1d0243a511"
		 hash6= "312888a0742815cccc53dc37abf1a958"
		 hash7= "3804d23ddb141c977b98c2885953444f"
		 hash8= "3a27de4fb6e2c524e883c40a43da554e"
		 hash9= "3c973c1ad37dae0443a078dba685c0ea"
		 hash10= "3dec6df39910045791ee697f461baaba"
		 hash11= "42d98ddb0a5b870e8bb828fb2ef22b3f"
		 hash12= "42ecdce7d7dab7c3088e332ff4f64875"
		 hash13= "449521ce87ed0111dcb0d4beff85064d"
		 hash14= "469d4825c5acacb62d1c109085790849"
		 hash15= "59cb505d1636119f2881caa14bf42326"
		 hash16= "62567951f942f6015138449520e67aeb"
		 hash17= "6802c21d3d0d80084bf93413dc0c23a7"
		 hash18= "6811b8667e08ffa5fcd8a69ca9c72161"
		 hash19= "6d620d5a903f0d714c30565a9bfdce8f"
		 hash20= "6ec15a34f058176be4e4685eda9a5cfc"
		 hash21= "72662c61ae8ef7566a945f648e9d4dd8"
		 hash22= "75b3ccd4d3bfb56b55a46fba9463d282"
		 hash23= "76767ef2d2bb25eba45203f0d2e8335b"
		 hash24= "837b6b1601e0fa99f28657dee244223b"
		 hash25= "87f93dcfa2c329081ddbd175ea6d946b"
		 hash26= "8c0cf5bc1f75d71879b48a286f6befcf"
		 hash27= "9318d336f8d8018fd97357c26a2dfb20"
		 hash28= "985abc913a294c096718892332631ec9"
		 hash29= "a1fb51343f3724e8b683a93f2d42127b"
		 hash30= "a395eed1d0f8a7a79bdebbfd6c673cc1"
		 hash31= "bc32ecb75624a7bec7a901e10c195307"
		 hash32= "c353bac6ebace04b376adf1f3115e087"
		 hash33= "cc09af194acf2039ad9f6074d89157ca"
		 hash34= "d3ad90010c701e731835142fabb6bfcc"
		 hash35= "de7500fc1065a081180841f32f06a537"
		 hash36= "eb698247808b8e35ed5a9d5fefd7a3ae"
		 hash37= "eeb636886ecc9ff3623d10f1efcf3c09"
		 hash38= "f942f98cff86f8fcde7eb0c2f465be7a"

	strings:

	
 		 $s1= "%$&$'$($)$*$+$107698:8LKQPRPkjljmjnjojpj" fullword wide
		 $s2= "5.2.3790.3959 (srv03_sp2_rtm.070216-1710)" fullword wide
		 $s3= "6.1.7601.17514 (win7sp1_rtm.101119-1850)" fullword wide
		 $s4= "{6AB5E732-DFA9-4618-AF1C-F0D9DEF0E222}" fullword wide
		 $s5= "8=8>8?8EDKJMLNL[Z^]_]srtrurvrwrxr" fullword wide
		 $s6= "{93144EB0-8E3E-4591-B307-8EEBFE7DB28F}" fullword wide
		 $s7= "{BC87739C-6024-412c-B489-B951C2F17000}" fullword wide
		 $s8= "C:WindowsSystem32sysprep" fullword wide
		 $s9= "C:WindowsSystem32sysprepCRYPTBASE.dll" fullword wide
		 $s10= "C:WindowsSystem32sysprepsysprep.exe" fullword wide
		 $s11= "Device{93144EB0-8E3E-4591-B307-8EEBFE7DB28F}" fullword wide
		 $s12= "DosDevicesC:windowssystem32%ws" fullword wide
		 $s13= "DosDevices%wsFonts%ws" fullword wide
		 $s14= "DosDevices%wsPrefetch%ws" fullword wide
		 $s15= "DosDevices%wssystem32%ws" fullword wide
		 $s16= "L$_RasDefaultCredentials#0" fullword wide
		 $s17= "LsaEnumerateLogonSessions" fullword wide
		 $s18= "RegistryMachineSystemCurrentControlSetServices" fullword wide
		 $s19= "SOFTWAREMicrosoftInternet Explorer" fullword wide
		 $s20= "SoftwareMicrosoftWindowsCurrentVersionInternet Settings" fullword wide
		 $s21= "SOFTWAREMicrosoftWZCSVCParametersInterfaces" fullword wide
		 $s22= "sSYSTEMCurrentControlSetServices" fullword wide
		 $s23= "SYSTEMCurrentControlSetControlPnp" fullword wide
		 $s24= "SystemCurrentControlSetServices" fullword wide
		 $s25= "SystemCurrentControlSetServices" fullword wide
		 $s26= "%WINDIR%PCHealthHelpCtrBinariespchsvc.dll" fullword wide
		 $s27= "%windir%system32IMEconime.exe" fullword wide
		 $s28= "%windir%systemconime.exe" fullword wide
		 $s29= "%Windir%syswow64Irclass.dll" fullword wide
		 $s30= "%Windir%syswow64kmddsp.tsp" fullword wide
		 $s31= "%Windir%syswow64msvidc32.dll" fullword wide
		 $s32= ";WV" fullword wide
		 $a1= "RegistryMachineSystemCurrentControlSetServices" fullword ascii
		 $a2= "SoftwareMicrosoftWindowsCurrentVersionInternet Settings" fullword ascii

		 $hex1= {2461313d2022526567}
		 $hex2= {2461323d2022536f66}
		 $hex3= {247331303d2022433a}
		 $hex4= {247331313d20224465}
		 $hex5= {247331323d2022446f}
		 $hex6= {247331333d2022446f}
		 $hex7= {247331343d2022446f}
		 $hex8= {247331353d2022446f}
		 $hex9= {247331363d20224c24}
		 $hex10= {247331373d20224c73}
		 $hex11= {247331383d20225265}
		 $hex12= {247331393d2022534f}
		 $hex13= {2473313d2022252426}
		 $hex14= {247332303d2022536f}
		 $hex15= {247332313d2022534f}
		 $hex16= {247332323d20227353}
		 $hex17= {247332333d20225359}
		 $hex18= {247332343d20225379}
		 $hex19= {247332353d20225379}
		 $hex20= {247332363d20222557}
		 $hex21= {247332373d20222577}
		 $hex22= {247332383d20222577}
		 $hex23= {247332393d20222557}
		 $hex24= {2473323d2022352e32}
		 $hex25= {247333303d20222557}
		 $hex26= {247333313d20222557}
		 $hex27= {247333323d20223b57}
		 $hex28= {2473333d2022362e31}
		 $hex29= {2473343d20227b3641}
		 $hex30= {2473353d2022383d38}
		 $hex31= {2473363d20227b3933}
		 $hex32= {2473373d20227b4243}
		 $hex33= {2473383d2022433a57}
		 $hex34= {2473393d2022433a57}

	condition:
		22 of them
}
