
/*
   YARA Rule Set
   Author: resteex
   Identifier: RokRAT 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_RokRAT {
	meta: 
		 description= "RokRAT Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-18-22" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "6c668fd6a98f0659abc54d88c1db209e"
		 hash2= "7ca1e08fc07166a440576d1af0a15bb1"
		 hash3= "9cf931c33319f2a23d0b49cb805a4a34"
		 hash4= "b441d9a75c60b222e3c9fd50c0d14c5b"
		 hash5= "bdbabe7d5605c00d24d15e3fac6eda1e"
		 hash6= "bedc4b9f39dcc0907f8645db1acce59e"

	strings:

	
 		 $s1= "api-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s2= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s3= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s5= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s6= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s7= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s8= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s9= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s10= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s11= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s12= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s13= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s14= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s15= "charset={[A-Za-z0-9-_]+}" fullword wide
		 $s16= "C:Windowssystem32cmd.exe" fullword wide
		 $s17= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s18= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s19= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s20= "https://account.box.com/api/oauth2/authorize" fullword wide
		 $s21= "https://api.box.com/2.0/files/%s" fullword wide
		 $s22= "https://api.box.com/2.0/files/%s/content" fullword wide
		 $s23= "https://api.box.com/2.0/files/%s/trash" fullword wide
		 $s24= "https://api.box.com/2.0/folders/%s" fullword wide
		 $s25= "https://api.box.com/2.0/folders/%s/items" fullword wide
		 $s26= "https://api.box.com/oauth2/token" fullword wide
		 $s27= "https://api.dropboxapi.com/2/files/delete" fullword wide
		 $s28= "https://api.pcloud.com/deletefile?path=%s" fullword wide
		 $s29= "https://api.pcloud.com/oauth2_token" fullword wide
		 $s30= "https://cloud-api.yandex.net/v1/disk/resources/download?path=%s" fullword wide
		 $s31= "https://content.dropboxapi.com/2/files/download" fullword wide
		 $s32= "https://content.dropboxapi.com/2/files/upload" fullword wide
		 $s33= "https://my.pcloud.com/oauth2/authorize" fullword wide
		 $s34= "https://upload.box.com/api/2.0/files/content" fullword wide
		 $s35= "Location: {[A-Za-z0-9.:=&?/-_#]+}" fullword wide
		 $s36= "multipart/form-data;boundary=--opxer--" fullword wide
		 $s37= "multipart/form-data;boundary=--wwjaughalvncjwiajs--" fullword wide
		 $s38= "SoftwareMicrosoftInternet ExplorerIntelliFormsStorage2" fullword wide
		 $s39= "SoftwareMicrosoftWindowsCurrentVersionExplorerShell Folders" fullword wide
		 $s40= "spanish-dominican republic" fullword wide
		 $s41= "SYSTEMCurrentControlSetServicesmssmbiosData" fullword wide
		 $a1= "https://cloud-api.yandex.net/v1/disk/resources/download?path=%s" fullword ascii
		 $a2= "multipart/form-data;boundary=--wwjaughalvncjwiajs--" fullword ascii
		 $a3= "SoftwareMicrosoftInternet ExplorerIntelliFormsStorage2" fullword ascii
		 $a4= "SoftwareMicrosoftWindowsCurrentVersionExplorerShell Folders" fullword ascii

		 $hex1= {2461313d2022687474}
		 $hex2= {2461323d20226d756c}
		 $hex3= {2461333d2022536f66}
		 $hex4= {2461343d2022536f66}
		 $hex5= {247331303d20226170}
		 $hex6= {247331313d20226170}
		 $hex7= {247331323d20226170}
		 $hex8= {247331333d20226170}
		 $hex9= {247331343d20226170}
		 $hex10= {247331353d20226368}
		 $hex11= {247331363d2022433a}
		 $hex12= {247331373d20226578}
		 $hex13= {247331383d20226578}
		 $hex14= {247331393d20226578}
		 $hex15= {2473313d2022617069}
		 $hex16= {247332303d20226874}
		 $hex17= {247332313d20226874}
		 $hex18= {247332323d20226874}
		 $hex19= {247332333d20226874}
		 $hex20= {247332343d20226874}
		 $hex21= {247332353d20226874}
		 $hex22= {247332363d20226874}
		 $hex23= {247332373d20226874}
		 $hex24= {247332383d20226874}
		 $hex25= {247332393d20226874}
		 $hex26= {2473323d2022617069}
		 $hex27= {247333303d20226874}
		 $hex28= {247333313d20226874}
		 $hex29= {247333323d20226874}
		 $hex30= {247333333d20226874}
		 $hex31= {247333343d20226874}
		 $hex32= {247333353d20224c6f}
		 $hex33= {247333363d20226d75}
		 $hex34= {247333373d20226d75}
		 $hex35= {247333383d2022536f}
		 $hex36= {247333393d2022536f}
		 $hex37= {2473333d2022617069}
		 $hex38= {247334303d20227370}
		 $hex39= {247334313d20225359}
		 $hex40= {2473343d2022617069}
		 $hex41= {2473353d2022617069}
		 $hex42= {2473363d2022617069}
		 $hex43= {2473373d2022617069}
		 $hex44= {2473383d2022617069}
		 $hex45= {2473393d2022617069}

	condition:
		30 of them
}
