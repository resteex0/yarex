
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Petya 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Petya {
	meta: 
		 description= "Ransomware_Petya Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-53-39" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "a92f13f3a1b3b39833d3cc336301b713"
		 hash2= "af2379cc4d607a45ac44d62135fb7015"

	strings:

	
 		 $s1= "[%02d/%02d/%02d %02d:%02d:%02d.%03d]" fullword wide
		 $s2= "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" fullword wide
		 $s3= "{A0C1F415-D2CE-4ddc-9B48-14E56FD55162}" fullword wide
		 $s4= "Assertion failed!" fullword wide
		 $s5= "BIsEnrolledToDomain" fullword wide
		 $s6= "BX-GoogleUpdate-Interactivity" fullword wide
		 $s7= "BX-Proxy-Manual-Auth" fullword wide
		 $s8= "{C4F406E5-F024-4e3f-89A7-D5AB7663C3CD}" fullword wide
		 $s9= "{C68009EA-1163-4498-8E93-D5C4E317D8CE}" fullword wide
		 $s10= "ClientCustomData" fullword wide
		 $s11= "@CommandLineMode" fullword wide
		 $s12= "@CrashHandlerEnv_CrashInfo" fullword wide
		 $s13= "CrashHandlerLaunchedForMinidump" fullword wide
		 $s14= "[CrashHandler::RunUntilShutdown]" fullword wide
		 $s15= "[CrashHandler::Shutdown]" fullword wide
		 $s16= "CSoftwareGoogle%wsUsageStatsDaily" fullword wide
		 $s17= "custom_info_filename" fullword wide
		 $s18= "{D19BAF17-7C87-467E-8D63-6C4B1C836373}" fullword wide
		 $s19= "Default Proxy>" fullword wide
		 $s20= "deferred-upload" fullword wide
		 $s21= "DOracleJavajava.settings.cfg" fullword wide
		 $s22= "download_time_ms" fullword wide
		 $s23= "[GetCrashPipeName][GetProcessUser failed][0x%08x]" fullword wide
		 $s24= "GoogleCrashHandlerWorkerDesktop" fullword wide
		 $s25= "GoogleCrashReports" fullword wide
		 $s26= "GoogleUpdate.exe" fullword wide
		 $s27= "GoogleUpdate.ini" fullword wide
		 $s28= "GoogleUpdateLog" fullword wide
		 $s29= "GoogleUpdate.log" fullword wide
		 $s30= "_Google_Update_logging_mutex_" fullword wide
		 $s31= "GOOGLE_UPDATE_NO_CRASH_HANDLER" fullword wide
		 $s32= "GRuntime Error!" fullword wide
		 $s33= "HKCUSoftwareGoogleUpdate" fullword wide
		 $s34= "HKCUSoftwareGoogleUpdateClientState" fullword wide
		 $s35= "HKEY_CURRENT_USER" fullword wide
		 $s36= "HKEY_LOCAL_MACHINE" fullword wide
		 $s37= "HKLMSoftwareGoogleUpdate" fullword wide
		 $s38= "HKLMSoftwareGoogleUpdateClientState" fullword wide
		 $s39= "HKLMSoftwareGoogleUpdateClientStateMedium" fullword wide
		 $s40= "HKLMSoftwareGoogleUpdateDev" fullword wide
		 $s41= "HKLMSoftwareMicrosoftWindows NTCurrentVersionNetworkCards" fullword wide
		 $s42= "HKLMSoftwarePoliciesGoogleUpdate" fullword wide
		 $s43= "install_time_ms" fullword wide
		 $s44= "LastTransmission" fullword wide
		 $s45= "LoggingSettings" fullword wide
		 $s46= "LogToOutputDebug" fullword wide
		 $s47= "[OpenCustomInfoFile failed][0x%08x]" fullword wide
		 $s48= "PendingFileRenameOperations" fullword wide
		 $s49= "\\.pipeGoogleCrashServices" fullword wide
		 $s50= "PROGRAMFILESCOMMON" fullword wide
		 $s51= "registerproduct" fullword wide
		 $s52= "**SehSendMinidump**" fullword wide
		 $s53= "source_url_index" fullword wide
		 $s54= "sprintf failure" fullword wide
		 $s55= "[StartCrashReporter failed][0x%08x]" fullword wide
		 $s56= "[StartCrashUploader() failed][0x%08x]" fullword wide
		 $s57= "[Started process][%u]" fullword wide
		 $s58= "[StartProcessWithNoExceptionHandler][%s]" fullword wide
		 $s59= "SYSTEMCurrentControlSetControlSession Manager" fullword wide
		 $s60= "uid-create-time" fullword wide
		 $s61= "uid-num-rotations" fullword wide
		 $s62= "unregisterproduct" fullword wide
		 $s63= "update_check_time_ms" fullword wide
		 $s64= "@VarFileInfoTranslation" fullword wide
		 $s65= "X-HTTP-Attempts" fullword wide
		 $s66= "X-Last-HTTP-Status-Code" fullword wide
		 $s67= "X-Proxy-Retry-Count" fullword wide
		 $a1= "[%02d/%02d/%02d %02d:%02d:%02d.%03d]" fullword ascii
		 $a2= "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" fullword ascii
		 $a3= "{A0C1F415-D2CE-4ddc-9B48-14E56FD55162}" fullword ascii
		 $a4= "{C4F406E5-F024-4e3f-89A7-D5AB7663C3CD}" fullword ascii
		 $a5= "{C68009EA-1163-4498-8E93-D5C4E317D8CE}" fullword ascii
		 $a6= "CSoftwareGoogle%wsUsageStatsDaily" fullword ascii
		 $a7= "{D19BAF17-7C87-467E-8D63-6C4B1C836373}" fullword ascii
		 $a8= "[GetCrashPipeName][GetProcessUser failed][0x%08x]" fullword ascii
		 $a9= "HKCUSoftwareGoogleUpdateClientState" fullword ascii
		 $a10= "HKLMSoftwareGoogleUpdateClientState" fullword ascii
		 $a11= "HKLMSoftwareGoogleUpdateClientStateMedium" fullword ascii
		 $a12= "HKLMSoftwareMicrosoftWindows NTCurrentVersionNetworkCards" fullword ascii
		 $a13= "HKLMSoftwarePoliciesGoogleUpdate" fullword ascii
		 $a14= "[OpenCustomInfoFile failed][0x%08x]" fullword ascii
		 $a15= "[StartCrashReporter failed][0x%08x]" fullword ascii
		 $a16= "[StartCrashUploader() failed][0x%08x]" fullword ascii
		 $a17= "[StartProcessWithNoExceptionHandler][%s]" fullword ascii
		 $a18= "SYSTEMCurrentControlSetControlSession Manager" fullword ascii

		 $hex1= {246131303d2022484b}
		 $hex2= {246131313d2022484b}
		 $hex3= {246131323d2022484b}
		 $hex4= {246131333d2022484b}
		 $hex5= {246131343d20225b4f}
		 $hex6= {246131353d20225b53}
		 $hex7= {246131363d20225b53}
		 $hex8= {246131373d20225b53}
		 $hex9= {246131383d20225359}
		 $hex10= {2461313d20225b2530}
		 $hex11= {2461323d2022253038}
		 $hex12= {2461333d20227b4130}
		 $hex13= {2461343d20227b4334}
		 $hex14= {2461353d20227b4336}
		 $hex15= {2461363d202243536f}
		 $hex16= {2461373d20227b4431}
		 $hex17= {2461383d20225b4765}
		 $hex18= {2461393d2022484b43}
		 $hex19= {247331303d2022436c}
		 $hex20= {247331313d20224043}
		 $hex21= {247331323d20224043}
		 $hex22= {247331333d20224372}
		 $hex23= {247331343d20225b43}
		 $hex24= {247331353d20225b43}
		 $hex25= {247331363d20224353}
		 $hex26= {247331373d20226375}
		 $hex27= {247331383d20227b44}
		 $hex28= {247331393d20224465}
		 $hex29= {2473313d20225b2530}
		 $hex30= {247332303d20226465}
		 $hex31= {247332313d2022444f}
		 $hex32= {247332323d2022646f}
		 $hex33= {247332333d20225b47}
		 $hex34= {247332343d2022476f}
		 $hex35= {247332353d2022476f}
		 $hex36= {247332363d2022476f}
		 $hex37= {247332373d2022476f}
		 $hex38= {247332383d2022476f}
		 $hex39= {247332393d2022476f}
		 $hex40= {2473323d2022253038}
		 $hex41= {247333303d20225f47}
		 $hex42= {247333313d2022474f}
		 $hex43= {247333323d20224752}
		 $hex44= {247333333d2022484b}
		 $hex45= {247333343d2022484b}
		 $hex46= {247333353d2022484b}
		 $hex47= {247333363d2022484b}
		 $hex48= {247333373d2022484b}
		 $hex49= {247333383d2022484b}
		 $hex50= {247333393d2022484b}
		 $hex51= {2473333d20227b4130}
		 $hex52= {247334303d2022484b}
		 $hex53= {247334313d2022484b}
		 $hex54= {247334323d2022484b}
		 $hex55= {247334333d2022696e}
		 $hex56= {247334343d20224c61}
		 $hex57= {247334353d20224c6f}
		 $hex58= {247334363d20224c6f}
		 $hex59= {247334373d20225b4f}
		 $hex60= {247334383d20225065}
		 $hex61= {247334393d20222e70}
		 $hex62= {2473343d2022417373}
		 $hex63= {247335303d20225052}
		 $hex64= {247335313d20227265}
		 $hex65= {247335323d20222a2a}
		 $hex66= {247335333d2022736f}
		 $hex67= {247335343d20227370}
		 $hex68= {247335353d20225b53}
		 $hex69= {247335363d20225b53}
		 $hex70= {247335373d20225b53}
		 $hex71= {247335383d20225b53}
		 $hex72= {247335393d20225359}
		 $hex73= {2473353d2022424973}
		 $hex74= {247336303d20227569}
		 $hex75= {247336313d20227569}
		 $hex76= {247336323d2022756e}
		 $hex77= {247336333d20227570}
		 $hex78= {247336343d20224056}
		 $hex79= {247336353d2022582d}
		 $hex80= {247336363d2022582d}
		 $hex81= {247336373d2022582d}
		 $hex82= {2473363d202242582d}
		 $hex83= {2473373d202242582d}
		 $hex84= {2473383d20227b4334}
		 $hex85= {2473393d20227b4336}

	condition:
		10 of them
}
