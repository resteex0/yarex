
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Ransomware_Petya 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Ransomware_Petya {
	meta: 
		 description= "theZoo_Ransomware_Petya Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-35-17" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "a92f13f3a1b3b39833d3cc336301b713"
		 hash2= "af2379cc4d607a45ac44d62135fb7015"

	strings:

	
 		 $s1= "[%02d/%02d/%02d %02d:%02d:%02d.%03d]" fullword wide
		 $s2= "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" fullword wide
		 $s3= "{A0C1F415-D2CE-4ddc-9B48-14E56FD55162}" fullword wide
		 $s4= "BX-GoogleUpdate-Interactivity" fullword wide
		 $s5= "{C4F406E5-F024-4e3f-89A7-D5AB7663C3CD}" fullword wide
		 $s6= "{C68009EA-1163-4498-8E93-D5C4E317D8CE}" fullword wide
		 $s7= "@CrashHandlerEnv_CrashInfo" fullword wide
		 $s8= "CrashHandlerLaunchedForMinidump" fullword wide
		 $s9= "[CrashHandler::RunUntilShutdown]" fullword wide
		 $s10= "CSoftwareGoogle%wsUsageStatsDaily" fullword wide
		 $s11= "{D19BAF17-7C87-467E-8D63-6C4B1C836373}" fullword wide
		 $s12= "DOracleJavajava.settings.cfg" fullword wide
		 $s13= "[GetCrashPipeName][GetProcessUser failed][0x%08x]" fullword wide
		 $s14= "GoogleCrashHandlerWorkerDesktop" fullword wide
		 $s15= "_Google_Update_logging_mutex_" fullword wide
		 $s16= "GOOGLE_UPDATE_NO_CRASH_HANDLER" fullword wide
		 $s17= "HKCUSoftwareGoogleUpdate" fullword wide
		 $s18= "HKCUSoftwareGoogleUpdateClientState" fullword wide
		 $s19= "HKLMSoftwareGoogleUpdate" fullword wide
		 $s20= "HKLMSoftwareGoogleUpdateClientState" fullword wide
		 $s21= "HKLMSoftwareGoogleUpdateClientStateMedium" fullword wide
		 $s22= "HKLMSoftwareGoogleUpdateDev" fullword wide
		 $s23= "HKLMSoftwareMicrosoftWindows NTCurrentVersionNetworkCards" fullword wide
		 $s24= "HKLMSoftwarePoliciesGoogleUpdate" fullword wide
		 $s25= "[OpenCustomInfoFile failed][0x%08x]" fullword wide
		 $s26= "PendingFileRenameOperations" fullword wide
		 $s27= "\\.pipeGoogleCrashServices" fullword wide
		 $s28= "[StartCrashReporter failed][0x%08x]" fullword wide
		 $s29= "[StartCrashUploader() failed][0x%08x]" fullword wide
		 $s30= "[StartProcessWithNoExceptionHandler][%s]" fullword wide
		 $s31= "SYSTEMCurrentControlSetControlSession Manager" fullword wide
		 $s32= "@VarFileInfoTranslation" fullword wide
		 $a1= ".?AV?$UpgradeCodeInstalledJavaTracker@$00$0CA@@?A0x49b81677@@" fullword ascii
		 $a2= ".?AV?$UpgradeCodeInstalledJavaTracker@$00$0EA@@?A0x49b81677@@" fullword ascii
		 $a3= ".?AV?$UpgradeCodeInstalledJavaTracker@$0A@$0CA@@?A0x49b81677@@" fullword ascii
		 $a4= ".?AV?$UpgradeCodeInstalledJavaTracker@$0A@$0EA@@?A0x49b81677@@" fullword ascii

		 $hex1= {2461313d20222e3f41}
		 $hex2= {2461323d20222e3f41}
		 $hex3= {2461333d20222e3f41}
		 $hex4= {2461343d20222e3f41}
		 $hex5= {247331303d20224353}
		 $hex6= {247331313d20227b44}
		 $hex7= {247331323d2022444f}
		 $hex8= {247331333d20225b47}
		 $hex9= {247331343d2022476f}
		 $hex10= {247331353d20225f47}
		 $hex11= {247331363d2022474f}
		 $hex12= {247331373d2022484b}
		 $hex13= {247331383d2022484b}
		 $hex14= {247331393d2022484b}
		 $hex15= {2473313d20225b2530}
		 $hex16= {247332303d2022484b}
		 $hex17= {247332313d2022484b}
		 $hex18= {247332323d2022484b}
		 $hex19= {247332333d2022484b}
		 $hex20= {247332343d2022484b}
		 $hex21= {247332353d20225b4f}
		 $hex22= {247332363d20225065}
		 $hex23= {247332373d20222e70}
		 $hex24= {247332383d20225b53}
		 $hex25= {247332393d20225b53}
		 $hex26= {2473323d2022253038}
		 $hex27= {247333303d20225b53}
		 $hex28= {247333313d20225359}
		 $hex29= {247333323d20224056}
		 $hex30= {2473333d20227b4130}
		 $hex31= {2473343d202242582d}
		 $hex32= {2473353d20227b4334}
		 $hex33= {2473363d20227b4336}
		 $hex34= {2473373d2022404372}
		 $hex35= {2473383d2022437261}
		 $hex36= {2473393d20225b4372}

	condition:
		24 of them
}
