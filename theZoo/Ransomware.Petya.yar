
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
		 date = "2022-01-20_04-42-53" 
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
		 $a1= "`anonymous-namespace'::detectFullVersionFromHomeDir" fullword ascii
		 $a2= "`anonymous-namespace'::extractEntryInMemory::operator ()" fullword ascii
		 $a3= "`anonymous-namespace'::InstalledJavaTrackerBase::next" fullword ascii
		 $a4= "`anonymous-namespace'::UpgradeCodeIterator::getTemplate" fullword ascii
		 $a5= ".?AV?$UpgradeCodeInstalledJavaTracker@$00$0CA@@?A0x49b81677@@" fullword ascii
		 $a6= ".?AV?$UpgradeCodeInstalledJavaTracker@$00$0EA@@?A0x49b81677@@" fullword ascii
		 $a7= ".?AV?$UpgradeCodeInstalledJavaTracker@$0A@$0CA@@?A0x49b81677@@" fullword ascii
		 $a8= ".?AV?$UpgradeCodeInstalledJavaTracker@$0A@$0EA@@?A0x49b81677@@" fullword ascii
		 $a9= ".?AVCallback@?5??DownloadFile@CDownloadManager@@EAGJPBD0@Z@" fullword ascii
		 $a10= ".?AVCursor@PlainTextFileConfigParser@settings_impl@@" fullword ascii
		 $a11= ".?AVDestroyAction@?4??destroy@BrowserWindow@ui@@QAEXXZ@" fullword ascii
		 $a12= ".?AVFixedValueValidator@?A0x36325356@settings_impl@@" fullword ascii
		 $a13= ".?AVIBuffer@PlainTextFileConfigParser@settings_impl@@" fullword ascii
		 $a14= ".?AVIKeyMapperFactory@KeyMapperBuilder@settings_impl@@" fullword ascii
		 $a15= ".?AVInavlidKeyError@ConfigValidator@settings_impl@@" fullword ascii
		 $a16= ".?AVInavlidValueError@ConfigValidator@settings_impl@@" fullword ascii
		 $a17= "CDownloadManager::DownloadFile::Callback::onProgress" fullword ascii
		 $a18= "ConvertStringSecurityDescriptorToSecurityDescriptorW" fullword ascii
		 $a19= "ExecProcessAsDesktopUser: pJavaShortCutItem->SetArguments(" fullword ascii
		 $a20= "ExecProcessAsDesktopUser: pJavaShortCutItem->SetPath(" fullword ascii
		 $a21= "FileUtils::`anonymous-namespace'::BatchDeleter::execute" fullword ascii
		 $a22= "https://javadl-esd-secure.oracle.com/update/%s/map-m-%s.xml" fullword ascii
		 $a23= "https://javadl-esd-secure.oracle.com/update/%s/map-%s.xml" fullword ascii
		 $a24= "JavaEnvironment::`anonymous-namespace'::toFilterFlags" fullword ascii
		 $a25= "JavaVersionDetails::Base::throwUnrecognizedVersionType" fullword ascii
		 $a26= "jscrub::`anonymous-namespace'::downloadBaselinesFile" fullword ascii
		 $a27= "msi::`anonymous-namespace'::CallbackTrigger::adapter" fullword ascii
		 $a28= "SOFTWAREMicrosoftWindowsCurrentVersionUninstall" fullword ascii
		 $a29= "ui::BrowserControl::BrowserExternal::GetIDsOfNames" fullword ascii

		 $hex1= {246131303d20222e3f}
		 $hex2= {246131313d20222e3f}
		 $hex3= {246131323d20222e3f}
		 $hex4= {246131333d20222e3f}
		 $hex5= {246131343d20222e3f}
		 $hex6= {246131353d20222e3f}
		 $hex7= {246131363d20222e3f}
		 $hex8= {246131373d20224344}
		 $hex9= {246131383d2022436f}
		 $hex10= {246131393d20224578}
		 $hex11= {2461313d202260616e}
		 $hex12= {246132303d20224578}
		 $hex13= {246132313d20224669}
		 $hex14= {246132323d20226874}
		 $hex15= {246132333d20226874}
		 $hex16= {246132343d20224a61}
		 $hex17= {246132353d20224a61}
		 $hex18= {246132363d20226a73}
		 $hex19= {246132373d20226d73}
		 $hex20= {246132383d2022534f}
		 $hex21= {246132393d20227569}
		 $hex22= {2461323d202260616e}
		 $hex23= {2461333d202260616e}
		 $hex24= {2461343d202260616e}
		 $hex25= {2461353d20222e3f41}
		 $hex26= {2461363d20222e3f41}
		 $hex27= {2461373d20222e3f41}
		 $hex28= {2461383d20222e3f41}
		 $hex29= {2461393d20222e3f41}
		 $hex30= {247331303d20224353}
		 $hex31= {247331313d20227b44}
		 $hex32= {247331323d2022444f}
		 $hex33= {247331333d20225b47}
		 $hex34= {247331343d2022476f}
		 $hex35= {247331353d20225f47}
		 $hex36= {247331363d2022474f}
		 $hex37= {247331373d2022484b}
		 $hex38= {247331383d2022484b}
		 $hex39= {247331393d2022484b}
		 $hex40= {2473313d20225b2530}
		 $hex41= {247332303d2022484b}
		 $hex42= {247332313d2022484b}
		 $hex43= {247332323d2022484b}
		 $hex44= {247332333d2022484b}
		 $hex45= {247332343d2022484b}
		 $hex46= {247332353d20225b4f}
		 $hex47= {247332363d20225065}
		 $hex48= {247332373d20222e70}
		 $hex49= {247332383d20225b53}
		 $hex50= {247332393d20225b53}
		 $hex51= {2473323d2022253038}
		 $hex52= {247333303d20225b53}
		 $hex53= {247333313d20225359}
		 $hex54= {247333323d20224056}
		 $hex55= {2473333d20227b4130}
		 $hex56= {2473343d202242582d}
		 $hex57= {2473353d20227b4334}
		 $hex58= {2473363d20227b4336}
		 $hex59= {2473373d2022404372}
		 $hex60= {2473383d2022437261}
		 $hex61= {2473393d20225b4372}

	condition:
		40 of them
}
