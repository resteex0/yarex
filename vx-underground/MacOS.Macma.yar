
/*
   YARA Rule Set
   Author: resteex
   Identifier: MacOS_Macma 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_MacOS_Macma {
	meta: 
		 description= "MacOS_Macma Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_11-18-29" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1daba393eee9d8bdaf645157dae83990"
		 hash2= "282b7cc7884a7592709d88415ee4b9ae"
		 hash3= "2833b7480f3920ecf840c802d239b05c"
		 hash4= "2f9e31877fe6911ac70b26f935144adc"
		 hash5= "3e4de0eeefd2e1c024b41a4222285f74"
		 hash6= "59d8cabdde0a4a99e5fa908a3486e0f2"
		 hash7= "6714d89089c62045dbdbd75e74dd64ec"
		 hash8= "6b5cf5bf5cbf2f611f717790a3bb252e"
		 hash9= "cb3921b78a80ac2a545189ce30054a03"
		 hash10= "d15740e3612a56844208218c4e76e7bb"
		 hash11= "fda6368c08e22aa3a3a4a71b5270cd95"

	strings:

	
 		 $a1= "21CHandleFailSendThread11GetInstanceEvE20handleFailSendThread" fullword ascii
		 $a2= "7myCGEventCallbackP17__CGEventTapProxy11CGEventTypeP9__CGEventPv" fullword ascii
		 $a3= "application:didFailToRegisterForRemoteNotificationsWithError:" fullword ascii
		 $a4= "application:didRegisterForRemoteNotificationsWithDeviceToken:" fullword ascii
		 $a5= "com.AudioConverterFileConvertTest.AudioFileConverOperation.queue" fullword ascii
		 $a6= "*FindAndSaveAliceECDHParamEP24TAG_CDataECDHKeyExchangeR7ECDHKEY" fullword ascii
		 $a7= "FindAndSaveAliceECDHParamEP24TAG_CDataECDHKeyExchangeR7ECDHKEY" fullword ascii
		 $a8= "FindAndSaveBobAckECDHParamEP24TAG_CDataECDHKeyExchangeR7ECDHKEY" fullword ascii
		 $a9= "(Landroid/content/Context;Ljava/lang/String;)Ljava/util/List;" fullword ascii
		 $a10= "/Library/Caches/com.apple.xbs/Sources/arclite/arclite-65/source/" fullword ascii
		 $a11= "(Ljava/lang/String;Ljava/lang/ClassLoader;)Ljava/lang/String;" fullword ascii
		 $a12= "(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;" fullword ascii
		 $a13= "SetMagicCookieForFileP16OpaqueAudioQueueP17OpaqueAudioFileID" fullword ascii
		 $a14= "/string>" fullword ascii
		 $a15= "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit" fullword ascii
		 $a16= "/System/Library/Frameworks/Carbon.framework/Versions/A/Carbon" fullword ascii
		 $a17= "U7HandleDirZipQueueEP9FileQueueRNSt3__115__list_iteratorIS1_PvEE" fullword ascii
		 $a18= "/Users/%s/Library/Safari/Safari.app/Contents/MacOS/UpdateHelper" fullword ascii
		 $a19= "_Z18getPhoneNumberListP7_JNIEnvP8_jobjectS2_PSt6vectorISsSaISsEE" fullword ascii
		 $a20= "__ZGVZL30add_image_hook_autoreleasepoolPK11mach_headerlE7patches" fullword ascii
		 $a21= "__ZL36__arclite_object_setInstanceVariableP11objc_objectPKcPv" fullword ascii
		 $a22= "__ZL43__arclite_objc_retainAutoreleaseReturnValueP11objc_object" fullword ascii
		 $a23= "__ZL44__arclite_objc_retainAutoreleasedReturnValueP11objc_object" fullword ascii
		 $a24= "_ZN10CDDSRcvThr22HandleRecvDDSHeartBeatEP21TAG_CDataDDCHeartBeat" fullword ascii
		 $a25= "_ZN13PluginsMapper17saveOnePluginInfoEP7_JNIEnv15LocalPluginInfo" fullword ascii
		 $a26= "__ZN14CRCallACKQueue3putEP16RCallACKFuncInfoI16CRCallACKNullObjE" fullword ascii
		 $a27= "_ZN14CRCallACKQueue3putEP16RCallACKFuncInfoI16CRCallACKNullObjE" fullword ascii
		 $a28= "_ZN14ExternalClient21saveServerClientInfo2EP16CDDSServerOnline" fullword ascii
		 $a29= "__ZN15CTerminalThread26HandleTerminalConnectQueueEP10CDDSNetObj" fullword ascii
		 $a30= "__ZN16CBaseInfoManager24HandleCDDSReqMacBaseInfoEP10CDDSNetObj" fullword ascii
		 $a31= "__ZN16CTerminalManager23HandleCDDSTerminalInputEP10CDDSNetObj" fullword ascii
		 $a32= "__ZN16CTerminalManager24HandleCDDSTerminalOutputEP10CDDSNetObj" fullword ascii
		 $a33= "__ZN16CTerminalManager25HandleCDDSTerminalConnectEP10CDDSNetObj" fullword ascii
		 $a34= "_ZN16InnerTurnManager19add_ServerReq_TasksEP14ServerReqTasks" fullword ascii
		 $a35= "__ZN18CFileSystemManager24HandleCDDSReqMacFileListEP10CDDSNetObj" fullword ascii
		 $a36= "__ZN18CFileSystemManager24HandleCSearchFSThrNotifyEP10CDDSNetObj" fullword ascii
		 $a37= "__ZN19CDDSFTSRecvThrQueue15join_and_deleteEP14CDDSFTSRecvThr" fullword ascii
		 $a38= "__ZN19CDDSFTSSendThrQueue15join_and_deleteEP14CDDSFTSSendThr" fullword ascii
		 $a39= "_ZN19selfstart_javautils14getPackageNameEP7_JNIEnvP8_jobject" fullword ascii
		 $a40= "_ZN19selfstart_javautils17getPackageManagerEP7_JNIEnvP8_jobject" fullword ascii
		 $a41= "__ZN20CFileDownLoadManager18HandleCDDSFileInfoEP10CDDSNetObj" fullword ascii
		 $a42= "_ZN21CDDSClientBaseStation31CDDSClientBaseStation_CLASSNAMEE" fullword ascii
		 $a43= "_ZN21CDDSClientOnlineToMac31CDDSClientOnlineToMac_CLASSNAMEE" fullword ascii
		 $a44= "_ZN21CDDSClientPhoneParams31CDDSClientPhoneParams_CLASSNAMEE" fullword ascii
		 $a45= "_ZN21CDDSClientPictureInfo31CDDSClientPictureInfo_CLASSNAMEE" fullword ascii
		 $a46= "_ZN21CDDSClientReqSeedInfo31CDDSClientReqSeedInfo_CLASSNAMEE" fullword ascii
		 $a47= "_ZN21CDDSClientSNSFilePath31CDDSClientSNSFilePath_CLASSNAMEE" fullword ascii
		 $a48= "_ZN21CDDSObjTransferStatus31CDDSObjTransferStatus_CLASSNAMEE" fullword ascii
		 $a49= "_ZN21CDDSPhoneParamsChange31CDDSPhoneParamsChange_CLASSNAMEE" fullword ascii
		 $a50= "__ZN21CDDSScreenCaptureInfo31CDDSScreenCaptureInfo_CLASSNAMEE" fullword ascii
		 $a51= "_ZN21CDDSServerBaseStation31CDDSServerBaseStation_CLASSNAMEE" fullword ascii
		 $a52= "_ZN21CDDSServerPhoneParams31CDDSServerPhoneParams_CLASSNAMEE" fullword ascii
		 $a53= "_ZN21CDDSServerPictureInfo31CDDSServerPictureInfo_CLASSNAMEE" fullword ascii
		 $a54= "_ZN21CDDSServerReqContacts31CDDSServerReqContacts_CLASSNAMEE" fullword ascii
		 $a55= "_ZN21CDDSServerReqFileInfo31CDDSServerReqFileInfo_CLASSNAMEE" fullword ascii
		 $a56= "_ZN21CDDSServerReqLocation31CDDSServerReqLocation_CLASSNAMEE" fullword ascii
		 $a57= "_ZN21CDDSServerReqPowerOff31CDDSServerReqPowerOff_CLASSNAMEE" fullword ascii
		 $a58= "_ZN21CDDSServerSetShutMode31CDDSServerSetShutMode_CLASSNAMEE" fullword ascii
		 $a59= "_ZN21CDDSServerSNSFilePath31CDDSServerSNSFilePath_CLASSNAMEE" fullword ascii
		 $a60= "__ZN21CDDSStopMacSearchFile31CDDSStopMacSearchFile_CLASSNAMEE" fullword ascii
		 $a61= "__ZN21CDDSZipDirRequestInfo31CDDSZipDirRequestInfo_CLASSNAMEE" fullword ascii
		 $a62= "_ZN21CStartFileDownloadObj31CStartFileDownloadObj_CLASSNAMEE" fullword ascii
		 $a63= "__ZN22CDDSChangeDDSPwdStatus30CDDSChangeDDSPwdStatus_CREATOREv" fullword ascii
		 $a64= "_ZN22CDDSChangeDDSPwdStatus30CDDSChangeDDSPwdStatus_CREATOREv" fullword ascii
		 $a65= "__ZN22CDDSChangeDDSPwdStatus30CDDSChangeDDSPwdStatus_VERSIONE" fullword ascii
		 $a66= "_ZN22CDDSChangeDDSPwdStatus30CDDSChangeDDSPwdStatus_VERSIONE" fullword ascii
		 $a67= "__ZN22CDDSChangeDDSPwdStatus32CDDSChangeDDSPwdStatus_CLASSNAMEE" fullword ascii
		 $a68= "_ZN22CDDSChangeDDSPwdStatus32CDDSChangeDDSPwdStatus_CLASSNAMEE" fullword ascii
		 $a69= "_ZN22CDDSClientCurrentPlugs30CDDSClientCurrentPlugs_CREATOREv" fullword ascii
		 $a70= "_ZN22CDDSClientCurrentPlugs30CDDSClientCurrentPlugs_VERSIONE" fullword ascii
		 $a71= "_ZN22CDDSClientCurrentPlugs32CDDSClientCurrentPlugs_CLASSNAMEE" fullword ascii
		 $a72= "_ZN22CDDSClientInjectStatus30CDDSClientInjectStatus_CREATOREv" fullword ascii
		 $a73= "_ZN22CDDSClientInjectStatus30CDDSClientInjectStatus_VERSIONE" fullword ascii
		 $a74= "_ZN22CDDSClientInjectStatus32CDDSClientInjectStatus_CLASSNAMEE" fullword ascii
		 $a75= "_ZN22CDDSClientNearWifiInfo30CDDSClientNearWifiInfo_CREATOREv" fullword ascii
		 $a76= "_ZN22CDDSClientNearWifiInfo30CDDSClientNearWifiInfo_VERSIONE" fullword ascii
		 $a77= "_ZN22CDDSClientNearWifiInfo32CDDSClientNearWifiInfo_CLASSNAMEE" fullword ascii
		 $a78= "_ZN22CDDSClientOfflineToMac30CDDSClientOfflineToMac_CREATOREv" fullword ascii
		 $a79= "_ZN22CDDSClientOfflineToMac30CDDSClientOfflineToMac_VERSIONE" fullword ascii
		 $a80= "_ZN22CDDSClientOfflineToMac32CDDSClientOfflineToMac_CLASSNAMEE" fullword ascii
		 $a81= "_ZN22CDDSClientStatusUpdate30CDDSClientStatusUpdate_CREATOREv" fullword ascii
		 $a82= "_ZN22CDDSClientStatusUpdate30CDDSClientStatusUpdate_VERSIONE" fullword ascii
		 $a83= "_ZN22CDDSClientStatusUpdate32CDDSClientStatusUpdate_CLASSNAMEE" fullword ascii
		 $a84= "_ZN22CDDSClientWebLogModify30CDDSClientWebLogModify_CREATOREv" fullword ascii
		 $a85= "_ZN22CDDSClientWebLogModify30CDDSClientWebLogModify_VERSIONE" fullword ascii
		 $a86= "_ZN22CDDSClientWebLogModify32CDDSClientWebLogModify_CLASSNAMEE" fullword ascii
		 $a87= "__ZN22CDDSExecuteFileRequest30CDDSExecuteFileRequest_VERSIONE" fullword ascii
		 $a88= "__ZN22CDDSExecuteFileRequest32CDDSExecuteFileRequest_CLASSNAMEE" fullword ascii
		 $a89= "__ZN22CDDSFileTransferStatus30CDDSFileTransferStatus_CREATOREv" fullword ascii
		 $a90= "_ZN22CDDSFileTransferStatus30CDDSFileTransferStatus_CREATOREv" fullword ascii
		 $a91= "__ZN22CDDSFileTransferStatus30CDDSFileTransferStatus_VERSIONE" fullword ascii
		 $a92= "_ZN22CDDSFileTransferStatus30CDDSFileTransferStatus_VERSIONE" fullword ascii
		 $a93= "__ZN22CDDSFileTransferStatus32CDDSFileTransferStatus_CLASSNAMEE" fullword ascii
		 $a94= "_ZN22CDDSFileTransferStatus32CDDSFileTransferStatus_CLASSNAMEE" fullword ascii
		 $a95= "__ZN22CDDSMacSearchFileReply30CDDSMacSearchFileReply_VERSIONE" fullword ascii
		 $a96= "__ZN22CDDSMacSearchFileReply32CDDSMacSearchFileReply_CLASSNAMEE" fullword ascii
		 $a97= "_ZN22CDDSServerInjectStatus30CDDSServerInjectStatus_CREATOREv" fullword ascii
		 $a98= "_ZN22CDDSServerInjectStatus30CDDSServerInjectStatus_VERSIONE" fullword ascii
		 $a99= "_ZN22CDDSServerInjectStatus32CDDSServerInjectStatus_CLASSNAMEE" fullword ascii
		 $a100= "_ZN22CDDSServerNearWifiInfo30CDDSServerNearWifiInfo_CREATOREv" fullword ascii
		 $a101= "_ZN22CDDSServerNearWifiInfo30CDDSServerNearWifiInfo_VERSIONE" fullword ascii
		 $a102= "_ZN22CDDSServerNearWifiInfo32CDDSServerNearWifiInfo_CLASSNAMEE" fullword ascii
		 $a103= "_ZN22CDDSServerOnlineInform30CDDSServerOnlineInform_CREATOREv" fullword ascii
		 $a104= "_ZN22CDDSServerOnlineInform30CDDSServerOnlineInform_VERSIONE" fullword ascii
		 $a105= "_ZN22CDDSServerOnlineInform32CDDSServerOnlineInform_CLASSNAMEE" fullword ascii
		 $a106= "_ZN22CDDSServerPluginUpdate30CDDSServerPluginUpdate_CREATOREv" fullword ascii
		 $a107= "_ZN22CDDSServerPluginUpdate30CDDSServerPluginUpdate_VERSIONE" fullword ascii
		 $a108= "_ZN22CDDSServerPluginUpdate32CDDSServerPluginUpdate_CLASSNAMEE" fullword ascii
		 $a109= "_ZN22CDDSServerReqAppBackup30CDDSServerReqAppBackup_CREATOREv" fullword ascii
		 $a110= "_ZN22CDDSServerReqAppBackup30CDDSServerReqAppBackup_VERSIONE" fullword ascii
		 $a111= "_ZN22CDDSServerReqAppBackup32CDDSServerReqAppBackup_CLASSNAMEE" fullword ascii
		 $a112= "_ZN22CDDSServerReqCreateDir30CDDSServerReqCreateDir_CREATOREv" fullword ascii
		 $a113= "_ZN22CDDSServerReqCreateDir30CDDSServerReqCreateDir_VERSIONE" fullword ascii
		 $a114= "_ZN22CDDSServerReqCreateDir32CDDSServerReqCreateDir_CLASSNAMEE" fullword ascii
		 $a115= "_ZN22CDDSServerReqFileInDir30CDDSServerReqFileInDir_CREATOREv" fullword ascii
		 $a116= "_ZN22CDDSServerReqFileInDir30CDDSServerReqFileInDir_VERSIONE" fullword ascii
		 $a117= "_ZN22CDDSServerReqFileInDir32CDDSServerReqFileInDir_CLASSNAMEE" fullword ascii
		 $a118= "_ZN22CDDSServerReqRunStatus30CDDSServerReqRunStatus_CREATOREv" fullword ascii
		 $a119= "_ZN22CDDSServerReqRunStatus30CDDSServerReqRunStatus_VERSIONE" fullword ascii
		 $a120= "_ZN22CDDSServerReqRunStatus32CDDSServerReqRunStatus_CLASSNAMEE" fullword ascii
		 $a121= "_ZN22CDDSServerReqScreenCap30CDDSServerReqScreenCap_CREATOREv" fullword ascii
		 $a122= "_ZN22CDDSServerReqScreenCap30CDDSServerReqScreenCap_VERSIONE" fullword ascii
		 $a123= "_ZN22CDDSServerReqScreenCap32CDDSServerReqScreenCap_CLASSNAMEE" fullword ascii
		 $a124= "_ZN22CDDSServerReqUnInstall30CDDSServerReqUnInstall_CREATOREv" fullword ascii
		 $a125= "_ZN22CDDSServerReqUnInstall30CDDSServerReqUnInstall_VERSIONE" fullword ascii
		 $a126= "_ZN22CDDSServerReqUnInstall32CDDSServerReqUnInstall_CLASSNAMEE" fullword ascii
		 $a127= "_ZN22CDDSServerStopTerminal30CDDSServerStopTerminal_CREATOREv" fullword ascii
		 $a128= "_ZN22CDDSServerStopTerminal30CDDSServerStopTerminal_VERSIONE" fullword ascii
		 $a129= "_ZN22CDDSServerStopTerminal32CDDSServerStopTerminal_CLASSNAMEE" fullword ascii
		 $a130= "_ZN22CDDSServerWebLogModify30CDDSServerWebLogModify_CREATOREv" fullword ascii
		 $a131= "_ZN22CDDSServerWebLogModify30CDDSServerWebLogModify_VERSIONE" fullword ascii
		 $a132= "_ZN22CDDSServerWebLogModify32CDDSServerWebLogModify_CLASSNAMEE" fullword ascii
		 $a133= "__ZN22CDDSTerminalDisConnect30CDDSTerminalDisConnect_VERSIONE" fullword ascii
		 $a134= "__ZN22CDDSTerminalDisConnect32CDDSTerminalDisConnect_CLASSNAMEE" fullword ascii
		 $a135= "_ZN23CDDSClientAutoEnvStatus31CDDSClientAutoEnvStatus_CREATOREv" fullword ascii
		 $a136= "_ZN23CDDSClientAutoEnvStatus31CDDSClientAutoEnvStatus_VERSIONE" fullword ascii
		 $a137= "_ZN23CDDSClientAutoEnvStatus33CDDSClientAutoEnvStatus_CLASSNAMEE" fullword ascii
		 $a138= "_ZN23CDDSClientCallLogModify31CDDSClientCallLogModify_CREATOREv" fullword ascii
		 $a139= "_ZN23CDDSClientCallLogModify31CDDSClientCallLogModify_VERSIONE" fullword ascii
		 $a140= "_ZN23CDDSClientCallLogModify33CDDSClientCallLogModify_CLASSNAMEE" fullword ascii
		 $a141= "_ZN23CDDSServerAutoEnvStatus31CDDSServerAutoEnvStatus_CREATOREv" fullword ascii
		 $a142= "_ZN23CDDSServerAutoEnvStatus31CDDSServerAutoEnvStatus_VERSIONE" fullword ascii
		 $a143= "_ZN23CDDSServerAutoEnvStatus33CDDSServerAutoEnvStatus_CLASSNAMEE" fullword ascii
		 $a144= "_ZN23CDDSServerCallLogModify31CDDSServerCallLogModify_CREATOREv" fullword ascii
		 $a145= "_ZN23CDDSServerCallLogModify31CDDSServerCallLogModify_VERSIONE" fullword ascii
		 $a146= "_ZN23CDDSServerCallLogModify33CDDSServerCallLogModify_CLASSNAMEE" fullword ascii
		 $a147= "_ZN23CDDSServerForegroundApp31CDDSServerForegroundApp_CREATOREv" fullword ascii
		 $a148= "_ZN23CDDSServerForegroundApp31CDDSServerForegroundApp_VERSIONE" fullword ascii
		 $a149= "_ZN23CDDSServerForegroundApp33CDDSServerForegroundApp_CLASSNAMEE" fullword ascii
		 $a150= "_ZN23CDDSServerReqExploitLog31CDDSServerReqExploitLog_CREATOREv" fullword ascii
		 $a151= "_ZN23CDDSServerReqExploitLog31CDDSServerReqExploitLog_VERSIONE" fullword ascii
		 $a152= "_ZN23CDDSServerReqExploitLog33CDDSServerReqExploitLog_CLASSNAMEE" fullword ascii
		 $a153= "_ZN23CDDSServerReqInstallApp31CDDSServerReqInstallApp_CREATOREv" fullword ascii
		 $a154= "_ZN23CDDSServerReqInstallApp31CDDSServerReqInstallApp_VERSIONE" fullword ascii
		 $a155= "_ZN23CDDSServerReqInstallApp33CDDSServerReqInstallApp_CLASSNAMEE" fullword ascii
		 $a156= "_ZN23CDDSServerReqRunningApp31CDDSServerReqRunningApp_CREATOREv" fullword ascii
		 $a157= "_ZN23CDDSServerReqRunningApp31CDDSServerReqRunningApp_VERSIONE" fullword ascii
		 $a158= "_ZN23CDDSServerReqRunningApp33CDDSServerReqRunningApp_CLASSNAMEE" fullword ascii
		 $a159= "_ZN23CDDSServerReqSetAutoEnv31CDDSServerReqSetAutoEnv_CREATOREv" fullword ascii
		 $a160= "_ZN23CDDSServerReqSetAutoEnv31CDDSServerReqSetAutoEnv_VERSIONE" fullword ascii
		 $a161= "_ZN23CDDSServerReqSetAutoEnv33CDDSServerReqSetAutoEnv_CLASSNAMEE" fullword ascii
		 $a162= "_ZN23CDDSServerScreenCapList31CDDSServerScreenCapList_CREATOREv" fullword ascii
		 $a163= "_ZN23CDDSServerScreenCapList31CDDSServerScreenCapList_VERSIONE" fullword ascii
		 $a164= "_ZN23CDDSServerScreenCapList33CDDSServerScreenCapList_CLASSNAMEE" fullword ascii
		 $a165= "_ZN23CDDSServerStartTerminal31CDDSServerStartTerminal_CREATOREv" fullword ascii
		 $a166= "_ZN23CDDSServerStartTerminal31CDDSServerStartTerminal_VERSIONE" fullword ascii
		 $a167= "_ZN23CDDSServerStartTerminal33CDDSServerStartTerminal_CLASSNAMEE" fullword ascii
		 $a168= "_ZN23CDDSServerStopEnvRecord31CDDSServerStopEnvRecord_CREATOREv" fullword ascii
		 $a169= "_ZN23CDDSServerStopEnvRecord31CDDSServerStopEnvRecord_VERSIONE" fullword ascii
		 $a170= "_ZN23CDDSServerStopEnvRecord33CDDSServerStopEnvRecord_CLASSNAMEE" fullword ascii
		 $a171= "_ZN23CDDSServerTerminalInput31CDDSServerTerminalInput_CREATOREv" fullword ascii
		 $a172= "_ZN23CDDSServerTerminalInput31CDDSServerTerminalInput_VERSIONE" fullword ascii
		 $a173= "_ZN23CDDSServerTerminalInput33CDDSServerTerminalInput_CLASSNAMEE" fullword ascii
		 $a174= "_ZN23PluginsFuncEnableMapper21queryClientIdByFunKeyEP7_JNIEnvi" fullword ascii
		 $a175= "_ZN24CDDSClientContactsModify32CDDSClientContactsModify_VERSIONE" fullword ascii
		 $a176= "_ZN24CDDSClientExploitLogInfo32CDDSClientExploitLogInfo_VERSIONE" fullword ascii
		 $a177= "_ZN24CDDSClientTerminalOutput32CDDSClientTerminalOutput_VERSIONE" fullword ascii
		 $a178= "_ZN24CDDSPassiveConnectStatus32CDDSPassiveConnectStatus_VERSIONE" fullword ascii
		 $a179= "_ZN24CDDSPluginUpdateComplete32CDDSPluginUpdateComplete_VERSIONE" fullword ascii
		 $a180= "_ZN24CDDSServerContactsModify32CDDSServerContactsModify_VERSIONE" fullword ascii
		 $a181= "_ZN24CDDSServerExploitLogInfo32CDDSServerExploitLogInfo_VERSIONE" fullword ascii
		 $a182= "_ZN24CDDSServerOfflineCommand32CDDSServerOfflineCommand_VERSIONE" fullword ascii
		 $a183= "_ZN24CDDSServerReqBaseStation32CDDSServerReqBaseStation_VERSIONE" fullword ascii
		 $a184= "_ZN24CDDSServerReqTakePicture32CDDSServerReqTakePicture_VERSIONE" fullword ascii
		 $a185= "_ZN24CDDSServerStartEnvRecord32CDDSServerStartEnvRecord_VERSIONE" fullword ascii
		 $a186= "_ZN24CDDSServerStopCallRecord32CDDSServerStopCallRecord_VERSIONE" fullword ascii
		 $a187= "_ZN24CDDSServerTerminalOutput32CDDSServerTerminalOutput_VERSIONE" fullword ascii
		 $a188= "_ZN24CFileDownloadCompleteObj32CFileDownloadCompleteObj_VERSIONE" fullword ascii
		 $a189= "_ZN27CDDServerAutoTakePictureSet11UnserializeERN3YYZ6ParcelE" fullword ascii
		 $a190= "_ZN27CDDSServerRecordInfoHistory11UnserializeERN3YYZ6ParcelE" fullword ascii
		 $a191= "__ZN28CDDSAutoScreenCaptureRequest11UnserializeERN3YYZ6ParcelE" fullword ascii
		 $a192= "_ZN28CDDSClientReqAutoWorkerParam11UnserializeERN3YYZ6ParcelE" fullword ascii
		 $a193= "_ZN28CDDSServerReqSearchFileInDir11UnserializeERN3YYZ6ParcelE" fullword ascii
		 $a194= "_ZN28CDDSServerSetAutoTakePicture11UnserializeERN3YYZ6ParcelE" fullword ascii
		 $a195= "_ZN29CDDSServerSetShutPowerOffTime11UnserializeERN3YYZ6ParcelE" fullword ascii
		 $a196= "_ZN31CDDSServerOfflineTakePictureSet11UnserializeERN3YYZ6ParcelE" fullword ascii
		 $a197= "_ZN31CDDSServerOfflineTakePictureSet9SerializeERN3YYZ6ParcelE" fullword ascii
		 $a198= "_ZN32CDDSClientAutoWorkerFileDownload9SerializeERN3YYZ6ParcelE" fullword ascii
		 $a199= "__ZN33CDDSScreenCaptureParameterRequest9SerializeERN3YYZ6ParcelE" fullword ascii
		 $a200= "__ZN3YYZ12MonitorQueueIP21AutoScreenCaptureInfoE7try_getERS2_" fullword ascii
		 $a201= "_ZN3YYZ6Thread9AddNotifyEPNS_13CInputHandlerEPSt6vectorIiSaIiEE" fullword ascii
		 $a202= "__ZN7CDDSIfi26FindOrAddECDHClientKeyInfoERK10ECDHClientR7ECDHKEY" fullword ascii
		 $a203= "_ZN7CDDSIfi26FindOrAddECDHClientKeyInfoERK10ECDHClientR7ECDHKEY" fullword ascii
		 $a204= "_ZN7_JNIEnv23CallStaticBooleanMethodEP7_jclassP10_jmethodIDz" fullword ascii
		 $a205= "_ZNKSt12ctype_bynameIwE10do_scan_isENSt10ctype_base4maskEPKwS4_" fullword ascii
		 $a206= "_ZNKSt12ctype_bynameIwE11do_scan_notENSt10ctype_base4maskEPKwS4_" fullword ascii
		 $a207= "_ZNKSt14codecvt_bynameIwc9mbstate_tE10do_unshiftERS0_PcS3_RS3_" fullword ascii
		 $a208= "@__ZNKSt3__119__shared_weak_count13__get_deleterERKSt9type_info" fullword ascii
		 $a209= "__ZNKSt3__119__shared_weak_count13__get_deleterERKSt9type_info" fullword ascii
		 $a210= "@__ZNKSt3__120__vector_base_commonILb1EE20__throw_length_errorEv" fullword ascii
		 $a211= "__ZNKSt3__120__vector_base_commonILb1EE20__throw_length_errorEv" fullword ascii
		 $a212= "__ZNKSt3__121__basic_string_commonILb1EE20__throw_length_errorEv" fullword ascii
		 $a213= "__ZNKSt3__16vectorI10CINIStructNS_9allocatorIS1_EEE8max_sizeEv" fullword ascii
		 $a214= "__ZNKSt3__16vectorI9CTransObjNS_9allocatorIS1_EEE8max_sizeEv" fullword ascii
		 $a215= "__ZNKSt3__16vectorIP4CININS_9allocatorIS2_EEE14__annotate_newEm" fullword ascii
		 $a216= "_ZNSt13basic_filebufIcSt11char_traitsIcEE18_M_exit_input_modeEv" fullword ascii
		 $a217= "_ZNSt15basic_stringbufIcSt11char_traitsIcESaIcEE10_M_xsputncEci" fullword ascii
		 $a218= "_ZNSt15basic_stringbufIcSt11char_traitsIcESaIcEE6xsputnEPKci" fullword ascii
		 $a219= "_ZNSt15basic_stringbufIcSt11char_traitsIcESaIcEE7seekoffElii" fullword ascii
		 $a220= "_ZNSt15basic_stringbufIcSt11char_traitsIcESaIcEE9pbackfailEi" fullword ascii
		 $a221= "_ZNSt15basic_stringbufIcSt11char_traitsIcESaIcEE9underflowEv" fullword ascii
		 $a222= "_ZNSt15insert_iteratorISt3setI4IP327IP32_LTSaIS1_EEEaSERKS1_" fullword ascii
		 $a223= "__ZNSt3__110__list_impI15PRESENDFILETASKNS_9allocatorIS1_EEED2Ev" fullword ascii
		 $a224= "__ZNSt3__110__list_impI9CDataGUIDNS_9allocatorIS1_EEE5clearEv" fullword ascii
		 $a225= "__ZNSt3__110__list_impIP10CDDSNetObjNS_9allocatorIS2_EEE5clearEv" fullword ascii
		 $a226= "__ZNSt3__110__list_impIP10CDDSNetObjNS_9allocatorIS2_EEED2Ev" fullword ascii
		 $a227= "__ZNSt3__110__list_impIP14CDDSFTSRecvThrNS_9allocatorIS2_EEED2Ev" fullword ascii
		 $a228= "__ZNSt3__110__list_impIP14CDDSFTSSendThrNS_9allocatorIS2_EEED2Ev" fullword ascii
		 $a229= "__ZNSt3__110__list_impIP9CDataHeadNS_9allocatorIS2_EEE5clearEv" fullword ascii
		 $a230= "__ZNSt3__110__list_impIP9CDataWaitNS_9allocatorIS2_EEE5clearEv" fullword ascii
		 $a231= "__ZNSt3__110__list_impIP9CTransObjNS_9allocatorIS2_EEE5clearEv" fullword ascii
		 $a232= "__ZNSt3__110__list_impIP9FileQueueNS_9allocatorIS2_EEE5clearEv" fullword ascii
		 $a233= "@__ZNSt3__113basic_istreamIcNS_11char_traitsIcEEE6sentryC1ERS3_b" fullword ascii
		 $a234= "__ZNSt3__113basic_istreamIcNS_11char_traitsIcEEE6sentryC1ERS3_b" fullword ascii
		 $a235= "@__ZNSt3__113basic_istreamIcNS_11char_traitsIcEEE7getlineEPclc" fullword ascii
		 $a236= "__ZNSt3__113basic_istreamIcNS_11char_traitsIcEEE7getlineEPclc" fullword ascii
		 $a237= "@__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_" fullword ascii
		 $a238= "__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_" fullword ascii
		 $a239= "__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC2ERS3_" fullword ascii
		 $a240= "@__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryD1Ev" fullword ascii
		 $a241= "__ZNSt3__113__vector_baseI10CINIStructNS_9allocatorIS1_EEED2Ev" fullword ascii
		 $a242= "__ZNSt3__113__vector_baseI9CTransObjNS_9allocatorIS1_EEED2Ev" fullword ascii
		 $a243= "__ZNSt3__114__split_bufferI10CINIStructRNS_9allocatorIS1_EEED1Ev" fullword ascii
		 $a244= "__ZNSt3__114__split_bufferI10CINIStructRNS_9allocatorIS1_EEED2Ev" fullword ascii
		 $a245= "__ZNSt3__114__split_bufferI8FileInfoRNS_9allocatorIS1_EEED1Ev" fullword ascii
		 $a246= "__ZNSt3__114__split_bufferI8FileInfoRNS_9allocatorIS1_EEED2Ev" fullword ascii
		 $a247= "__ZNSt3__114__split_bufferI9CTransObjRNS_9allocatorIS1_EEED1Ev" fullword ascii
		 $a248= "__ZNSt3__114__split_bufferI9CTransObjRNS_9allocatorIS1_EEED2Ev" fullword ascii
		 $a249= "__ZNSt3__114__split_bufferIP4CINIRNS_9allocatorIS2_EEEC1EmmS5_" fullword ascii
		 $a250= "__ZNSt3__114__split_bufferIP4CINIRNS_9allocatorIS2_EEEC2EmmS5_" fullword ascii
		 $a251= "@__ZNSt3__115basic_streambufIcNS_11char_traitsIcEEE4swapERS3_" fullword ascii
		 $a252= "__ZNSt3__115basic_streambufIcNS_11char_traitsIcEEE4swapERS3_" fullword ascii
		 $a253= "@__ZNSt3__115basic_streambufIcNS_11char_traitsIcEEE6setbufEPcl" fullword ascii
		 $a254= "__ZNSt3__115basic_streambufIcNS_11char_traitsIcEEE6setbufEPcl" fullword ascii
		 $a255= "@__ZNSt3__115basic_streambufIcNS_11char_traitsIcEEE6xsgetnEPcl" fullword ascii
		 $a256= "__ZNSt3__115basic_streambufIcNS_11char_traitsIcEEE6xsgetnEPcl" fullword ascii
		 $a257= "@__ZNSt3__115basic_streambufIcNS_11char_traitsIcEEE6xsputnEPKcl" fullword ascii
		 $a258= "__ZNSt3__115basic_streambufIcNS_11char_traitsIcEEE6xsputnEPKcl" fullword ascii
		 $a259= "@__ZNSt3__115basic_streambufIcNS_11char_traitsIcEEE9showmanycEv" fullword ascii
		 $a260= "__ZNSt3__115basic_streambufIcNS_11char_traitsIcEEE9showmanycEv" fullword ascii
		 $a261= "__ZNSt3__14listI9CDataGUIDNS_9allocatorIS1_EEE9push_backERKS1_" fullword ascii
		 $a262= "__ZNSt3__14listIP10CDDSNetObjNS_9allocatorIS2_EEE9pop_frontEv" fullword ascii
		 $a263= "__ZNSt3__14listIP18ScreenCaptureQueueNS_9allocatorIS2_EEED1Ev" fullword ascii
		 $a264= "__ZNSt3__14listIP18ScreenCaptureQueueNS_9allocatorIS2_EEED2Ev" fullword ascii
		 $a265= "__ZNSt3__14listIP21AutoScreenCaptureInfoNS_9allocatorIS2_EEED1Ev" fullword ascii
		 $a266= "__ZNSt3__14listIP21AutoScreenCaptureInfoNS_9allocatorIS2_EEED2Ev" fullword ascii
		 $a267= "__ZNSt3__14listIP9CDataHeadNS_9allocatorIS2_EEE9push_backERKS2_" fullword ascii
		 $a268= "__ZNSt3__14listIP9CDataWaitNS_9allocatorIS2_EEE9push_backERKS2_" fullword ascii
		 $a269= "__ZNSt3__14listIP9CTransObjNS_9allocatorIS2_EEE9push_backERKS2_" fullword ascii
		 $a270= "__ZNSt3__14listIP9FileQueueNS_9allocatorIS2_EEE9push_backERKS2_" fullword ascii
		 $a271= "__ZNSt3__16vectorI10CINIStructNS_9allocatorIS1_EEE8allocateEm" fullword ascii
		 $a272= "_ZNSt3mapIiP10PluginRespSt4lessIiESaISt4pairIKiS1_EEE5eraseERS5_" fullword ascii
		 $a273= "_ZNSt3mapISs7AppInfoSt4lessISsESaISt4pairIKSsS0_EEE5eraseERS4_" fullword ascii
		 $a274= "_ZNSt4priv17_Rb_tree_iteratorI4IP32NS_11_SetTraitsTIS1_EEEppEv" fullword ascii
		 $a275= "_ZSt14_Destroy_RangeISt16reverse_iteratorIP10FuncEnableEEvT_S4_" fullword ascii
		 $a276= "__ZThn168_N27CReadOutputThrForProcRunner12InputHandlerEiPKvi" fullword ascii
		 $a277= "_ZThn8_NSt18basic_stringstreamIcSt11char_traitsIcESaIcEED0Ev" fullword ascii
		 $a278= "_ZThn8_NSt18basic_stringstreamIcSt11char_traitsIcESaIcEED1Ev" fullword ascii
		 $a279= "_ZTv0_n12_NSt18basic_stringstreamIcSt11char_traitsIcESaIcEED0Ev" fullword ascii
		 $a280= "_ZTv0_n12_NSt18basic_stringstreamIcSt11char_traitsIcESaIcEED1Ev" fullword ascii
		 $a281= "_ZTv0_n12_NSt19basic_ostringstreamIcSt11char_traitsIcESaIcEED0Ev" fullword ascii
		 $a282= "_ZTv0_n12_NSt19basic_ostringstreamIcSt11char_traitsIcESaIcEED1Ev" fullword ascii
		 $a283= "@__ZTv0_n24_NSt3__113basic_ostreamIcNS_11char_traitsIcEEED0Ev" fullword ascii
		 $a284= "__ZTv0_n24_NSt3__113basic_ostreamIcNS_11char_traitsIcEEED0Ev" fullword ascii
		 $a285= "@__ZTv0_n24_NSt3__113basic_ostreamIcNS_11char_traitsIcEEED1Ev" fullword ascii
		 $a286= "__ZTv0_n24_NSt3__113basic_ostreamIcNS_11char_traitsIcEEED1Ev" fullword ascii
		 $a287= "__ZZL30add_image_hook_autoreleasepoolPK11mach_headerlE7patches" fullword ascii

		 $hex1= {24613130303d20225f}
		 $hex2= {24613130313d20225f}
		 $hex3= {24613130323d20225f}
		 $hex4= {24613130333d20225f}
		 $hex5= {24613130343d20225f}
		 $hex6= {24613130353d20225f}
		 $hex7= {24613130363d20225f}
		 $hex8= {24613130373d20225f}
		 $hex9= {24613130383d20225f}
		 $hex10= {24613130393d20225f}
		 $hex11= {246131303d20222f4c}
		 $hex12= {24613131303d20225f}
		 $hex13= {24613131313d20225f}
		 $hex14= {24613131323d20225f}
		 $hex15= {24613131333d20225f}
		 $hex16= {24613131343d20225f}
		 $hex17= {24613131353d20225f}
		 $hex18= {24613131363d20225f}
		 $hex19= {24613131373d20225f}
		 $hex20= {24613131383d20225f}
		 $hex21= {24613131393d20225f}
		 $hex22= {246131313d2022284c}
		 $hex23= {24613132303d20225f}
		 $hex24= {24613132313d20225f}
		 $hex25= {24613132323d20225f}
		 $hex26= {24613132333d20225f}
		 $hex27= {24613132343d20225f}
		 $hex28= {24613132353d20225f}
		 $hex29= {24613132363d20225f}
		 $hex30= {24613132373d20225f}
		 $hex31= {24613132383d20225f}
		 $hex32= {24613132393d20225f}
		 $hex33= {246131323d2022284c}
		 $hex34= {24613133303d20225f}
		 $hex35= {24613133313d20225f}
		 $hex36= {24613133323d20225f}
		 $hex37= {24613133333d20225f}
		 $hex38= {24613133343d20225f}
		 $hex39= {24613133353d20225f}
		 $hex40= {24613133363d20225f}
		 $hex41= {24613133373d20225f}
		 $hex42= {24613133383d20225f}
		 $hex43= {24613133393d20225f}
		 $hex44= {246131333d20225365}
		 $hex45= {24613134303d20225f}
		 $hex46= {24613134313d20225f}
		 $hex47= {24613134323d20225f}
		 $hex48= {24613134333d20225f}
		 $hex49= {24613134343d20225f}
		 $hex50= {24613134353d20225f}
		 $hex51= {24613134363d20225f}
		 $hex52= {24613134373d20225f}
		 $hex53= {24613134383d20225f}
		 $hex54= {24613134393d20225f}
		 $hex55= {246131343d20222f73}
		 $hex56= {24613135303d20225f}
		 $hex57= {24613135313d20225f}
		 $hex58= {24613135323d20225f}
		 $hex59= {24613135333d20225f}
		 $hex60= {24613135343d20225f}
		 $hex61= {24613135353d20225f}
		 $hex62= {24613135363d20225f}
		 $hex63= {24613135373d20225f}
		 $hex64= {24613135383d20225f}
		 $hex65= {24613135393d20225f}
		 $hex66= {246131353d20222f53}
		 $hex67= {24613136303d20225f}
		 $hex68= {24613136313d20225f}
		 $hex69= {24613136323d20225f}
		 $hex70= {24613136333d20225f}
		 $hex71= {24613136343d20225f}
		 $hex72= {24613136353d20225f}
		 $hex73= {24613136363d20225f}
		 $hex74= {24613136373d20225f}
		 $hex75= {24613136383d20225f}
		 $hex76= {24613136393d20225f}
		 $hex77= {246131363d20222f53}
		 $hex78= {24613137303d20225f}
		 $hex79= {24613137313d20225f}
		 $hex80= {24613137323d20225f}
		 $hex81= {24613137333d20225f}
		 $hex82= {24613137343d20225f}
		 $hex83= {24613137353d20225f}
		 $hex84= {24613137363d20225f}
		 $hex85= {24613137373d20225f}
		 $hex86= {24613137383d20225f}
		 $hex87= {24613137393d20225f}
		 $hex88= {246131373d20225537}
		 $hex89= {24613138303d20225f}
		 $hex90= {24613138313d20225f}
		 $hex91= {24613138323d20225f}
		 $hex92= {24613138333d20225f}
		 $hex93= {24613138343d20225f}
		 $hex94= {24613138353d20225f}
		 $hex95= {24613138363d20225f}
		 $hex96= {24613138373d20225f}
		 $hex97= {24613138383d20225f}
		 $hex98= {24613138393d20225f}
		 $hex99= {246131383d20222f55}
		 $hex100= {24613139303d20225f}
		 $hex101= {24613139313d20225f}
		 $hex102= {24613139323d20225f}
		 $hex103= {24613139333d20225f}
		 $hex104= {24613139343d20225f}
		 $hex105= {24613139353d20225f}
		 $hex106= {24613139363d20225f}
		 $hex107= {24613139373d20225f}
		 $hex108= {24613139383d20225f}
		 $hex109= {24613139393d20225f}
		 $hex110= {246131393d20225f5a}
		 $hex111= {2461313d2022323143}
		 $hex112= {24613230303d20225f}
		 $hex113= {24613230313d20225f}
		 $hex114= {24613230323d20225f}
		 $hex115= {24613230333d20225f}
		 $hex116= {24613230343d20225f}
		 $hex117= {24613230353d20225f}
		 $hex118= {24613230363d20225f}
		 $hex119= {24613230373d20225f}
		 $hex120= {24613230383d202240}
		 $hex121= {24613230393d20225f}
		 $hex122= {246132303d20225f5f}
		 $hex123= {24613231303d202240}
		 $hex124= {24613231313d20225f}
		 $hex125= {24613231323d20225f}
		 $hex126= {24613231333d20225f}
		 $hex127= {24613231343d20225f}
		 $hex128= {24613231353d20225f}
		 $hex129= {24613231363d20225f}
		 $hex130= {24613231373d20225f}
		 $hex131= {24613231383d20225f}
		 $hex132= {24613231393d20225f}
		 $hex133= {246132313d20225f5f}
		 $hex134= {24613232303d20225f}
		 $hex135= {24613232313d20225f}
		 $hex136= {24613232323d20225f}
		 $hex137= {24613232333d20225f}
		 $hex138= {24613232343d20225f}
		 $hex139= {24613232353d20225f}
		 $hex140= {24613232363d20225f}
		 $hex141= {24613232373d20225f}
		 $hex142= {24613232383d20225f}
		 $hex143= {24613232393d20225f}
		 $hex144= {246132323d20225f5f}
		 $hex145= {24613233303d20225f}
		 $hex146= {24613233313d20225f}
		 $hex147= {24613233323d20225f}
		 $hex148= {24613233333d202240}
		 $hex149= {24613233343d20225f}
		 $hex150= {24613233353d202240}
		 $hex151= {24613233363d20225f}
		 $hex152= {24613233373d202240}
		 $hex153= {24613233383d20225f}
		 $hex154= {24613233393d20225f}
		 $hex155= {246132333d20225f5f}
		 $hex156= {24613234303d202240}
		 $hex157= {24613234313d20225f}
		 $hex158= {24613234323d20225f}
		 $hex159= {24613234333d20225f}
		 $hex160= {24613234343d20225f}
		 $hex161= {24613234353d20225f}
		 $hex162= {24613234363d20225f}
		 $hex163= {24613234373d20225f}
		 $hex164= {24613234383d20225f}
		 $hex165= {24613234393d20225f}
		 $hex166= {246132343d20225f5a}
		 $hex167= {24613235303d20225f}
		 $hex168= {24613235313d202240}
		 $hex169= {24613235323d20225f}
		 $hex170= {24613235333d202240}
		 $hex171= {24613235343d20225f}
		 $hex172= {24613235353d202240}
		 $hex173= {24613235363d20225f}
		 $hex174= {24613235373d202240}
		 $hex175= {24613235383d20225f}
		 $hex176= {24613235393d202240}
		 $hex177= {246132353d20225f5a}
		 $hex178= {24613236303d20225f}
		 $hex179= {24613236313d20225f}
		 $hex180= {24613236323d20225f}
		 $hex181= {24613236333d20225f}
		 $hex182= {24613236343d20225f}
		 $hex183= {24613236353d20225f}
		 $hex184= {24613236363d20225f}
		 $hex185= {24613236373d20225f}
		 $hex186= {24613236383d20225f}
		 $hex187= {24613236393d20225f}
		 $hex188= {246132363d20225f5f}
		 $hex189= {24613237303d20225f}
		 $hex190= {24613237313d20225f}
		 $hex191= {24613237323d20225f}
		 $hex192= {24613237333d20225f}
		 $hex193= {24613237343d20225f}
		 $hex194= {24613237353d20225f}
		 $hex195= {24613237363d20225f}
		 $hex196= {24613237373d20225f}
		 $hex197= {24613237383d20225f}
		 $hex198= {24613237393d20225f}
		 $hex199= {246132373d20225f5a}
		 $hex200= {24613238303d20225f}
		 $hex201= {24613238313d20225f}
		 $hex202= {24613238323d20225f}
		 $hex203= {24613238333d202240}
		 $hex204= {24613238343d20225f}
		 $hex205= {24613238353d202240}
		 $hex206= {24613238363d20225f}
		 $hex207= {24613238373d20225f}
		 $hex208= {246132383d20225f5a}
		 $hex209= {246132393d20225f5f}
		 $hex210= {2461323d2022376d79}
		 $hex211= {246133303d20225f5f}
		 $hex212= {246133313d20225f5f}
		 $hex213= {246133323d20225f5f}
		 $hex214= {246133333d20225f5f}
		 $hex215= {246133343d20225f5a}
		 $hex216= {246133353d20225f5f}
		 $hex217= {246133363d20225f5f}
		 $hex218= {246133373d20225f5f}
		 $hex219= {246133383d20225f5f}
		 $hex220= {246133393d20225f5a}
		 $hex221= {2461333d2022617070}
		 $hex222= {246134303d20225f5a}
		 $hex223= {246134313d20225f5f}
		 $hex224= {246134323d20225f5a}
		 $hex225= {246134333d20225f5a}
		 $hex226= {246134343d20225f5a}
		 $hex227= {246134353d20225f5a}
		 $hex228= {246134363d20225f5a}
		 $hex229= {246134373d20225f5a}
		 $hex230= {246134383d20225f5a}
		 $hex231= {246134393d20225f5a}
		 $hex232= {2461343d2022617070}
		 $hex233= {246135303d20225f5f}
		 $hex234= {246135313d20225f5a}
		 $hex235= {246135323d20225f5a}
		 $hex236= {246135333d20225f5a}
		 $hex237= {246135343d20225f5a}
		 $hex238= {246135353d20225f5a}
		 $hex239= {246135363d20225f5a}
		 $hex240= {246135373d20225f5a}
		 $hex241= {246135383d20225f5a}
		 $hex242= {246135393d20225f5a}
		 $hex243= {2461353d2022636f6d}
		 $hex244= {246136303d20225f5f}
		 $hex245= {246136313d20225f5f}
		 $hex246= {246136323d20225f5a}
		 $hex247= {246136333d20225f5f}
		 $hex248= {246136343d20225f5a}
		 $hex249= {246136353d20225f5f}
		 $hex250= {246136363d20225f5a}
		 $hex251= {246136373d20225f5f}
		 $hex252= {246136383d20225f5a}
		 $hex253= {246136393d20225f5a}
		 $hex254= {2461363d20222a4669}
		 $hex255= {246137303d20225f5a}
		 $hex256= {246137313d20225f5a}
		 $hex257= {246137323d20225f5a}
		 $hex258= {246137333d20225f5a}
		 $hex259= {246137343d20225f5a}
		 $hex260= {246137353d20225f5a}
		 $hex261= {246137363d20225f5a}
		 $hex262= {246137373d20225f5a}
		 $hex263= {246137383d20225f5a}
		 $hex264= {246137393d20225f5a}
		 $hex265= {2461373d202246696e}
		 $hex266= {246138303d20225f5a}
		 $hex267= {246138313d20225f5a}
		 $hex268= {246138323d20225f5a}
		 $hex269= {246138333d20225f5a}
		 $hex270= {246138343d20225f5a}
		 $hex271= {246138353d20225f5a}
		 $hex272= {246138363d20225f5a}
		 $hex273= {246138373d20225f5f}
		 $hex274= {246138383d20225f5f}
		 $hex275= {246138393d20225f5f}
		 $hex276= {2461383d202246696e}
		 $hex277= {246139303d20225f5a}
		 $hex278= {246139313d20225f5f}
		 $hex279= {246139323d20225f5a}
		 $hex280= {246139333d20225f5f}
		 $hex281= {246139343d20225f5a}
		 $hex282= {246139353d20225f5f}
		 $hex283= {246139363d20225f5f}
		 $hex284= {246139373d20225f5a}
		 $hex285= {246139383d20225f5a}
		 $hex286= {246139393d20225f5a}
		 $hex287= {2461393d2022284c61}

	condition:
		143 of them
}