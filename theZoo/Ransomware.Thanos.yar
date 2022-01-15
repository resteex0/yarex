
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Thanos 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Thanos {
	meta: 
		 description= "Ransomware_Thanos Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-53-44" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "03b76a5130d0df8134a6bdea7fe97bcd"
		 hash2= "be60e389a0108b2871dff12dfbb542ac"
		 hash3= "d6d956267a268c9dcf48445629d2803e"
		 hash4= "e01e11dca5e8b08fc8231b1cb6e2048c"

	strings:

	
 		 $s1= "3747bdbf-0ef0-42d8-9234-70d68801f407" fullword wide
		 $s2= "Aditional KeyId:" fullword wide
		 $s3= "admin123Test123" fullword wide
		 $s4= "Administrator123" fullword wide
		 $s5= "aHR0cCBhbmFseXplciBzdGFuZC1hbG9uZQ==" fullword wide
		 $s6= "aHR0cDovL2ljYW5oYXppcC5jb20=" fullword wide
		 $s7= "Assembly Version" fullword wide
		 $s8= "aW50ZXJjZXB0ZXI=" fullword wide
		 $s9= "aZnLma0ZpqTthmr" fullword wide
		 $s10= "b3BlcmEzMi5leGU=" fullword wide
		 $s11= "bm90ZXBhZC5leGU=" fullword wide
		 $s12= "bXlzcWxkLmV4ZQ==" fullword wide
		 $s13= "c3Bvb2xjdi5leGU=" fullword wide
		 $s14= "c3lzaW50ZXJuYWxzIHRjcHZpZXc=" fullword wide
		 $s15= "c3RvcCB2ZWVhbSAveQ==" fullword wide
		 $s16= "c3RvcCBBY3JvbmlzQWdlbnQgL3k=" fullword wide
		 $s17= "c3RvcCBCTVIgQm9vdCBTZXJ2aWNlIC95" fullword wide
		 $s18= "c3RvcCBCYWNrdXBFeGVjQWdlbnRBY2NlbGVyYXRvciAveQ==" fullword wide
		 $s19= "c3RvcCBCYWNrdXBFeGVjQWdlbnRCcm93c2VyIC95" fullword wide
		 $s20= "c3RvcCBCYWNrdXBFeGVjRGl2ZWNpTWVkaWFTZXJ2aWNlIC95" fullword wide
		 $s21= "c3RvcCBCYWNrdXBFeGVjTWFuYWdlbWVudFNlcnZpY2UgL3k=" fullword wide
		 $s22= "c3RvcCBCYWNrdXBFeGVjUlBDU2VydmljZSAveQ==" fullword wide
		 $s23= "c3RvcCBCYWNrdXBFeGVjVlNTUHJvdmlkZXIgL3k=" fullword wide
		 $s24= "c3RvcCBDQUFSQ1VwZGF0ZVN2YyAveQ==" fullword wide
		 $s25= "c3RvcCBDQVNBRDJEV2ViU3ZjIC95" fullword wide
		 $s26= "c3RvcCBEZWZXYXRjaCAveQ==" fullword wide
		 $s27= "c3RvcCBhdnBzdXMgL3k=" fullword wide
		 $s28= "c3RvcCBjY0V2dE1nciAveQ==" fullword wide
		 $s29= "c3RvcCBjY1NldE1nciAveQ==" fullword wide
		 $s30= "c3RvcCBQRFZGU1NlcnZpY2UgL3k=" fullword wide
		 $s31= "c3RvcCBRQklEUFNlcnZpY2UgL3k=" fullword wide
		 $s32= "c3RvcCBRQkNGTW9uaXRvclNlcnZpY2UgL3k=" fullword wide
		 $s33= "c3RvcCBRQkZDU2VydmljZSAveQ==" fullword wide
		 $s34= "c3RvcCBSVFZzY2FuIC95" fullword wide
		 $s35= "c3RvcCBTYXZSb2FtIC95" fullword wide
		 $s36= "c3RvcCBtZmV3YyAveQ==" fullword wide
		 $s37= "c3RvcCBWU05BUFZTUyAveQ==" fullword wide
		 $s38= "c3RvcCBWZWVhbU5GU1N2YyAveQ==" fullword wide
		 $s39= "c3RvcCBWZWVhbURlcGxveW1lbnRTZXJ2aWNlIC95" fullword wide
		 $s40= "c3RvcCBWZWVhbVRyYW5zcG9ydFN2YyAveQ==" fullword wide
		 $s41= "c3RvcCBZb29CYWNrdXAgL3k=" fullword wide
		 $s42= "c3RvcCBZb29JVCAveQ==" fullword wide
		 $s43= "c3RvcCBzb3Bob3MgL3k=" fullword wide
		 $s44= "c3ZjaHN0LmV4ZQ==" fullword wide
		 $s45= "cHJvdGVjdGlvbl9pZA==" fullword wide
		 $s46= "d2lyZXNoYXJrIHBvcnRhYmxl" fullword wide
		 $s47= "DisableAntiSpyware" fullword wide
		 $s48= "DisableArchiveScanning" fullword wide
		 $s49= "DisableBehaviorMonitoring" fullword wide
		 $s50= "DisableBlockAtFirstSeen" fullword wide
		 $s51= "DisableIntrusionPreventionSystem" fullword wide
		 $s52= "DisableIOAVProtection" fullword wide
		 $s53= "DisableOnAccessProtection" fullword wide
		 $s54= "DisablePrivacyMode" fullword wide
		 $s55= "DisableRealtimeMonitoring" fullword wide
		 $s56= "DisableScanOnRealtimeEnable" fullword wide
		 $s57= "DisableScriptScanning" fullword wide
		 $s58= "dnNzYWRtaW4uZXhl" fullword wide
		 $s59= "FileDescription" fullword wide
		 $s60= "Final-02.exe.bin" fullword wide
		 $s61= "gCLianUocZKoeIY" fullword wide
		 $s62= "GetCurrentProcessId" fullword wide
		 $s63= "Get-MpPreference -verbose" fullword wide
		 $s64= "HighThreatDefaultAction" fullword wide
		 $s65= "HOW_TO_DECYPHER_FILES" fullword wide
		 $s66= "HOW_TO_DECYPHER_FILES.hta" fullword wide
		 $s67= "HOW_TO_DECYPHER_FILES.txt" fullword wide
		 $s68= "https://www.google.com/" fullword wide
		 $s69= "internet explorer" fullword wide
		 $s70= "L0lNIG1zcHViLmV4ZSAvRg==" fullword wide
		 $s71= "L3YgL2ZvIGNzdg==" fullword wide
		 $s72= "LegalTrademarks" fullword wide
		 $s73= "LowThreatDefaultAction" fullword wide
		 $s74= "mac>([a-f0-9]{2}-?){6})" fullword wide
		 $s75= "microsoft corporation" fullword wide
		 $s76= "ModerateThreatDefaultAction" fullword wide
		 $s77= "NtQuerySystemInformation" fullword wide
		 $s78= "NtReadVirtualMemory" fullword wide
		 $s79= "ntWB6ohspNIoCar" fullword wide
		 $s80= "OriginalFilename" fullword wide
		 $s81= "PHAgc3R5bGU9InRleHQtYWxpZ246IGNlbnRlcjsiPg==" fullword wide
		 $s82= "PHAgc3R5bGU9InRleHQtYWxpZ246IGNlbnRlcjsiPktleSBJZGVudGlmaWVyOiA=" fullword wide
		 $s83= "\\.PhysicalDrive0" fullword wide
		 $s84= "PWWPh5jww0vweJe 4pFhUfFs2GJ1B5U" fullword wide
		 $s85= "Q0ZGIEV4cGxvcmVy" fullword wide
		 $s86= "Q2xpZW50IElQOiAg" fullword wide
		 $s87= "Q2xpZW50IFVuaXF1ZSBJZGVudGlmaWVyIEtleTog" fullword wide
		 $s88= "Q3JlYXRlU2hvcnRjdXQ=" fullword wide
		 $s89= "QnVpbGRlcl9Mb2c=" fullword wide
		 $s90= "RGF0ZSBvZiBlbmNyeXB0aW9uOiA=" fullword wide
		 $s91= "RGVsZXRlIFNoYWRvd3MgL2FsbCAvcXVpZXQ=" fullword wide
		 $s92= "RW5hYmxlTGlua2VkQ29ubmVjdGlvbnM=" fullword wide
		 $s93= "S2V5IElkZW50aWZpZXI6IA==" fullword wide
		 $s94= "SevereThreatDefaultAction" fullword wide
		 $s95= "SFRUUE5ldHdvcmtTbmlmZmVy" fullword wide
		 $s96= "SignatureDisableUpdateOnStartupWithoutEngine" fullword wide
		 $s97= "SoftwareMicrosoftWindowsCurrentVersionPoliciesSystem" fullword wide
		 $s98= "SOFTWAREMicrosoftWindows DefenderFeatures" fullword wide
		 $s99= "SOFTWAREPoliciesMicrosoftWindows Defender" fullword wide
		 $s100= "SubmitSamplesConsent" fullword wide
		 $s101= "SUVXYXRjaCBQcm9mZXNzaW9uYWw=" fullword wide
		 $s102= "SW50ZXJjZXB0ZXItTkc=" fullword wide
		 $s103= "SW5mb3JtYXRpb24uLi4=" fullword wide
		 $s104= "TamperProtection" fullword wide
		 $s105= "TaskManagerWindow" fullword wide
		 $s106= "TGVnYWxOb3RpY2VDYXB0aW9u" fullword wide
		 $s107= "TGVnYWxOb3RpY2VUZXh0" fullword wide
		 $s108= "TmV0d29ya01pbmVy" fullword wide
		 $s109= "TmV0d29ya1RyYWZmaWNWaWV3" fullword wide
		 $s110= "TnVtYmVyIG9mIGZpbGVzIGVuY3J5cHRlZDog" fullword wide
		 $s111= "TnVtYmVyIG9mIGZpbGVzIHRoYXQgd2VyZSBwcm9jZXNzZWQgaXM6IA==" fullword wide
		 $s112= "TWVnYUR1bXBlcg==" fullword wide
		 $s113= "U2t5cGVBcHAuZXhl" fullword wide
		 $s114= "UG9zc2libGUgYWZmZWN0ZWQgZmlsZXM6IA==" fullword wide
		 $s115= "UHJvY2Vzc0hhY2tlcg==" fullword wide
		 $s116= "UkRHIFBhY2tlciBEZXRlY3Rvcg==" fullword wide
		 $s117= "V1NjcmlwdC5TaGVsbA==" fullword wide
		 $s118= "VolumeSerialNumber" fullword wide
		 $s119= "VS_VERSION_INFO" fullword wide
		 $s120= "VW5Db25mdXNlckV4" fullword wide
		 $s121= "VW5pdmVyc2FsX0ZpeGVy" fullword wide
		 $s122= "win32_processor" fullword wide
		 $s123= "Y29uZmlnIFNRTFdyaXRlciBzdGFydD0gZGlzYWJsZWQ=" fullword wide
		 $s124= "Y29uZmlnIFNRTFRFTEVNRVRSWSBzdGFydD0gZGlzYWJsZWQ=" fullword wide
		 $s125= "Y29uZmlnIFNzdHBTdmMgc3RhcnQ9IGRpc2FibGVk" fullword wide
		 $s126= "Y2hyb21lMzIuZXhl" fullword wide
		 $s127= "Y3RmbW9tLmV4ZQ==" fullword wide
		 $s128= "YOkBRITTKNBYLVa qNEQn0mbG2wNoNm" fullword wide
		 $s129= "ZGxsaHN0LmV4ZQ==" fullword wide
		 $s130= "ZmlyZWZveC5leGU=" fullword wide
		 $s131= "ZWZmZXRlY2ggaHR0cCBzbmlmZmVy" fullword wide
		 $a1= "3747bdbf-0ef0-42d8-9234-70d68801f407" fullword ascii
		 $a2= "aHR0cCBhbmFseXplciBzdGFuZC1hbG9uZQ==" fullword ascii
		 $a3= "c3RvcCBCYWNrdXBFeGVjQWdlbnRBY2NlbGVyYXRvciAveQ==" fullword ascii
		 $a4= "c3RvcCBCYWNrdXBFeGVjQWdlbnRCcm93c2VyIC95" fullword ascii
		 $a5= "c3RvcCBCYWNrdXBFeGVjRGl2ZWNpTWVkaWFTZXJ2aWNlIC95" fullword ascii
		 $a6= "c3RvcCBCYWNrdXBFeGVjTWFuYWdlbWVudFNlcnZpY2UgL3k=" fullword ascii
		 $a7= "c3RvcCBCYWNrdXBFeGVjUlBDU2VydmljZSAveQ==" fullword ascii
		 $a8= "c3RvcCBCYWNrdXBFeGVjVlNTUHJvdmlkZXIgL3k=" fullword ascii
		 $a9= "c3RvcCBRQkNGTW9uaXRvclNlcnZpY2UgL3k=" fullword ascii
		 $a10= "c3RvcCBWZWVhbURlcGxveW1lbnRTZXJ2aWNlIC95" fullword ascii
		 $a11= "c3RvcCBWZWVhbVRyYW5zcG9ydFN2YyAveQ==" fullword ascii
		 $a12= "mac>([a-f0-9]{2}-?){6})" fullword ascii
		 $a13= "PHAgc3R5bGU9InRleHQtYWxpZ246IGNlbnRlcjsiPg==" fullword ascii
		 $a14= "PHAgc3R5bGU9InRleHQtYWxpZ246IGNlbnRlcjsiPktleSBJZGVudGlmaWVyOiA=" fullword ascii
		 $a15= "Q2xpZW50IFVuaXF1ZSBJZGVudGlmaWVyIEtleTog" fullword ascii
		 $a16= "RGVsZXRlIFNoYWRvd3MgL2FsbCAvcXVpZXQ=" fullword ascii
		 $a17= "SignatureDisableUpdateOnStartupWithoutEngine" fullword ascii
		 $a18= "SoftwareMicrosoftWindowsCurrentVersionPoliciesSystem" fullword ascii
		 $a19= "SOFTWAREMicrosoftWindows DefenderFeatures" fullword ascii
		 $a20= "SOFTWAREPoliciesMicrosoftWindows Defender" fullword ascii
		 $a21= "TnVtYmVyIG9mIGZpbGVzIGVuY3J5cHRlZDog" fullword ascii
		 $a22= "TnVtYmVyIG9mIGZpbGVzIHRoYXQgd2VyZSBwcm9jZXNzZWQgaXM6IA==" fullword ascii
		 $a23= "UG9zc2libGUgYWZmZWN0ZWQgZmlsZXM6IA==" fullword ascii
		 $a24= "Y29uZmlnIFNRTFdyaXRlciBzdGFydD0gZGlzYWJsZWQ=" fullword ascii
		 $a25= "Y29uZmlnIFNRTFRFTEVNRVRSWSBzdGFydD0gZGlzYWJsZWQ=" fullword ascii
		 $a26= "Y29uZmlnIFNzdHBTdmMgc3RhcnQ9IGRpc2FibGVk" fullword ascii

		 $hex1= {246131303d20226333}
		 $hex2= {246131313d20226333}
		 $hex3= {246131323d20226d61}
		 $hex4= {246131333d20225048}
		 $hex5= {246131343d20225048}
		 $hex6= {246131353d20225132}
		 $hex7= {246131363d20225247}
		 $hex8= {246131373d20225369}
		 $hex9= {246131383d2022536f}
		 $hex10= {246131393d2022534f}
		 $hex11= {2461313d2022333734}
		 $hex12= {246132303d2022534f}
		 $hex13= {246132313d2022546e}
		 $hex14= {246132323d2022546e}
		 $hex15= {246132333d20225547}
		 $hex16= {246132343d20225932}
		 $hex17= {246132353d20225932}
		 $hex18= {246132363d20225932}
		 $hex19= {2461323d2022614852}
		 $hex20= {2461333d2022633352}
		 $hex21= {2461343d2022633352}
		 $hex22= {2461353d2022633352}
		 $hex23= {2461363d2022633352}
		 $hex24= {2461373d2022633352}
		 $hex25= {2461383d2022633352}
		 $hex26= {2461393d2022633352}
		 $hex27= {24733130303d202253}
		 $hex28= {24733130313d202253}
		 $hex29= {24733130323d202253}
		 $hex30= {24733130333d202253}
		 $hex31= {24733130343d202254}
		 $hex32= {24733130353d202254}
		 $hex33= {24733130363d202254}
		 $hex34= {24733130373d202254}
		 $hex35= {24733130383d202254}
		 $hex36= {24733130393d202254}
		 $hex37= {247331303d20226233}
		 $hex38= {24733131303d202254}
		 $hex39= {24733131313d202254}
		 $hex40= {24733131323d202254}
		 $hex41= {24733131333d202255}
		 $hex42= {24733131343d202255}
		 $hex43= {24733131353d202255}
		 $hex44= {24733131363d202255}
		 $hex45= {24733131373d202256}
		 $hex46= {24733131383d202256}
		 $hex47= {24733131393d202256}
		 $hex48= {247331313d2022626d}
		 $hex49= {24733132303d202256}
		 $hex50= {24733132313d202256}
		 $hex51= {24733132323d202277}
		 $hex52= {24733132333d202259}
		 $hex53= {24733132343d202259}
		 $hex54= {24733132353d202259}
		 $hex55= {24733132363d202259}
		 $hex56= {24733132373d202259}
		 $hex57= {24733132383d202259}
		 $hex58= {24733132393d20225a}
		 $hex59= {247331323d20226258}
		 $hex60= {24733133303d20225a}
		 $hex61= {24733133313d20225a}
		 $hex62= {247331333d20226333}
		 $hex63= {247331343d20226333}
		 $hex64= {247331353d20226333}
		 $hex65= {247331363d20226333}
		 $hex66= {247331373d20226333}
		 $hex67= {247331383d20226333}
		 $hex68= {247331393d20226333}
		 $hex69= {2473313d2022333734}
		 $hex70= {247332303d20226333}
		 $hex71= {247332313d20226333}
		 $hex72= {247332323d20226333}
		 $hex73= {247332333d20226333}
		 $hex74= {247332343d20226333}
		 $hex75= {247332353d20226333}
		 $hex76= {247332363d20226333}
		 $hex77= {247332373d20226333}
		 $hex78= {247332383d20226333}
		 $hex79= {247332393d20226333}
		 $hex80= {2473323d2022416469}
		 $hex81= {247333303d20226333}
		 $hex82= {247333313d20226333}
		 $hex83= {247333323d20226333}
		 $hex84= {247333333d20226333}
		 $hex85= {247333343d20226333}
		 $hex86= {247333353d20226333}
		 $hex87= {247333363d20226333}
		 $hex88= {247333373d20226333}
		 $hex89= {247333383d20226333}
		 $hex90= {247333393d20226333}
		 $hex91= {2473333d202261646d}
		 $hex92= {247334303d20226333}
		 $hex93= {247334313d20226333}
		 $hex94= {247334323d20226333}
		 $hex95= {247334333d20226333}
		 $hex96= {247334343d20226333}
		 $hex97= {247334353d20226348}
		 $hex98= {247334363d20226432}
		 $hex99= {247334373d20224469}
		 $hex100= {247334383d20224469}
		 $hex101= {247334393d20224469}
		 $hex102= {2473343d202241646d}
		 $hex103= {247335303d20224469}
		 $hex104= {247335313d20224469}
		 $hex105= {247335323d20224469}
		 $hex106= {247335333d20224469}
		 $hex107= {247335343d20224469}
		 $hex108= {247335353d20224469}
		 $hex109= {247335363d20224469}
		 $hex110= {247335373d20224469}
		 $hex111= {247335383d2022646e}
		 $hex112= {247335393d20224669}
		 $hex113= {2473353d2022614852}
		 $hex114= {247336303d20224669}
		 $hex115= {247336313d20226743}
		 $hex116= {247336323d20224765}
		 $hex117= {247336333d20224765}
		 $hex118= {247336343d20224869}
		 $hex119= {247336353d2022484f}
		 $hex120= {247336363d2022484f}
		 $hex121= {247336373d2022484f}
		 $hex122= {247336383d20226874}
		 $hex123= {247336393d2022696e}
		 $hex124= {2473363d2022614852}
		 $hex125= {247337303d20224c30}
		 $hex126= {247337313d20224c33}
		 $hex127= {247337323d20224c65}
		 $hex128= {247337333d20224c6f}
		 $hex129= {247337343d20226d61}
		 $hex130= {247337353d20226d69}
		 $hex131= {247337363d20224d6f}
		 $hex132= {247337373d20224e74}
		 $hex133= {247337383d20224e74}
		 $hex134= {247337393d20226e74}
		 $hex135= {2473373d2022417373}
		 $hex136= {247338303d20224f72}
		 $hex137= {247338313d20225048}
		 $hex138= {247338323d20225048}
		 $hex139= {247338333d20222e50}
		 $hex140= {247338343d20225057}
		 $hex141= {247338353d20225130}
		 $hex142= {247338363d20225132}
		 $hex143= {247338373d20225132}
		 $hex144= {247338383d20225133}
		 $hex145= {247338393d2022516e}
		 $hex146= {2473383d2022615735}
		 $hex147= {247339303d20225247}
		 $hex148= {247339313d20225247}
		 $hex149= {247339323d20225257}
		 $hex150= {247339333d20225332}
		 $hex151= {247339343d20225365}
		 $hex152= {247339353d20225346}
		 $hex153= {247339363d20225369}
		 $hex154= {247339373d2022536f}
		 $hex155= {247339383d2022534f}
		 $hex156= {247339393d2022534f}
		 $hex157= {2473393d2022615a6e}

	condition:
		19 of them
}
