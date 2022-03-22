
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_Turla 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_Turla {
	meta: 
		 description= "APT_Sample_Turla Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-22_12-23-22" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "25ad1d40b05d9b6978d352b490e7b93f"
		 hash2= "2ced6205942be2349da93af07170bdfd"
		 hash3= "38ff4b9747c1e6462d8fc31d5455cca2"
		 hash4= "59b57bdabee2ce1fb566de51dd92ec94"
		 hash5= "7009af646c6c3e6abc0af744152ca968"
		 hash6= "a352f93e5f63bbf5cd0905c38f054d27"
		 hash7= "af8889f4705145d4390ee8d581f45436"
		 hash8= "d891c9374ccb2a4cae2274170e8644d8"
		 hash9= "ea874ac436223b30743fc9979eed5f2f"
		 hash10= "edfd33d319af1cce7baa1b15b52940e7"
		 hash11= "ff8c3f362d7c9b9a19cfa09b4b3cfc75"

	strings:

	
 		 $s1= "%02d:%02d:%04d %02d:%02d:%02d" fullword wide
		 $s2= "0faa41d9-47a7-4735-ac0e-7dabedfb3985" fullword wide
		 $s3= "1.0.2536.0 (win7sp1_rtm.101119-1850)" fullword wide
		 $s4= "{1578B51C-73B6-4322-B36C-9D3B761718B1" fullword wide
		 $s5= "{1578B51C-73B6-4322-B36C-9D3B761718B1}" fullword wide
		 $s6= "2F6C2D44-9494-4331-843D-145950FFE59B" fullword wide
		 $s7= "3de75680-7a53-4b71-a5ac-bd019e104294" fullword wide
		 $s8= "5.2.3790.3959 (srv03.sp2.070216-1710)" fullword wide
		 $s9= "59906128-e741-411f-90e7-a8457c8ba590" fullword wide
		 $s10= "^([a-z]{0,40})::([a-z]{0,40})::([a-z_]{0,40})$" fullword wide
		 $s11= "{ba2dc583-e676-4403-b805-62f9c09f794c}" fullword wide
		 $s12= "c_fscfsmetadataserver.inf" fullword wide
		 $s13= "clientResultSequenceNumber" fullword wide
		 $s14= "%CommonProgramFiles%SystemWab32.dll" fullword wide
		 $s15= "C:WindowsMicrosoft.NETFrameworkv4.0.30319ngentask.exe" fullword wide
		 $s16= "C:WindowsservicingSessions30695177_809879615.back.xml" fullword wide
		 $s17= "C:WindowsservicingSessions30695177_809879615.xml" fullword wide
		 $s18= "DeviceHarddiskVolume2WindowsSystem32SSShim.dll" fullword wide
		 $s19= "deviceharddiskvolume2windowssystem32svchost.exe" fullword wide
		 $s20= "DiagnosticsCollectorLiblet: Init" fullword wide
		 $s21= "HKEY_CURRENT_USERSoftwareClassessteamShellOpenCommand" fullword wide
		 $s22= "http://www.w3.org/2001/04/xmldsig-more#sha384" fullword wide
		 $s23= "http://www.w3.org/2001/04/xmlenc#sha512" fullword wide
		 $s24= "HxMailSplashLogo.scale-200.png" fullword wide
		 $s25= "HxMailSplashLogo.scale-250.png" fullword wide
		 $s26= "HxMailSplashLogo.scale-300.png" fullword wide
		 $s27= "jbdsicoiohttp://img-save.xyz" fullword wide
		 $s28= ".jse',$d);invoke-item $d;" fullword wide
		 $s29= ".js';(new-object system.net.webclient).downloadfile('http'+'s://" fullword wide
		 $s30= "JumpListOpenDrawer.pngx" fullword wide
		 $s31= "LockScreenLogo.scale-200.png" fullword wide
		 $s32= "mapEditGroupOperationType" fullword wide
		 $s33= "mapEditUnifiedGroupDialogType" fullword wide
		 $s34= "mapUnifiedGroupDialogEntryPoint" fullword wide
		 $s35= "Microsoft.Applications.Telemetry.Windows.dll" fullword wide
		 $s36= "Microsoft.Applications.Telemetry.Windows.winmdx" fullword wide
		 $s37= "Microsoft.Graphics.Canvas.dll" fullword wide
		 $s38= "Microsoft.Graphics.Canvas.winmd" fullword wide
		 $s39= "Microsoft.Notes.Upgrade.dll" fullword wide
		 $s40= "Microsoft.Notes.Upgrade.winmd" fullword wide
		 $s41= "Microsoft.Office.Diagnostics.Scrubbing.EnableScrubbing" fullword wide
		 $s42= "Microsoft.Office.Diagnostics.Scrubbing.UseStdRegex" fullword wide
		 $s43= "Microsoft.Office.Diagnostics.ScurbbingPattern" fullword wide
		 $s44= "Microsoft?Windows?Operating System" fullword wide
		 $s45= "Mso::Diagnostics::DiagnosticsTelemetryEventSink" fullword wide
		 $s46= "Mso::PrivacyComplianceEventSink::PrivacyComplianceEventSink" fullword wide
		 $s47= "nSoftwareMicrosoftWABDLLPath" fullword wide
		 $s48= "OneNotePageMedTile.scale-100.png" fullword wide
		 $s49= "OneNotePageMedTile.scale-125.png" fullword wide
		 $s50= "OneNotePageMedTile.scale-150.png" fullword wide
		 $s51= "OneNotePageMedTile.scale-200.png" fullword wide
		 $s52= "OUSERSKPIERCE.ARMYAPPDATALO" fullword wide
		 $s53= "pipe://*/Winsock2/baseapi_http" fullword wide
		 $s54= "powershell.exe=$env:temp+[char][byte]92+'15" fullword wide
		 $s55= "Preview.scale-200_layoutdir-LTR.png" fullword wide
		 $s56= "Preview.scale-200_layoutdir-RTL.png" fullword wide
		 $s57= "S-1-5-21-2471956375-579435592-1913153620-500" fullword wide
		 $s58= "S-1-5-21-2471956375-579435592-1913153620-500.pckgdep" fullword wide
		 $s59= "SOFTWAREMicrosoftCryptography" fullword wide
		 $s60= "SOFTWAREMicrosoftWindowsCurrentVersionRun4GP.ME/bbtc/" fullword wide
		 $s61= "SoftwareMicrosoftWindowsCurrentVersionRun/k DownloadFile" fullword wide
		 $s62= "SoftwareMicrosoftWindows NTCurrentVersionSvchost" fullword wide
		 $s63= "SplashScreen.scale-200.png" fullword wide
		 $s64= "Square150x150Logo.scale-200.png" fullword wide
		 $s65= "Square310x310Logo.scale-200.png" fullword wide
		 $s66= "Square44x44Logo.scale-200.png" fullword wide
		 $s67= "Square44x44Logo.targetsize-16_altform-unplated.png" fullword wide
		 $s68= "Square44x44Logo.targetsize-24_altform-unplated.png" fullword wide
		 $s69= "Square44x44Logo.targetsize-256_altform-unplated.png" fullword wide
		 $s70= "Square44x44Logo.targetsize-48_altform-unplated.pngx" fullword wide
		 $s71= "Square71x71Logo.scale-200.png" fullword wide
		 $s72= "(://)|(\\+)|([S]+@[^s]{3,})|(d{1,3}.){3}d{1,3}" fullword wide
		 $s73= "StoreLogo.scale-200.png" fullword wide
		 $s74= "SUNIQUE_ID_DO_NOT_REMOVECRYPT_INFORMATION.html" fullword wide
		 $s75= ")System.ComponentModel.DataAnnotations.dll" fullword wide
		 $s76= "System.ComponentModel.EventBasedAsync" fullword wide
		 $s77= ")System.ComponentModel.EventBasedAsync.dll" fullword wide
		 $s78= "System.ComponentModel.Primitives" fullword wide
		 $s79= "SYSTEMCurrentControlSetServices%sParameters" fullword wide
		 $s80= "%system%macromedflashflash" fullword wide
		 $s81= "VES-Disambiguation.1009.grxml" fullword wide
		 $s82= "VES-SeeItSayIt.0407.grxml" fullword wide
		 $s83= "VES-SeeItSayIt.0409.grxml" fullword wide
		 $s84= "Volume2WindowsLogsDISMdism.log" fullword wide
		 $s85= "Wide310x150Logo.scale-200.png" fullword wide
		 $s86= "Windows.ApplicationModel.Background.LocationTrigger" fullword wide
		 $s87= "Windows.ApplicationModel.Background.MaintenanceTrigger" fullword wide
		 $s88= "Windows.ApplicationModel.Background.TimeTrigger" fullword wide
		 $s89= "Windows.Services.Store.StoreContext" fullword wide
		 $s90= "Windows.Services.Store.StoreContract" fullword wide
		 $s91= "Windows.Services.Store.StoreRequestHelper" fullword wide
		 $s92= "Windows.UI.ApplicationSettings.SettingsPane" fullword wide
		 $s93= "Windows.UI.Composition.CompositionScopedBatch" fullword wide
		 $s94= "Windows.UI.Input.PointerPoint" fullword wide
		 $s95= "Windows.UI.Notifications.BadgeUpdateManager" fullword wide
		 $s96= "Windows.UI.Notifications.ScheduledToastNotification" fullword wide
		 $s97= "xSktJslycStEhpTsYx9PDqDZmUYVIUlypHSu" fullword wide
		 $s98= "ycStEktrJLrir9HIUlypslSuKFdySkDqDZmU" fullword wide
		 $s99= "YellowAbstractNote.scale-200.png" fullword wide
		 $a1= "4s3c5kdmlxiaj1tobxcqr-eo2g zya89vfl/qzwi0kntugyfsdnh7b6_mjhwupv" fullword ascii
		 $a2= "HiKxjLhQcuK0Mllsq+54gYPaoi6LkZG/lUxhWuGI1M2i3/dHp40vbwaaL5Sotxuv" fullword ascii
		 $a3= ".js';(new-objectsystem.net.webclient).downloadfile('http'+'s://" fullword ascii
		 $a4= "jSytDsU75U5T+rCAHVMykiLi/x7PKg40JQoYGMSOPUJsx87i/uy3uHoecl2ns038" fullword ascii
		 $a5= "M7162eRS+RTE8BYW8cTGdFPSiDiVOblImyddBLu/fW7MSc+BUsmg2l9SVyvJrHJk" fullword ascii

		 $hex1= {253032643a25303264}
		 $hex2= {25436f6d6d6f6e5072}
		 $hex3= {2573797374656d256d}
		 $hex4= {283a2f2f297c282b29}
		 $hex5= {2953797374656d2e43}
		 $hex6= {2e6a73273b286e6577}
		 $hex7= {2e6a7365272c246429}
		 $hex8= {30666161343164392d}
		 $hex9= {312e302e323533362e}
		 $hex10= {32463643324434342d}
		 $hex11= {33646537353638302d}
		 $hex12= {34733363356b646d6c}
		 $hex13= {352e322e333739302e}
		 $hex14= {35393930363132382d}
		 $hex15= {433a57696e646f7773}
		 $hex16= {446576696365486172}
		 $hex17= {446961676e6f737469}
		 $hex18= {484b45595f43555252}
		 $hex19= {48694b786a4c685163}
		 $hex20= {48784d61696c53706c}
		 $hex21= {4a756d704c6973744f}
		 $hex22= {4c6f636b5363726565}
		 $hex23= {4d373136326552532b}
		 $hex24= {4d6963726f736f6674}
		 $hex25= {4d736f3a3a44696167}
		 $hex26= {4d736f3a3a50726976}
		 $hex27= {4f55534552534b5049}
		 $hex28= {4f6e654e6f74655061}
		 $hex29= {507265766965772e73}
		 $hex30= {532d312d352d32312d}
		 $hex31= {534f4654574152454d}
		 $hex32= {53554e495155455f49}
		 $hex33= {53595354454d437572}
		 $hex34= {536f6674776172654d}
		 $hex35= {53706c617368536372}
		 $hex36= {537175617265313530}
		 $hex37= {537175617265333130}
		 $hex38= {537175617265343478}
		 $hex39= {537175617265373178}
		 $hex40= {53746f72654c6f676f}
		 $hex41= {53797374656d2e436f}
		 $hex42= {5645532d446973616d}
		 $hex43= {5645532d5365654974}
		 $hex44= {566f6c756d65325769}
		 $hex45= {576964653331307831}
		 $hex46= {57696e646f77732e41}
		 $hex47= {57696e646f77732e53}
		 $hex48= {57696e646f77732e55}
		 $hex49= {59656c6c6f77416273}
		 $hex50= {5e285b612d7a5d7b30}
		 $hex51= {635f66736366736d65}
		 $hex52= {636c69656e74526573}
		 $hex53= {646576696365686172}
		 $hex54= {687474703a2f2f7777}
		 $hex55= {6a5379744473553735}
		 $hex56= {6a62647369636f696f}
		 $hex57= {6d6170456469744772}
		 $hex58= {6d617045646974556e}
		 $hex59= {6d6170556e69666965}
		 $hex60= {6e536f667477617265}
		 $hex61= {706970653a2f2f2a2f}
		 $hex62= {706f7765727368656c}
		 $hex63= {78536b744a736c7963}
		 $hex64= {79635374456b74724a}
		 $hex65= {7b3135373842353143}
		 $hex66= {7b6261326463353833}

	condition:
		17 of them
}
