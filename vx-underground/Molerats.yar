
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Molerats 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Molerats {
	meta: 
		 description= "vx_underground2_Molerats Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-11-40" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "05854d1475cfbbcca799b3b1d03fd5af"
		 hash2= "0ea8f665f5e2d20e6a6e852c57264193"
		 hash3= "12fd3469bdc463a52c89da576aec857e"
		 hash4= "1c64b27a58b016a966c654f1fdf4c155"
		 hash5= "2a7e0463c7814465f9a78355c4754d0a"
		 hash6= "2b6bd6f99c913cd895891114bef55bdd"
		 hash7= "2dcbcfac6323fc2be682ee3eb9b26d21"
		 hash8= "3227cc9462ffdc5fa27ae75a62d6d0d9"
		 hash9= "486954967e02a2e1577bd7dd91026102"
		 hash10= "5d5b2ed283af4c9c96bc05c566bf5063"
		 hash11= "5da48e60c61a7f16e69f8163df76fac3"
		 hash12= "6c81f73fb99c56b90548b9769ab6a747"
		 hash13= "6dc73f2b635019724353b251f1b6f849"
		 hash14= "76191048a30b395461449266d13c3d33"
		 hash15= "84fdcb1f23f592543381c85527c19aaa"
		 hash16= "8598313222c41280eb42863eda8a9490"
		 hash17= "a08b9b8f0d09f293c731b122648579d3"
		 hash18= "a9dd94f3f0eb23b4d8b030ad758e49c9"
		 hash19= "ade199b16607fd29c8e7288fb750ca2b"
		 hash20= "aede654e77e92dbd77ca512e19f495b8"
		 hash21= "b726fe42c5b6c80b4f10d3542507340f"
		 hash22= "b76f4c8c22b84600ac3cff64dadfaf8b"
		 hash23= "b8d5d8e79f1f83548f1efef7f53606da"
		 hash24= "bb161c7a01d218ee0cc98b4d5404d460"
		 hash25= "c9a0e0c04b27276fcce552cf175b2c82"
		 hash26= "d99a401a4db249e973e33e9f2b51f8ad"
		 hash27= "ea406ea60a05afa14f7debc67a75a472"
		 hash28= "fea6546e3299a31a58a3aa2a6b7060c9"

	strings:

	
 		 $s1= "09876543210987654321098765432100" fullword wide
		 $s2= "-+3?+-5z?-+3/?-+/3?3/-+?+-/3?-/3?-+?-+?+-+?/3-+3/" fullword wide
		 $s3= "%4d-%02d-%02d-%02d-%02d-%02d-%03d" fullword wide
		 $s4= "{6b490fda-d207-452c-8f50-19c8bb1ddcee}" fullword wide
		 $s5= "{6f0ea965-435a-4205-b146-069dbb82e5dd}" fullword wide
		 $s6= "{71461f04-2faa-4bb9-a0dd-28a79101b599}" fullword wide
		 $s7= "{80ad08c8-dd68-4b7a-b8d6-e2704f9d0be0}" fullword wide
		 $s8= "8=/8/=%=;/;==;/=;/8?;=/=;#=/8?=/:8=/8=/" fullword wide
		 $s9= "9be4bf1e-6f2a-4490-808a-04b0eb56b002" fullword wide
		 $s10= "9d487cb3-c90f-4d82-8fc3-ebf3cc9a5ec6" fullword wide
		 $s11= "/Adope Player;component/mainwindow.xaml" fullword wide
		 $s12= "/Adope Player;component/page1.xaml" fullword wide
		 $s13= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s14= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s15= "ArrangeIconsToolStripMenuItem" fullword wide
		 $s16= "{c5d2e92b-c1e4-4b15-8843-43fc2da2bf3e}" fullword wide
		 $s17= "Capi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s18= "CloseAllToolStripMenuItem" fullword wide
		 $s19= "ContentsToolStripMenuItem" fullword wide
		 $s20= "CopyToolStripMenuItem.Image" fullword wide
		 $s21= "CryptProtectMemory failed" fullword wide
		 $s22= "CryptUnprotectMemory failed" fullword wide
		 $s23= "CutToolStripMenuItem.Image" fullword wide
		 $s24= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s25= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s26= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s27= "GetDelegateForFunctionPointer" fullword wide
		 $s28= "HelpToolStripButton.Image" fullword wide
		 $s29= "https://wiknet.wikaba.com" fullword wide
		 $s30= "import.Properties.Resources" fullword wide
		 $s31= "IndexToolStripMenuItem.Image" fullword wide
		 $s32= "NewToolStripMenuItem.Image" fullword wide
		 $s33= "NewWindowToolStripMenuItem" fullword wide
		 $s34= "OpenToolStripButton.Image" fullword wide
		 $s35= "OpenToolStripMenuItem.Image" fullword wide
		 $s36= "PasteToolStripMenuItem.Image" fullword wide
		 $s37= "pi-ms-win-core-datetime-l1-1-1" fullword wide
		 $s38= "pi-ms-win-core-fibers-l1-1-1" fullword wide
		 $s39= "pi-ms-win-core-file-l2-1-1" fullword wide
		 $s40= "pi-ms-win-core-localization-l1-2-1" fullword wide
		 $s41= "pi-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s42= "pi-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s43= "pi-ms-win-core-string-l1-1-0" fullword wide
		 $s44= "pi-ms-win-core-synch-l1-2-0" fullword wide
		 $s45= "pi-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s46= "pi-ms-win-core-winrt-l1-1-0" fullword wide
		 $s47= "pi-ms-win-core-xstate-l2-1-0" fullword wide
		 $s48= "PrintPreviewToolStripButton" fullword wide
		 $s49= "PrintPreviewToolStripButton.Image" fullword wide
		 $s50= "PrintPreviewToolStripMenuItem" fullword wide
		 $s51= "PrintPreviewToolStripMenuItem.Image" fullword wide
		 $s52= "PrintSetupToolStripMenuItem" fullword wide
		 $s53= "PrintToolStripButton.Image" fullword wide
		 $s54= "PrintToolStripMenuItem.Image" fullword wide
		 $s55= "Program FilesWinrarrar.exe" fullword wide
		 $s56= "RedoToolStripMenuItem.Image" fullword wide
		 $s57= "RFdUVk90T2tUU1NCcmFaZkRZWXBza2Q=" fullword wide
		 $s58= "RkJPbHVRTWRaS3RaVkhkVVRSd1ZyYnM=" fullword wide
		 $s59= "SaveToolStripButton.Image" fullword wide
		 $s60= "SaveToolStripMenuItem.Image" fullword wide
		 $s61= "SearchToolStripMenuItem.Image" fullword wide
		 $s62= "SeCreateSymbolicLinkPrivilege" fullword wide
		 $s63= "SelectAllToolStripMenuItem" fullword wide
		 $s64= "SoftwareMicrosoftWindowsCurrentVersion" fullword wide
		 $s65= "SOFTWAREMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s66= "SOFTWAREMicrosoftWindowsCurrentVersionUninstall" fullword wide
		 $s67= "SOFTWAREWow6432NodeMicrosoftWindowsCurrentVersionUninstall" fullword wide
		 $s68= "StatusBarToolStripMenuItem" fullword wide
		 $s69= "System.Diagnostics.Process (" fullword wide
		 $s70= "System.Security.Cryptography.AesCryptoServiceProvider" fullword wide
		 $s71= "TileHorizontalToolStripMenuItem" fullword wide
		 $s72= "TileVerticalToolStripMenuItem" fullword wide
		 $s73= "TklzSEJyUGROa2pUZWhZck1ZQlZSVUY=" fullword wide
		 $s74= "__tmp_rar_sfx_access_check_%u" fullword wide
		 $s75= "UndoToolStripMenuItem.Image" fullword wide
		 $s76= "VWloVlNjTVB3UEFGU0pFWHVwU3BZS0I=" fullword wide
		 $s77= "WindowsFormsApplication3.exe" fullword wide
		 $s78= "WindowsFormsApplication3.Properties.Resources" fullword wide
		 $s79= "WinForms_RecursiveFormCreate" fullword wide
		 $s80= "WinForms_SeeInnerException" fullword wide
		 $s81= "ZU1NV1pBUlFLaXdqSkFVd29mbENITmE=" fullword wide
		 $a1= "http://www.microsoft.com/pki/certs/MicrosoftTimeStampPCA.crt0" fullword ascii
		 $a2= "mc;http://schemas.openxmlformats.org/markup-compatibility/2006" fullword ascii
		 $a3= "mik9okl5okl.plm'qll!rnn" fullword ascii
		 $a4= "Namespace3http://www.smartassembly.com/webservices/Reporting/" fullword ascii

		 $hex1= {2461313d2022687474}
		 $hex2= {2461323d20226d633b}
		 $hex3= {2461333d20226d696b}
		 $hex4= {2461343d20224e616d}
		 $hex5= {247331303d20223964}
		 $hex6= {247331313d20222f41}
		 $hex7= {247331323d20222f41}
		 $hex8= {247331333d20226170}
		 $hex9= {247331343d20226170}
		 $hex10= {247331353d20224172}
		 $hex11= {247331363d20227b63}
		 $hex12= {247331373d20224361}
		 $hex13= {247331383d2022436c}
		 $hex14= {247331393d2022436f}
		 $hex15= {2473313d2022303938}
		 $hex16= {247332303d2022436f}
		 $hex17= {247332313d20224372}
		 $hex18= {247332323d20224372}
		 $hex19= {247332333d20224375}
		 $hex20= {247332343d20226578}
		 $hex21= {247332353d20226578}
		 $hex22= {247332363d20226578}
		 $hex23= {247332373d20224765}
		 $hex24= {247332383d20224865}
		 $hex25= {247332393d20226874}
		 $hex26= {2473323d20222d2b33}
		 $hex27= {247333303d2022696d}
		 $hex28= {247333313d2022496e}
		 $hex29= {247333323d20224e65}
		 $hex30= {247333333d20224e65}
		 $hex31= {247333343d20224f70}
		 $hex32= {247333353d20224f70}
		 $hex33= {247333363d20225061}
		 $hex34= {247333373d20227069}
		 $hex35= {247333383d20227069}
		 $hex36= {247333393d20227069}
		 $hex37= {2473333d2022253464}
		 $hex38= {247334303d20227069}
		 $hex39= {247334313d20227069}
		 $hex40= {247334323d20227069}
		 $hex41= {247334333d20227069}
		 $hex42= {247334343d20227069}
		 $hex43= {247334353d20227069}
		 $hex44= {247334363d20227069}
		 $hex45= {247334373d20227069}
		 $hex46= {247334383d20225072}
		 $hex47= {247334393d20225072}
		 $hex48= {2473343d20227b3662}
		 $hex49= {247335303d20225072}
		 $hex50= {247335313d20225072}
		 $hex51= {247335323d20225072}
		 $hex52= {247335333d20225072}
		 $hex53= {247335343d20225072}
		 $hex54= {247335353d20225072}
		 $hex55= {247335363d20225265}
		 $hex56= {247335373d20225246}
		 $hex57= {247335383d2022526b}
		 $hex58= {247335393d20225361}
		 $hex59= {2473353d20227b3666}
		 $hex60= {247336303d20225361}
		 $hex61= {247336313d20225365}
		 $hex62= {247336323d20225365}
		 $hex63= {247336333d20225365}
		 $hex64= {247336343d2022536f}
		 $hex65= {247336353d2022534f}
		 $hex66= {247336363d2022534f}
		 $hex67= {247336373d2022534f}
		 $hex68= {247336383d20225374}
		 $hex69= {247336393d20225379}
		 $hex70= {2473363d20227b3731}
		 $hex71= {247337303d20225379}
		 $hex72= {247337313d20225469}
		 $hex73= {247337323d20225469}
		 $hex74= {247337333d2022546b}
		 $hex75= {247337343d20225f5f}
		 $hex76= {247337353d2022556e}
		 $hex77= {247337363d20225657}
		 $hex78= {247337373d20225769}
		 $hex79= {247337383d20225769}
		 $hex80= {247337393d20225769}
		 $hex81= {2473373d20227b3830}
		 $hex82= {247338303d20225769}
		 $hex83= {247338313d20225a55}
		 $hex84= {2473383d2022383d2f}
		 $hex85= {2473393d2022396265}

	condition:
		56 of them
}
