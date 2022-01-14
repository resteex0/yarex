
/*
   YARA Rule Set
   Author: resteex
   Identifier: Molerats 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Molerats {
	meta: 
		 description= "Molerats Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_06-52-41" 
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

	
 		 $s1= "-+3?+-5z?-+3/?-+/3?3/-+?+-/3?-/3?-+?-+?+-+?/3-+3/" fullword wide
		 $s2= "{6b490fda-d207-452c-8f50-19c8bb1ddcee}" fullword wide
		 $s3= "{6f0ea965-435a-4205-b146-069dbb82e5dd}" fullword wide
		 $s4= "{71461f04-2faa-4bb9-a0dd-28a79101b599}" fullword wide
		 $s5= "{80ad08c8-dd68-4b7a-b8d6-e2704f9d0be0}" fullword wide
		 $s6= "8=/8/=%=;/;==;/=;/8?;=/=;#=/8?=/:8=/8=/" fullword wide
		 $s7= "9be4bf1e-6f2a-4490-808a-04b0eb56b002" fullword wide
		 $s8= "9d487cb3-c90f-4d82-8fc3-ebf3cc9a5ec6" fullword wide
		 $s9= "/Adope Player;component/mainwindow.xaml" fullword wide
		 $s10= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s11= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s12= "{c5d2e92b-c1e4-4b15-8843-43fc2da2bf3e}" fullword wide
		 $s13= "Capi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s14= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s15= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s16= "pi-ms-win-core-localization-l1-2-1" fullword wide
		 $s17= "pi-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s18= "pi-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s19= "PrintPreviewToolStripMenuItem.Image" fullword wide
		 $s20= "SoftwareMicrosoftWindowsCurrentVersion" fullword wide
		 $s21= "SOFTWAREMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s22= "SOFTWAREMicrosoftWindowsCurrentVersionUninstall" fullword wide
		 $s23= "SOFTWAREWow6432NodeMicrosoftWindowsCurrentVersionUninstall" fullword wide
		 $s24= "System.Security.Cryptography.AesCryptoServiceProvider" fullword wide
		 $s25= "WindowsFormsApplication3.Properties.Resources" fullword wide
		 $a1= "SOFTWAREMicrosoftWindowsCurrentVersionUninstall" fullword ascii
		 $a2= "SOFTWAREWow6432NodeMicrosoftWindowsCurrentVersionUninstall" fullword ascii
		 $a3= "System.Security.Cryptography.AesCryptoServiceProvider" fullword ascii

		 $hex1= {2461313d2022534f46}
		 $hex2= {2461323d2022534f46}
		 $hex3= {2461333d2022537973}
		 $hex4= {247331303d20226170}
		 $hex5= {247331313d20226170}
		 $hex6= {247331323d20227b63}
		 $hex7= {247331333d20224361}
		 $hex8= {247331343d20226578}
		 $hex9= {247331353d20226578}
		 $hex10= {247331363d20227069}
		 $hex11= {247331373d20227069}
		 $hex12= {247331383d20227069}
		 $hex13= {247331393d20225072}
		 $hex14= {2473313d20222d2b33}
		 $hex15= {247332303d2022536f}
		 $hex16= {247332313d2022534f}
		 $hex17= {247332323d2022534f}
		 $hex18= {247332333d2022534f}
		 $hex19= {247332343d20225379}
		 $hex20= {247332353d20225769}
		 $hex21= {2473323d20227b3662}
		 $hex22= {2473333d20227b3666}
		 $hex23= {2473343d20227b3731}
		 $hex24= {2473353d20227b3830}
		 $hex25= {2473363d2022383d2f}
		 $hex26= {2473373d2022396265}
		 $hex27= {2473383d2022396434}
		 $hex28= {2473393d20222f4164}

	condition:
		3 of them
}
