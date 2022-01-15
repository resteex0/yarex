
/*
   YARA Rule Set
   Author: resteex
   Identifier: PassCV 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_PassCV {
	meta: 
		 description= "PassCV Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-16-20" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "011858556ad3a5ef1a6bbc6ad9eaae09"
		 hash2= "027eb2cda9f1c8df00e26641ce4ef12d"
		 hash3= "045fd6e98a51a3c4e55a99bb6696f4de"
		 hash4= "04dc04a1a61769f33b234ad0f19fdc53"
		 hash5= "11898306703dcbeb1ca2cd7746384829"
		 hash6= "15ce067a4d370afae742db91646d26ee"
		 hash7= "175c7694d32191091334e20509a7b2c0"
		 hash8= "1826efb7b1a4f135785ccfc8b0e79094"
		 hash9= "19e137dc5974cfad5db62f96e3ba9fd1"
		 hash10= "218b1cd127a95a107dbaf4abe001d364"
		 hash11= "22de97c025f3cc9ad3f835d97b0a7fab"
		 hash12= "231257eb290ad0335ebf4556f156fc68"
		 hash13= "254d87bdd1f358de19ec50a3203d771a"
		 hash14= "276aaea14d125f69fe7e80e5a30180d7"
		 hash15= "285a2e9216dbf83edf5ef12ba063a511"
		 hash16= "28af0e2520713b81659c95430220d2b9"
		 hash17= "2ea30517938dda8a084aa00e5ee921f6"
		 hash18= "30498006ce28019ec4a879484d67a6b4"
		 hash19= "37bb8eacc454aa619ef35e8d82ae85bd"
		 hash20= "37c37e327a766a1b2db2fb9c934ff16e"
		 hash21= "3a9503ce79a0ac3b6f2f38163d55554d"
		 hash22= "47a69704566f37e8626bb8bb5fa784c8"
		 hash23= "485ca8d140169ebbc8e5b3d7eaed544f"
		 hash24= "48c21badebacdc9239416a9848b4855c"
		 hash25= "494bedc21836a3323f88717066150abf"
		 hash26= "50f7c822562c1213d244e1389d3895c8"
		 hash27= "527bfd801206c4b382487320ce2a245e"
		 hash28= "5919b59b61b3807b18be08a35d7c4633"
		 hash29= "5a69a3d1520260bea2c34adf3cb92c03"
		 hash30= "6103f34ec409f99762e9c3714dfa1262"
		 hash31= "6255f40b4000abad8b9e795280fddfd1"
		 hash32= "66f915ebdde2f98e2f802a52f1a4e85e"
		 hash33= "6e4846b1029fed9118bbfaa0bd66f0a9"
		 hash34= "70e41bc5daa6ff811317afef75498062"
		 hash35= "71f8fb73be84e3d5045d4cfbf7ed4f53"
		 hash36= "727dfef3918db48b9922ac75796aed55"
		 hash37= "72b1bfaf65ad9ec596860c1ea3bfb4cc"
		 hash38= "75b713b8d54403c51317679b4038a6ff"
		 hash39= "76c9bce4beb37cc8c00a05f3efafe89a"
		 hash40= "773afaa800f539ce195540e2f1882270"
		 hash41= "7c086172be6d1eed7fd65a1a4a8df59f"
		 hash42= "7cbabbfe44b12839b83225c5f91b5155"
		 hash43= "7d673e07393b45960e99b14bd2ebce77"
		 hash44= "8349691b6c37d9e5fa75ee6365b40bf5"
		 hash45= "840b05e6fefc3ce01bb181e0454c6bf5"
		 hash46= "88d2b57c8bf755c886b1bf30a4be87eb"
		 hash47= "8a8ee6f199438776f6842aab67fb953d"
		 hash48= "8cb10b202c47c41e1a2c11a721851654"
		 hash49= "8d20017f576fbd58cce25637d29826ca"
		 hash50= "8eabdff3d7d6bd826c109a37b10b218b"
		 hash51= "9b06c85682f8486d665f481e56ad65c7"
		 hash52= "a445d0bfafe5947492e4044cb49eda13"
		 hash53= "a4c07dbaa8ce969fd0f347d01776d03b"
		 hash54= "a765a20055059148af311023c95b9239"
		 hash55= "a7b7b485c266605e219ea185292443c8"
		 hash56= "a9f392eee93215109b2afc0c887128dc"
		 hash57= "aaee989b391dea8163ce5a0d6f55b317"
		 hash58= "ace2ace58cc68db21c38b43a0182fc8b"
		 hash59= "b15f9a6a0d6a5e52abc7a8134f856949"
		 hash60= "b5e7832464bff54896b1d42a76760dbc"
		 hash61= "c176286e35c0629ea526e299c369dc6e"
		 hash62= "c1d4b96374cfe485179b547ebacc1ee1"
		 hash63= "c214dc7763e98f2744dd5e7a44e80bba"
		 hash64= "c3869609968c97fd27e3dc71f26d98d3"
		 hash65= "c91efaa99a5d9c51dfe86ea286fab519"
		 hash66= "cbcff0eb404183902457332e72915d07"
		 hash67= "cd82d1dc730eb9e7e19802500417e58a"
		 hash68= "cf1d926f21bf93b958b55a43ee5317dc"
		 hash69= "d1eac0815f7244e799cf0883aab8ec3d"
		 hash70= "d3bf38bcf3a88e22eb6f5aad42f52846"
		 hash71= "d4bc7b620ab9ee2ded2ac783ad77dd6d"
		 hash72= "d73d232a9ae0e948c589148b061ccf03"
		 hash73= "db60f645e5efcb872ff843a696c6fe04"
		 hash74= "dc0fccad4972db4cf6cb85a4eabe8087"
		 hash75= "de7d2d4a6b093365013e6acf3e1d5a41"
		 hash76= "dee54d45b64fc48e35c80962fb44f73f"
		 hash77= "dfee3a4e1a137eda06e90540f3604ecb"
		 hash78= "e32dc66f1337cb8b1ed4f87a441e9457"
		 hash79= "e4192340a54d73dca73685ce999dc561"
		 hash80= "e61a40e9ddccc2412435d2f22b4227c2"
		 hash81= "e72a55235a65811e4afe31b857c5294d"
		 hash82= "eaaa0408c3cd686a30871fedf31ce241"
		 hash83= "f1059405feaaae373c59860fdec66fd0"
		 hash84= "f2449ecf637a370b6a0632a4b45cd554"
		 hash85= "f2a0df6b2a8de26d2f6e86ec46683808"
		 hash86= "f3917d618a37342eadfee90f8539b3b9"
		 hash87= "fc650a1292ade32e41d3fdc2fb7dd3f3"
		 hash88= "fcec72d588c1cdd03361a334f29c125b"
		 hash89= "fe9971fe78f3bc22c8df0553dced52ed"
		 hash90= "ff7611be7e3137708a68ea8523093419"

	strings:

	
 		 $s1= "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}" fullword wide
		 $s2= "6.0420.2600.2180 (rtm.040803-2158)" fullword wide
		 $s3= "6.0420.2600.2180 (xpsp_sp2_rtm.040803-2158)" fullword wide
		 $s4= "6.3.9600.16384 (winblue_rtm.130821-1623)" fullword wide
		 $s5= "CLSID{1006967F-7059-4DB4-A310-4F1A30F7BDC4}" fullword wide
		 $s6= "C:Program FilesExcalibur" fullword wide
		 $s7= "C:Program FilesExcalibur" fullword wide
		 $s8= "d1wmnlsnh8rftl.cloudfront.net" fullword wide
		 $s9= "f8ec627e_6c48_490e_a658_b046669d1d1c" fullword wide
		 $s10= "HttP://d1wmnlsnh8rftl.cloudfront.net/v4/" fullword wide
		 $s11= "PendingFileRenameOperations" fullword wide
		 $s12= "PsReferenceProcessFilePointer" fullword wide
		 $s13= "REGISTRYMACHINESOFTWAREClassesCLSID" fullword wide
		 $s14= "REGISTRYMACHINESYSTEMControlSet001Services" fullword wide
		 $s15= "REGISTRYMACHINESYSTEMCurrentControlSetServices" fullword wide
		 $s16= "SOFTWAREMicrosoftCryptography" fullword wide
		 $s17= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s18= "SoftwareMicrosoftWindowsCurrentVersionUninstall" fullword wide
		 $s19= "SOFTWAREMicrosoftWindowsCurrentVersionUninstallWinZipper" fullword wide
		 $s20= "spanish-dominican republic" fullword wide
		 $s21= "tianshiyed@iaomaomark1#23mark123tokenmarkqwebjiuga664115" fullword wide
		 $s22= "uninstallerOmigaZip.inst" fullword wide
		 $a1= "REGISTRYMACHINESYSTEMCurrentControlSetServices" fullword ascii
		 $a2= "SoftwareMicrosoftWindowsCurrentVersionUninstall" fullword ascii
		 $a3= "SOFTWAREMicrosoftWindowsCurrentVersionUninstallWinZipper" fullword ascii
		 $a4= "tianshiyed@iaomaomark1#23mark123tokenmarkqwebjiuga664115" fullword ascii

		 $hex1= {2461313d2022524547}
		 $hex2= {2461323d2022536f66}
		 $hex3= {2461333d2022534f46}
		 $hex4= {2461343d2022746961}
		 $hex5= {247331303d20224874}
		 $hex6= {247331313d20225065}
		 $hex7= {247331323d20225073}
		 $hex8= {247331333d20225245}
		 $hex9= {247331343d20225245}
		 $hex10= {247331353d20225245}
		 $hex11= {247331363d2022534f}
		 $hex12= {247331373d2022536f}
		 $hex13= {247331383d2022536f}
		 $hex14= {247331393d2022534f}
		 $hex15= {2473313d20223a3a7b}
		 $hex16= {247332303d20227370}
		 $hex17= {247332313d20227469}
		 $hex18= {247332323d2022756e}
		 $hex19= {2473323d2022362e30}
		 $hex20= {2473333d2022362e30}
		 $hex21= {2473343d2022362e33}
		 $hex22= {2473353d2022434c53}
		 $hex23= {2473363d2022433a50}
		 $hex24= {2473373d2022433a50}
		 $hex25= {2473383d2022643177}
		 $hex26= {2473393d2022663865}

	condition:
		17 of them
}
