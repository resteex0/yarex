
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Mamba 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Mamba {
	meta: 
		 description= "Ransomware_Mamba Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-37-45" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "409d80bb94645fbc4a1fa61c07806883"

	strings:

	
 		 $s1= "$dcsys$_fail_%x" fullword wide
		 $s2= "64NETPASS.EXE MOUNT.EXE" fullword wide
		 $s3= "Active partition" fullword wide
		 $s4= "AES-Twofish-Serpent" fullword wide
		 $s5= "american english" fullword wide
		 $s6= "american-english" fullword wide
		 $s7= "Applications key" fullword wide
		 $s8= "ArcNamemulti(0)disk(0)rdisk(0)partition(1)" fullword wide
		 $s9= "Authentication timeout" fullword wide
		 $s10= "Authentication type" fullword wide
		 $s11= "Browser Favorites" fullword wide
		 $s12= "Browser Forward" fullword wide
		 $s13= "Browser Refresh" fullword wide
		 $s14= "&Change Password" fullword wide
		 $s15= "Change password" fullword wide
		 $s16= "chinese-hongkong" fullword wide
		 $s17= "chinese-simplified" fullword wide
		 $s18= "chinese-singapore" fullword wide
		 $s19= "chinese-traditional" fullword wide
		 $s20= "Choice folder.." fullword wide
		 $s21= "DC_UI_DLG_CLASS" fullword wide
		 $s22= "Decrypting progress..." fullword wide
		 $s23= "Decryption cancelled" fullword wide
		 $s24= "Decryption finished" fullword wide
		 $s25= "DefaultInstance" fullword wide
		 $s26= "DefragmentService" fullword wide
		 $s27= "DFServerService.exe" fullword wide
		 $s28= "DiskCryptor api" fullword wide
		 $s29= "DiskCryptor console" fullword wide
		 $s30= "DiskCryptor driver" fullword wide
		 $s31= "DiskCryptor GUI" fullword wide
		 $s32= "DISKCRYPTOR_MUTEX" fullword wide
		 $s33= "DosDevicesdcrypt" fullword wide
		 $s34= "EC:DC22Mount.exe" fullword wide
		 $s35= "Encrypting/decrypting" fullword wide
		 $s36= "Encrypting iso-file.." fullword wide
		 $s37= "Encrypting progress..." fullword wide
		 $s38= "Encryption Benchmark" fullword wide
		 $s39= "Encryption cancelled" fullword wide
		 $s40= "Encryption finished" fullword wide
		 $s41= "Encryption mode" fullword wide
		 $s42= "Encrypt iso-file" fullword wide
		 $s43= "english-american" fullword wide
		 $s44= "english-caribbean" fullword wide
		 $s45= "english-jamaica" fullword wide
		 $s46= "english-south africa" fullword wide
		 $s47= "FileDescription" fullword wide
		 $s48= "Formatting cancelled" fullword wide
		 $s49= "Formatting progress..." fullword wide
		 $s50= "french-canadian" fullword wide
		 $s51= "french-luxembourg" fullword wide
		 $s52= "&Generate Keyfile" fullword wide
		 $s53= "german-austrian" fullword wide
		 $s54= "german-lichtenstein" fullword wide
		 $s55= "german-luxembourg" fullword wide
		 $s56= "http://diskcryptor.net/" fullword wide
		 $s57= "http://diskcryptor.net/forum" fullword wide
		 $s58= "http://diskcryptor.net/index.php/DiskCryptor" fullword wide
		 $s59= "&Install Loader" fullword wide
		 $s60= "Invalid password" fullword wide
		 $s61= "jDC_UI_DLG_CLASS" fullword wide
		 $s62= "Keyboard Layout" fullword wide
		 $s63= "msctls_progress32" fullword wide
		 $s64= "norwegian-bokmal" fullword wide
		 $s65= "norwegian-nynorsk" fullword wide
		 $s66= "OriginalFilename" fullword wide
		 $s67= "Password request" fullword wide
		 $s68= "\\.PhysicalDrive%d" fullword wide
		 $s69= "Play/Pause Media" fullword wide
		 $s70= "portuguese-brazilian" fullword wide
		 $s71= "Reencrypt Volume" fullword wide
		 $s72= "Retry authentication" fullword wide
		 $s73= "%s$DC_TRIM_%x$" fullword wide
		 $s74= "%sdrivers%s.sys" fullword wide
		 $s75= "Sector: %I64d " fullword wide
		 $s76= "Select Folder.." fullword wide
		 $s77= "Select partition:" fullword wide
		 $s78= "SeShutdownPrivilege" fullword wide
		 $s79= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s80= "SoftwareMicrosoftWindowsCurrentVersionRunOnce" fullword wide
		 $s81= "SOFTWAREMicrosoftWindowsCurrentVersionUninstall" fullword wide
		 $s82= "spanish-argentina" fullword wide
		 $s83= "spanish-bolivia" fullword wide
		 $s84= "spanish-colombia" fullword wide
		 $s85= "spanish-costa rica" fullword wide
		 $s86= "spanish-dominican republic" fullword wide
		 $s87= "spanish-ecuador" fullword wide
		 $s88= "spanish-el salvador" fullword wide
		 $s89= "spanish-guatemala" fullword wide
		 $s90= "spanish-honduras" fullword wide
		 $s91= "spanish-mexican" fullword wide
		 $s92= "spanish-nicaragua" fullword wide
		 $s93= "spanish-paraguay" fullword wide
		 $s94= "spanish-puerto rico" fullword wide
		 $s95= "spanish-uruguay" fullword wide
		 $s96= "spanish-venezuela" fullword wide
		 $s97= "Special Symbols" fullword wide
		 $s98= "Specified partition" fullword wide
		 $s99= "swedish-finland" fullword wide
		 $s100= "SysTabControl32" fullword wide
		 $s101= "SYSTEMCurrentControlSetControlCrashControl" fullword wide
		 $s102= "SYSTEMCurrentControlSetServicesdcryptconfig" fullword wide
		 $s103= "SYSTEMCurrentControlSetServicesdcryptInstances" fullword wide
		 $s104= "Trivially Breakable" fullword wide
		 $s105= "Twofish-Serpent" fullword wide
		 $s106= "Uninstall Driver" fullword wide
		 $s107= "Update DiskCryptor?" fullword wide
		 $s108= "VS_VERSION_INFO" fullword wide
		 $a1= "ArcNamemulti(0)disk(0)rdisk(0)partition(1)" fullword ascii
		 $a2= "http://diskcryptor.net/index.php/DiskCryptor" fullword ascii
		 $a3= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword ascii
		 $a4= "SoftwareMicrosoftWindowsCurrentVersionRunOnce" fullword ascii
		 $a5= "SOFTWAREMicrosoftWindowsCurrentVersionUninstall" fullword ascii
		 $a6= "SYSTEMCurrentControlSetControlCrashControl" fullword ascii
		 $a7= "SYSTEMCurrentControlSetServicesdcryptconfig" fullword ascii
		 $a8= "SYSTEMCurrentControlSetServicesdcryptInstances" fullword ascii

		 $hex1= {2461313d2022417263}
		 $hex2= {2461323d2022687474}
		 $hex3= {2461333d2022536f66}
		 $hex4= {2461343d2022536f66}
		 $hex5= {2461353d2022534f46}
		 $hex6= {2461363d2022535953}
		 $hex7= {2461373d2022535953}
		 $hex8= {2461383d2022535953}
		 $hex9= {24733130303d202253}
		 $hex10= {24733130313d202253}
		 $hex11= {24733130323d202253}
		 $hex12= {24733130333d202253}
		 $hex13= {24733130343d202254}
		 $hex14= {24733130353d202254}
		 $hex15= {24733130363d202255}
		 $hex16= {24733130373d202255}
		 $hex17= {24733130383d202256}
		 $hex18= {247331303d20224175}
		 $hex19= {247331313d20224272}
		 $hex20= {247331323d20224272}
		 $hex21= {247331333d20224272}
		 $hex22= {247331343d20222643}
		 $hex23= {247331353d20224368}
		 $hex24= {247331363d20226368}
		 $hex25= {247331373d20226368}
		 $hex26= {247331383d20226368}
		 $hex27= {247331393d20226368}
		 $hex28= {2473313d2022246463}
		 $hex29= {247332303d20224368}
		 $hex30= {247332313d20224443}
		 $hex31= {247332323d20224465}
		 $hex32= {247332333d20224465}
		 $hex33= {247332343d20224465}
		 $hex34= {247332353d20224465}
		 $hex35= {247332363d20224465}
		 $hex36= {247332373d20224446}
		 $hex37= {247332383d20224469}
		 $hex38= {247332393d20224469}
		 $hex39= {2473323d202236344e}
		 $hex40= {247333303d20224469}
		 $hex41= {247333313d20224469}
		 $hex42= {247333323d20224449}
		 $hex43= {247333333d2022446f}
		 $hex44= {247333343d20224543}
		 $hex45= {247333353d2022456e}
		 $hex46= {247333363d2022456e}
		 $hex47= {247333373d2022456e}
		 $hex48= {247333383d2022456e}
		 $hex49= {247333393d2022456e}
		 $hex50= {2473333d2022416374}
		 $hex51= {247334303d2022456e}
		 $hex52= {247334313d2022456e}
		 $hex53= {247334323d2022456e}
		 $hex54= {247334333d2022656e}
		 $hex55= {247334343d2022656e}
		 $hex56= {247334353d2022656e}
		 $hex57= {247334363d2022656e}
		 $hex58= {247334373d20224669}
		 $hex59= {247334383d2022466f}
		 $hex60= {247334393d2022466f}
		 $hex61= {2473343d2022414553}
		 $hex62= {247335303d20226672}
		 $hex63= {247335313d20226672}
		 $hex64= {247335323d20222647}
		 $hex65= {247335333d20226765}
		 $hex66= {247335343d20226765}
		 $hex67= {247335353d20226765}
		 $hex68= {247335363d20226874}
		 $hex69= {247335373d20226874}
		 $hex70= {247335383d20226874}
		 $hex71= {247335393d20222649}
		 $hex72= {2473353d2022616d65}
		 $hex73= {247336303d2022496e}
		 $hex74= {247336313d20226a44}
		 $hex75= {247336323d20224b65}
		 $hex76= {247336333d20226d73}
		 $hex77= {247336343d20226e6f}
		 $hex78= {247336353d20226e6f}
		 $hex79= {247336363d20224f72}
		 $hex80= {247336373d20225061}
		 $hex81= {247336383d20222e50}
		 $hex82= {247336393d2022506c}
		 $hex83= {2473363d2022616d65}
		 $hex84= {247337303d2022706f}
		 $hex85= {247337313d20225265}
		 $hex86= {247337323d20225265}
		 $hex87= {247337333d20222573}
		 $hex88= {247337343d20222573}
		 $hex89= {247337353d20225365}
		 $hex90= {247337363d20225365}
		 $hex91= {247337373d20225365}
		 $hex92= {247337383d20225365}
		 $hex93= {247337393d2022536f}
		 $hex94= {2473373d2022417070}
		 $hex95= {247338303d2022536f}
		 $hex96= {247338313d2022534f}
		 $hex97= {247338323d20227370}
		 $hex98= {247338333d20227370}
		 $hex99= {247338343d20227370}
		 $hex100= {247338353d20227370}
		 $hex101= {247338363d20227370}
		 $hex102= {247338373d20227370}
		 $hex103= {247338383d20227370}
		 $hex104= {247338393d20227370}
		 $hex105= {2473383d2022417263}
		 $hex106= {247339303d20227370}
		 $hex107= {247339313d20227370}
		 $hex108= {247339323d20227370}
		 $hex109= {247339333d20227370}
		 $hex110= {247339343d20227370}
		 $hex111= {247339353d20227370}
		 $hex112= {247339363d20227370}
		 $hex113= {247339373d20225370}
		 $hex114= {247339383d20225370}
		 $hex115= {247339393d20227377}
		 $hex116= {2473393d2022417574}

	condition:
		38 of them
}
