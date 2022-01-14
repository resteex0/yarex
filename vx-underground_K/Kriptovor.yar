
/*
   YARA Rule Set
   Author: resteex
   Identifier: Kriptovor 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Kriptovor {
	meta: 
		 description= "Kriptovor Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_03-23-52" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "00e3b69b18bfad7980c1621256ee10fa"
		 hash2= "16ef21dc28880a9bf4cd466618bcc2b1"
		 hash3= "2191510667defe7f386fc1c889e5b731"
		 hash4= "23afbf34eb2cbe2043a69233c6d1301b"
		 hash5= "2771174563606448a10cb0b5062825a5"
		 hash6= "28dae07573fecee2b28137205f8d9a98"
		 hash7= "29fe76f31482a42ba72f4015812184a3"
		 hash8= "2bcc3a2178cf01aece6284ef0932181b"
		 hash9= "2ea06433f5ae3bffa5896100d5361458"
		 hash10= "39391e022ce89784eb46fed43c8aa341"
		 hash11= "488ba9382c9ee260bbca1ef03e843981"
		 hash12= "4add1925e46ed6576861f62ebb016185"
		 hash13= "522dd6d774e7f53108e73a5f3935ba20"
		 hash14= "59b3597c3bbb8b389c02cce660431b75"
		 hash15= "68dfcb48d99a0735fdf477b869eac9df"
		 hash16= "6e618523c3eb5c286149c020fd6afadd"
		 hash17= "7bb86f70896668026b6d4b5367286d6a"
		 hash18= "7da180d0e49ee2b892c25bc93865b250"
		 hash19= "890c9bb8b257636a6e2081acdfdd6e3c"
		 hash20= "89fd244336cdb8fab0527609ca738afb"
		 hash21= "90a75836352c7662cb63dbc566f8e2de"
		 hash22= "a08b44d7f569c36e33cd9042ba7e5b42"
		 hash23= "a0a616b10019f1205a33462ab383c64b"
		 hash24= "a289ee37d8f17ef34dbf3751c3736162"
		 hash25= "a5d87890fa20020e6fdb1d7408c8a1ca"
		 hash26= "af6d27b47ae5a39db78972be5cbd3fa0"
		 hash27= "b98abbf8d47113dd53216bcfd0356175"
		 hash28= "b9cd15b5508608cd05dfa26b6a7c9acb"
		 hash29= "c3ab87f85ca07a7d026d3cbd54029bbe"
		 hash30= "d2aa056f1cb2b24e1ab4bb43169d8029"
		 hash31= "db4c2df5984e143abbfae023ee932ff8"
		 hash32= "dcadfe8c1da9616b69b1101e7980f263"
		 hash33= "e5765ebfdbe441e444d30ae804f9e01b"
		 hash34= "e5a65138290f1f972a29fdab52990eb9"
		 hash35= "fccb80162484b146619b4a9d9d0f6df9"
		 hash36= "fdd4f8ba09da78e1ff2957305d71563f"

	strings:

	
 		 $s1= "{%08lX-%04hX-%04hX-%02X%02X-%02X%02X%02X%02X%02X%02X}" fullword wide
		 $s2= "6.1.7600.16385 (win7_rtm.090713-1255)" fullword wide
		 $s3= ".cab=application/vnd.ms-cab-compressed" fullword wide
		 $s4= "C:BuildsTPindysocketslibCoreIdIOHandler.pas" fullword wide
		 $s5= "C:BuildsTPindysocketslibCoreIdIOHandlerStack.pas" fullword wide
		 $s6= "C:BuildsTPindysocketslibCoreIdScheduler.pas" fullword wide
		 $s7= "C:BuildsTPindysocketslibCoreIdThread.pas" fullword wide
		 $s8= "C:BuildsTPindysocketslibProtocolsIdCoder3to4.pas" fullword wide
		 $s9= "C:BuildsTPindysocketslibProtocolsIdGlobalProtocols.pas" fullword wide
		 $s10= "C:BuildsTPindysocketslibProtocolsIdHeaderCoderIndy.pas" fullword wide
		 $s11= "C:BuildsTPindysocketslibProtocolsIdHTTP.pas" fullword wide
		 $s12= "C:BuildsTPindysocketslibProtocolsIdMessageClient.pas" fullword wide
		 $s13= "C:BuildsTPindysocketslibProtocolsIdSSLOpenSSLHeaders.pas" fullword wide
		 $s14= "C:BuildsTPindysocketslibProtocolsIdSSLOpenSSL.pas" fullword wide
		 $s15= "C:BuildsTPindysocketslibProtocolsIdZLibCompressorBase.pas" fullword wide
		 $s16= "C:BuildsTPindysocketslibSystemIdGlobal.pas" fullword wide
		 $s17= "C:BuildsTPindysocketslibSystemIdStack.pas" fullword wide
		 $s18= "C:BuildsTPindysocketslibSystemIdStreamVCL.pas" fullword wide
		 $s19= "C:UsersChekerAppDataLocalTempAdobeReader (2).exe" fullword wide
		 $s20= "C:UsersChekerAppDataLocalTempAdobeReader.exe" fullword wide
		 $s21= "Extended_UNIX_Code_Fixed_Width_for_Japanese" fullword wide
		 $s22= "Extended_UNIX_Code_Packed_Format_for_Japanese" fullword wide
		 $s23= ".fml=application/x-file-mirror-list" fullword wide
		 $s24= "HARDWAREACPIDSDTParallels Workstation" fullword wide
		 $s25= "HARDWAREACPIDSDTVMware Workstation" fullword wide
		 $s26= "http://noproblembro.com/PHP/develop/config_add.php?name=" fullword wide
		 $s27= "http://noproblembro.com/PHP/develop/report.php?name=" fullword wide
		 $s28= "http://noproblembro.com/PHP/develop/sql_install.php?name=" fullword wide
		 $s29= "http://noproblembro.com/PHP/sucrot/pub_ns.rar" fullword wide
		 $s30= "http://noproblembro.com/PHP/sucrot/pub.rar" fullword wide
		 $s31= "HYPERLINK http://stafferyonline.ru/" fullword wide
		 $s32= ".kpr=application/vnd.kde.kpresenter" fullword wide
		 $s33= ".kpt=application/vnd.kde.kpresenter" fullword wide
		 $s34= ".mjf=audio/x-vnd.AudioExplosion.MjuiceMediaFile" fullword wide
		 $s35= ".odb=application/vnd.oasis.opendocument.database" fullword wide
		 $s36= ".odc=application/vnd.oasis.opendocument.chart" fullword wide
		 $s37= ".odf=application/vnd.oasis.opendocument.formula" fullword wide
		 $s38= ".odg=application/vnd.oasis.opendocument.graphics" fullword wide
		 $s39= ".odi=application/vnd.oasis.opendocument.image" fullword wide
		 $s40= ".odm=application/vnd.oasis.opendocument.text-master" fullword wide
		 $s41= ".odp=application/vnd.oasis.opendocument.presentation" fullword wide
		 $s42= ".ods=application/vnd.oasis.opendocument.spreadsheet" fullword wide
		 $s43= ".odt=application/vnd.oasis.opendocument.text" fullword wide
		 $s44= ".otg=application/vnd.oasis.opendocument.graphics-template" fullword wide
		 $s45= ".oth=application/vnd.oasis.opendocument.text-web" fullword wide
		 $s46= ".otp=application/vnd.oasis.opendocument.presentation-template" fullword wide
		 $s47= ".ots=application/vnd.oasis.opendocument.spreadsheet-template" fullword wide
		 $s48= ".ott=application/vnd.oasis.opendocument.text-template" fullword wide
		 $s49= ".p7b=application/x-pkcs7-certificates" fullword wide
		 $s50= ".p7r=application/x-pkcs7-certreqresp" fullword wide
		 $s51= ".package=application/vnd.autopackage" fullword wide
		 $s52= ".rjs=application/vnd.rn-realsystem-rjs" fullword wide
		 $s53= ".rmp=application/vnd.rn-rn_music_package" fullword wide
		 $s54= ".rmx=application/vnd.rn-realsystem-rmx" fullword wide
		 $s55= ".rpm=application/x-redhat-package-manager" fullword wide
		 $s56= ".sda=application/vnd.stardivision.draw" fullword wide
		 $s57= ".sdc=application/vnd.stardivision.calc" fullword wide
		 $s58= ".sdd=application/vnd.stardivision.impress" fullword wide
		 $s59= ".ser=application/java-serialized-object" fullword wide
		 $s60= ".setpay=application/set-payment-initiation" fullword wide
		 $s61= ".setreg=application/set-registration-initiation" fullword wide
		 $s62= ".smf=application/vnd.stardivision.math" fullword wide
		 $s63= "SOFTWAREClassesFoldershellsandbox" fullword wide
		 $s64= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s65= "SoftwareMicrosoftWindowsCurrentVersionRunOnce" fullword wide
		 $s66= "SOFTWAREMicrosoftWindowsCurrentVersionUninstallSandboxie" fullword wide
		 $s67= "SSL_CTX_set_default_passwd_cb_userdata" fullword wide
		 $s68= ".sst=application/vnd.ms-pki.certstore" fullword wide
		 $s69= ".stc=application/vnd.sun.xml.calc.template" fullword wide
		 $s70= ".std=application/vnd.sun.xml.draw.template" fullword wide
		 $s71= ".sti=application/vnd.sun.xml.impress.template" fullword wide
		 $s72= ".stw=application/vnd.sun.xml.writer.template" fullword wide
		 $s73= ".sxg=application/vnd.sun.xml.writer.global" fullword wide
		 $s74= ".sxi=application/vnd.sun.xml.impress" fullword wide
		 $s75= ".sxw=application/vnd.sun.xml.writer" fullword wide
		 $s76= "SYSTEMControlSet001ControlSystemInformation" fullword wide
		 $s77= ".vor=application/vnd.stardivision.writer" fullword wide
		 $s78= ".wmlsc=application/vnd.wap.wmlscriptc" fullword wide
		 $s79= ".xps=application/vnd.ms-xpsdocument" fullword wide
		 $s80= ".xul=application/vnd.mozilla.xul+xml" fullword wide
		 $a1= "{%08lX-%04hX-%04hX-%02X%02X-%02X%02X%02X%02X%02X%02X}" fullword ascii
		 $a2= "C:BuildsTPindysocketslibCoreIdIOHandlerStack.pas" fullword ascii
		 $a3= "C:BuildsTPindysocketslibProtocolsIdCoder3to4.pas" fullword ascii
		 $a4= "C:BuildsTPindysocketslibProtocolsIdGlobalProtocols.pas" fullword ascii
		 $a5= "C:BuildsTPindysocketslibProtocolsIdHeaderCoderIndy.pas" fullword ascii
		 $a6= "C:BuildsTPindysocketslibProtocolsIdMessageClient.pas" fullword ascii
		 $a7= "C:BuildsTPindysocketslibProtocolsIdSSLOpenSSLHeaders.pas" fullword ascii
		 $a8= "C:BuildsTPindysocketslibProtocolsIdSSLOpenSSL.pas" fullword ascii
		 $a9= "C:BuildsTPindysocketslibProtocolsIdZLibCompressorBase.pas" fullword ascii
		 $a10= "C:BuildsTPindysocketslibSystemIdStreamVCL.pas" fullword ascii
		 $a11= "C:UserschekerAppDataLocalTempAdobeReader (2).exe" fullword ascii
		 $a12= "C:UserschekerAppDataLocalTempAdobeReader.exe" fullword ascii
		 $a13= "http://noproblembro.com/PHP/develop/config_add.php?name=" fullword ascii
		 $a14= "http://noproblembro.com/PHP/develop/report.php?name=" fullword ascii
		 $a15= "http://noproblembro.com/PHP/develop/sql_install.php?name=" fullword ascii
		 $a16= ".odm=application/vnd.oasis.opendocument.text-master" fullword ascii
		 $a17= ".odp=application/vnd.oasis.opendocument.presentation" fullword ascii
		 $a18= ".ods=application/vnd.oasis.opendocument.spreadsheet" fullword ascii
		 $a19= ".otg=application/vnd.oasis.opendocument.graphics-template" fullword ascii
		 $a20= ".otp=application/vnd.oasis.opendocument.presentation-template" fullword ascii
		 $a21= ".ots=application/vnd.oasis.opendocument.spreadsheet-template" fullword ascii
		 $a22= ".ott=application/vnd.oasis.opendocument.text-template" fullword ascii
		 $a23= "SoftwareMicrosoftWindowsCurrentVersionRunOnce" fullword ascii
		 $a24= "SOFTWAREMicrosoftWindowsCurrentVersionUninstallSandboxie" fullword ascii

		 $hex1= {246131303d2022433a}
		 $hex2= {246131313d2022433a}
		 $hex3= {246131323d2022433a}
		 $hex4= {246131333d20226874}
		 $hex5= {246131343d20226874}
		 $hex6= {246131353d20226874}
		 $hex7= {246131363d20222e6f}
		 $hex8= {246131373d20222e6f}
		 $hex9= {246131383d20222e6f}
		 $hex10= {246131393d20222e6f}
		 $hex11= {2461313d20227b2530}
		 $hex12= {246132303d20222e6f}
		 $hex13= {246132313d20222e6f}
		 $hex14= {246132323d20222e6f}
		 $hex15= {246132333d2022536f}
		 $hex16= {246132343d2022534f}
		 $hex17= {2461323d2022433a42}
		 $hex18= {2461333d2022433a42}
		 $hex19= {2461343d2022433a42}
		 $hex20= {2461353d2022433a42}
		 $hex21= {2461363d2022433a42}
		 $hex22= {2461373d2022433a42}
		 $hex23= {2461383d2022433a42}
		 $hex24= {2461393d2022433a42}
		 $hex25= {247331303d2022433a}
		 $hex26= {247331313d2022433a}
		 $hex27= {247331323d2022433a}
		 $hex28= {247331333d2022433a}
		 $hex29= {247331343d2022433a}
		 $hex30= {247331353d2022433a}
		 $hex31= {247331363d2022433a}
		 $hex32= {247331373d2022433a}
		 $hex33= {247331383d2022433a}
		 $hex34= {247331393d2022433a}
		 $hex35= {2473313d20227b2530}
		 $hex36= {247332303d2022433a}
		 $hex37= {247332313d20224578}
		 $hex38= {247332323d20224578}
		 $hex39= {247332333d20222e66}
		 $hex40= {247332343d20224841}
		 $hex41= {247332353d20224841}
		 $hex42= {247332363d20226874}
		 $hex43= {247332373d20226874}
		 $hex44= {247332383d20226874}
		 $hex45= {247332393d20226874}
		 $hex46= {2473323d2022362e31}
		 $hex47= {247333303d20226874}
		 $hex48= {247333313d20224859}
		 $hex49= {247333323d20222e6b}
		 $hex50= {247333333d20222e6b}
		 $hex51= {247333343d20222e6d}
		 $hex52= {247333353d20222e6f}
		 $hex53= {247333363d20222e6f}
		 $hex54= {247333373d20222e6f}
		 $hex55= {247333383d20222e6f}
		 $hex56= {247333393d20222e6f}
		 $hex57= {2473333d20222e6361}
		 $hex58= {247334303d20222e6f}
		 $hex59= {247334313d20222e6f}
		 $hex60= {247334323d20222e6f}
		 $hex61= {247334333d20222e6f}
		 $hex62= {247334343d20222e6f}
		 $hex63= {247334353d20222e6f}
		 $hex64= {247334363d20222e6f}
		 $hex65= {247334373d20222e6f}
		 $hex66= {247334383d20222e6f}
		 $hex67= {247334393d20222e70}
		 $hex68= {2473343d2022433a42}
		 $hex69= {247335303d20222e70}
		 $hex70= {247335313d20222e70}
		 $hex71= {247335323d20222e72}
		 $hex72= {247335333d20222e72}
		 $hex73= {247335343d20222e72}
		 $hex74= {247335353d20222e72}
		 $hex75= {247335363d20222e73}
		 $hex76= {247335373d20222e73}
		 $hex77= {247335383d20222e73}
		 $hex78= {247335393d20222e73}
		 $hex79= {2473353d2022433a42}
		 $hex80= {247336303d20222e73}
		 $hex81= {247336313d20222e73}
		 $hex82= {247336323d20222e73}
		 $hex83= {247336333d2022534f}
		 $hex84= {247336343d2022536f}
		 $hex85= {247336353d2022536f}
		 $hex86= {247336363d2022534f}
		 $hex87= {247336373d20225353}
		 $hex88= {247336383d20222e73}
		 $hex89= {247336393d20222e73}
		 $hex90= {2473363d2022433a42}
		 $hex91= {247337303d20222e73}
		 $hex92= {247337313d20222e73}
		 $hex93= {247337323d20222e73}
		 $hex94= {247337333d20222e73}
		 $hex95= {247337343d20222e73}
		 $hex96= {247337353d20222e73}
		 $hex97= {247337363d20225359}
		 $hex98= {247337373d20222e76}
		 $hex99= {247337383d20222e77}
		 $hex100= {247337393d20222e78}
		 $hex101= {2473373d2022433a42}
		 $hex102= {247338303d20222e78}
		 $hex103= {2473383d2022433a42}
		 $hex104= {2473393d2022433a42}

	condition:
		13 of them
}
