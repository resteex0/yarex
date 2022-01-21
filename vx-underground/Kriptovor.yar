
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Kriptovor 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Kriptovor {
	meta: 
		 description= "vx_underground2_Kriptovor Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-05-51" 
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
		 $s3= ".aab=application/x-authorware-bin" fullword wide
		 $s4= ".aam=application/x-authorware-map" fullword wide
		 $s5= ".aas=application/x-authorware-seg" fullword wide
		 $s6= ".abw=application/x-abiword" fullword wide
		 $s7= ".ai=application/postscript" fullword wide
		 $s8= "application/x-www-form-urlencoded" fullword wide
		 $s9= ".asf=application/vnd.ms-asf" fullword wide
		 $s10= ".asx=video/x-ms-asf-plugin" fullword wide
		 $s11= ".bat=application/x-msdos-program" fullword wide
		 $s12= ".bcpio=application/x-bcpio" fullword wide
		 $s13= ".cab=application/vnd.ms-cab-compressed" fullword wide
		 $s14= ".cat=application/vnd.ms-pki.seccat" fullword wide
		 $s15= "C:BuildsTPindysocketslibCoreIdIOHandler.pas" fullword wide
		 $s16= "C:BuildsTPindysocketslibCoreIdIOHandlerStack.pas" fullword wide
		 $s17= "C:BuildsTPindysocketslibCoreIdScheduler.pas" fullword wide
		 $s18= "C:BuildsTPindysocketslibCoreIdThread.pas" fullword wide
		 $s19= "C:BuildsTPindysocketslibProtocolsIdCoder3to4.pas" fullword wide
		 $s20= "C:BuildsTPindysocketslibProtocolsIdGlobalProtocols.pas" fullword wide
		 $s21= "C:BuildsTPindysocketslibProtocolsIdHeaderCoderIndy.pas" fullword wide
		 $s22= "C:BuildsTPindysocketslibProtocolsIdHTTP.pas" fullword wide
		 $s23= "C:BuildsTPindysocketslibProtocolsIdMessageClient.pas" fullword wide
		 $s24= "C:BuildsTPindysocketslibProtocolsIdSSLOpenSSLHeaders.pas" fullword wide
		 $s25= "C:BuildsTPindysocketslibProtocolsIdSSLOpenSSL.pas" fullword wide
		 $s26= "C:BuildsTPindysocketslibProtocolsIdZLibCompressorBase.pas" fullword wide
		 $s27= "C:BuildsTPindysocketslibSystemIdGlobal.pas" fullword wide
		 $s28= "C:BuildsTPindysocketslibSystemIdStack.pas" fullword wide
		 $s29= "C:BuildsTPindysocketslibSystemIdStreamVCL.pas" fullword wide
		 $s30= ".cer=application/x-x509-ca-cert" fullword wide
		 $s31= "CERTIF CERTIFMGR CHARTABLE" fullword wide
		 $s32= ".chm=application/vnd.ms-htmlhelp" fullword wide
		 $s33= ".chrt=application/vnd.kde.kchart" fullword wide
		 $s34= ".cil=application/vnd.ms-artgalry" fullword wide
		 $s35= ".class=application/java-vm" fullword wide
		 $s36= ".clp=application/x-msclip" fullword wide
		 $s37= ".com=application/x-msdos-program" fullword wide
		 $s38= "Content-Transfer-Encoding" fullword wide
		 $s39= "Content-Transfer-Encoding: " fullword wide
		 $s40= ".cpt=application/mac-compactpro" fullword wide
		 $s41= ".cqk=application/x-calquick" fullword wide
		 $s42= ".crd=application/x-mscardfile" fullword wide
		 $s43= ".crl=application/pkix-crl" fullword wide
		 $s44= "CRYPTO_cleanup_all_ex_data" fullword wide
		 $s45= "CRYPTO_set_locking_callback" fullword wide
		 $s46= "CRYPTO_set_mem_debug_functions" fullword wide
		 $s47= "csISO95JIS62291984handadd" fullword wide
		 $s48= "C:UsersChekerAppDataLocalTempAdobeReader (2).exe" fullword wide
		 $s49= "C:UsersChekerAppDataLocalTempAdobeReader.exe" fullword wide
		 $s50= ".dcr=application/x-director" fullword wide
		 $s51= ".deb=application/x-debian-package" fullword wide
		 $s52= ".dir=application/x-director" fullword wide
		 $s53= "Disposition-Notification-To" fullword wide
		 $s54= ".dist=vnd.apple.installer+xml" fullword wide
		 $s55= ".distz=vnd.apple.installer+xml" fullword wide
		 $s56= ".dll=application/x-msdos-program" fullword wide
		 $s57= ".dmg=application/x-apple-diskimage" fullword wide
		 $s58= "DocumentSummaryInformation" fullword wide
		 $s59= ".dxr=application/x-director" fullword wide
		 $s60= "ebcdic-international-500+euro" fullword wide
		 $s61= ".ebk=application/x-expandedbook" fullword wide
		 $s62= "Encrypt Algorithm.Parameters::" fullword wide
		 $s63= ".eps=application/postscript" fullword wide
		 $s64= ".exe=application/x-msdos-program" fullword wide
		 $s65= "Extended_UNIX_Code_Fixed_Width_for_Japanese" fullword wide
		 $s66= "Extended_UNIX_Code_Packed_Format_for_Japanese" fullword wide
		 $s67= ".fif=application/fractals" fullword wide
		 $s68= ".flm=application/vnd.kde.kivio" fullword wide
		 $s69= ".fml=application/x-file-mirror-list" fullword wide
		 $s70= ".gnumeric=application/x-gnumeric" fullword wide
		 $s71= "HARDWAREACPIDSDTAMIBI" fullword wide
		 $s72= "HARDWAREACPIDSDTParallels Workstation" fullword wide
		 $s73= "HARDWAREACPIDSDTPRLS__" fullword wide
		 $s74= "HARDWAREACPIDSDTPTLTD__" fullword wide
		 $s75= "HARDWAREACPIDSDTVBOX__" fullword wide
		 $s76= "HARDWAREACPIDSDTVirtualBox" fullword wide
		 $s77= "HARDWAREACPIDSDTVirtual PC" fullword wide
		 $s78= "HARDWAREACPIDSDTVMware Workstation" fullword wide
		 $s79= "HashAlgorithm.Parameters::" fullword wide
		 $s80= ".hpf=application/x-icq-hpf" fullword wide
		 $s81= ".hqx=application/mac-binhex40" fullword wide
		 $s82= "http://checkip.dyndns.org" fullword wide
		 $s83= "http://noproblembro.com/PHP/develop/config_add.php?name=" fullword wide
		 $s84= "http://noproblembro.com/PHP/develop/report.php?name=" fullword wide
		 $s85= "http://noproblembro.com/PHP/develop/sql_install.php?name=" fullword wide
		 $s86= "http://noproblembro.com/PHP/sucrot/pub_ns.rar" fullword wide
		 $s87= "http://noproblembro.com/PHP/sucrot/pub.rar" fullword wide
		 $s88= "http://stafferyonline.ru/" fullword wide
		 $s89= "http://www.indyproject.org/" fullword wide
		 $s90= "http://www.inrecolan.com/" fullword wide
		 $s91= "HYPERLINK http://stafferyonline.ru/" fullword wide
		 $s92= "HYPERLINK http://www.inrecolan.com" fullword wide
		 $s93= ".iii=application/x-iphone" fullword wide
		 $s94= ".ims=application/vnd.ms-ims" fullword wide
		 $s95= "InitializeConditionVariable" fullword wide
		 $s96= ".ins=application/x-internet-signup" fullword wide
		 $s97= "ISO-8859-1-Windows-3.0-Latin-1" fullword wide
		 $s98= "ISO-8859-1-Windows-3.1-Latin-1" fullword wide
		 $s99= "ISO-8859-2-Windows-Latin-2" fullword wide
		 $s100= "ISO-8859-9-Windows-Latin-5" fullword wide
		 $s101= ".iso=application/x-iso9660-image" fullword wide
		 $s102= ".jar=application/java-archive" fullword wide
		 $s103= ".karbon=application/vnd.kde.karbon" fullword wide
		 $s104= ".kfo=application/vnd.kde.kformula" fullword wide
		 $s105= ".kon=application/vnd.kde.kontour" fullword wide
		 $s106= ".kpr=application/vnd.kde.kpresenter" fullword wide
		 $s107= ".kpt=application/vnd.kde.kpresenter" fullword wide
		 $s108= ".kwd=application/vnd.kde.kword" fullword wide
		 $s109= ".kwt=application/vnd.kde.kword" fullword wide
		 $s110= ".latex=application/x-latex" fullword wide
		 $s111= ".lrm=application/vnd.ms-lrm" fullword wide
		 $s112= ".m13=application/x-msmediaview" fullword wide
		 $s113= ".m14=application/x-msmediaview" fullword wide
		 $s114= ".man=application/x-troff-man" fullword wide
		 $s115= ".mdb=application/x-msaccess" fullword wide
		 $s116= ".me=application/x-troff-me" fullword wide
		 $s117= "MIMEDatabaseContent Type" fullword wide
		 $s118= "MIMEDatabaseContent Type" fullword wide
		 $s119= ".mjf=audio/x-vnd.AudioExplosion.MjuiceMediaFile" fullword wide
		 $s120= ".mny=application/x-msmoney" fullword wide
		 $s121= ".mpkg=vnd.apple.installer+xml" fullword wide
		 $s122= ".mpp=application/vnd.ms-project" fullword wide
		 $s123= ".ms=application/x-troff-ms" fullword wide
		 $s124= "multipart/form-data; boundary=" fullword wide
		 $s125= ".mvb=application/x-msmediaview" fullword wide
		 $s126= ".nix=application/x-mix-transfer" fullword wide
		 $s127= ".odb=application/vnd.oasis.opendocument.database" fullword wide
		 $s128= ".odc=application/vnd.oasis.opendocument.chart" fullword wide
		 $s129= ".odf=application/vnd.oasis.opendocument.formula" fullword wide
		 $s130= ".odg=application/vnd.oasis.opendocument.graphics" fullword wide
		 $s131= ".odi=application/vnd.oasis.opendocument.image" fullword wide
		 $s132= ".odm=application/vnd.oasis.opendocument.text-master" fullword wide
		 $s133= ".odp=application/vnd.oasis.opendocument.presentation" fullword wide
		 $s134= ".ods=application/vnd.oasis.opendocument.spreadsheet" fullword wide
		 $s135= ".odt=application/vnd.oasis.opendocument.text" fullword wide
		 $s136= "_ossl_old_des_ecb_encrypt" fullword wide
		 $s137= "_ossl_old_des_set_odd_parity" fullword wide
		 $s138= ".otg=application/vnd.oasis.opendocument.graphics-template" fullword wide
		 $s139= ".oth=application/vnd.oasis.opendocument.text-web" fullword wide
		 $s140= ".otp=application/vnd.oasis.opendocument.presentation-template" fullword wide
		 $s141= ".ots=application/vnd.oasis.opendocument.spreadsheet-template" fullword wide
		 $s142= ".ott=application/vnd.oasis.opendocument.text-template" fullword wide
		 $s143= ".p12=application/x-pkcs12" fullword wide
		 $s144= ".p7b=application/x-pkcs7-certificates" fullword wide
		 $s145= ".p7m=application/pkcs7-mime" fullword wide
		 $s146= ".p7r=application/x-pkcs7-certreqresp" fullword wide
		 $s147= ".p7s=application/pkcs7-signature" fullword wide
		 $s148= ".package=application/vnd.autopackage" fullword wide
		 $s149= ".pbm=image/x-portable-bitmap" fullword wide
		 $s150= "PEM_write_bio_PKCS8PrivateKey" fullword wide
		 $s151= ".pfr=application/font-tdpfr" fullword wide
		 $s152= ".pgm=image/x-portable-graymap" fullword wide
		 $s153= ".pkg=vnd.apple.installer+xml" fullword wide
		 $s154= ".pko=application/vnd.ms-pki.pko" fullword wide
		 $s155= ".pnm=image/x-portable-anymap" fullword wide
		 $s156= ".pnq=application/x-icq-pnq" fullword wide
		 $s157= ".pot=application/mspowerpoint" fullword wide
		 $s158= ".ppm=image/x-portable-pixmap" fullword wide
		 $s159= ".pps=application/mspowerpoint" fullword wide
		 $s160= ".ppt=application/mspowerpoint" fullword wide
		 $s161= ".ppz=application/mspowerpoint" fullword wide
		 $s162= ".ps=application/postscript" fullword wide
		 $s163= ".pub=application/x-mspublisher" fullword wide
		 $s164= ".qpw=application/x-quattropro" fullword wide
		 $s165= ".qtl=application/x-quicktimeplayer" fullword wide
		 $s166= ".ram=audio/x-pn-realaudio" fullword wide
		 $s167= ".rf=image/vnd.rn-realflash" fullword wide
		 $s168= ".rjs=application/vnd.rn-realsystem-rjs" fullword wide
		 $s169= ".rm=application/vnd.rn-realmedia" fullword wide
		 $s170= ".rmp=application/vnd.rn-rn_music_package" fullword wide
		 $s171= ".rms=video/vnd.rn-realvideo-secure" fullword wide
		 $s172= ".rmx=application/vnd.rn-realsystem-rmx" fullword wide
		 $s173= ".rnx=application/vnd.rn-realplayer" fullword wide
		 $s174= ".rpm=application/x-redhat-package-manager" fullword wide
		 $s175= ".rsml=application/vnd.rn-rsml" fullword wide
		 $s176= ".rv=video/vnd.rn-realvideo" fullword wide
		 $s177= ".scd=application/x-msschedule" fullword wide
		 $s178= ".scm=application/x-icq-scm" fullword wide
		 $s179= ".sda=application/vnd.stardivision.draw" fullword wide
		 $s180= ".sdc=application/vnd.stardivision.calc" fullword wide
		 $s181= ".sdd=application/vnd.stardivision.impress" fullword wide
		 $s182= ".ser=application/java-serialized-object" fullword wide
		 $s183= ".setpay=application/set-payment-initiation" fullword wide
		 $s184= ".setreg=application/set-registration-initiation" fullword wide
		 $s185= ".shtml=server-parsed-html" fullword wide
		 $s186= ".shw=application/presentations" fullword wide
		 $s187= ".sit=application/x-stuffit" fullword wide
		 $s188= ".smf=application/vnd.stardivision.math" fullword wide
		 $s189= "SoftwareBorlandDelphiLocales" fullword wide
		 $s190= "SOFTWAREClassesFoldershellsandbox" fullword wide
		 $s191= "SoftwareCodeGearLocales" fullword wide
		 $s192= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s193= "SoftwareMicrosoftWindowsCurrentVersionRunOnce" fullword wide
		 $s194= "SOFTWAREMicrosoftWindowsCurrentVersionUninstallSandboxie" fullword wide
		 $s195= "SOFTWARESandboxieAutoExec" fullword wide
		 $s196= ".spl=application/futuresplash" fullword wide
		 $s197= "SSL_COMP_get_compression_methods" fullword wide
		 $s198= "SSL_CTX_check_private_key" fullword wide
		 $s199= "SSL_CTX_load_verify_locations" fullword wide
		 $s200= "SSL_CTX_set_client_CA_list" fullword wide
		 $s201= "SSL_CTX_set_default_passwd_cb" fullword wide
		 $s202= "SSL_CTX_set_default_passwd_cb_userdata" fullword wide
		 $s203= "SSL_CTX_set_default_verify_paths" fullword wide
		 $s204= "SSL_CTX_set_session_id_context" fullword wide
		 $s205= "SSL_CTX_use_certificate_file" fullword wide
		 $s206= "SSL_CTX_use_PrivateKey_file" fullword wide
		 $s207= ".ssm=application/streamingmedia" fullword wide
		 $s208= ".sst=application/vnd.ms-pki.certstore" fullword wide
		 $s209= ".stc=application/vnd.sun.xml.calc.template" fullword wide
		 $s210= ".std=application/vnd.sun.xml.draw.template" fullword wide
		 $s211= ".sti=application/vnd.sun.xml.impress.template" fullword wide
		 $s212= ".stl=application/vnd.ms-pki.stl" fullword wide
		 $s213= ".stw=application/vnd.sun.xml.writer.template" fullword wide
		 $s214= "SubjectAlgorithm.Parameters::" fullword wide
		 $s215= "SubjectPublicKeyInfo.PublicKey" fullword wide
		 $s216= ".sv4cpio=application/x-sv4cpio" fullword wide
		 $s217= ".sv4crc=application/x-sv4crc" fullword wide
		 $s218= ".svi=application/softvision" fullword wide
		 $s219= ".swf=application/x-shockwave-flash" fullword wide
		 $s220= ".sxc=application/vnd.sun.xml.calc" fullword wide
		 $s221= ".sxg=application/vnd.sun.xml.writer.global" fullword wide
		 $s222= ".sxi=application/vnd.sun.xml.impress" fullword wide
		 $s223= ".sxm=application/vnd.sun.xml.math" fullword wide
		 $s224= ".sxw=application/vnd.sun.xml.writer" fullword wide
		 $s225= "SYSTEMControlSet001ControlSystemInformation" fullword wide
		 $s226= "SYSTEMControlSet002EnumVMBUS" fullword wide
		 $s227= ".texi=application/x-texinfo" fullword wide
		 $s228= ".texinfo=application/x-texinfo" fullword wide
		 $s229= ".tgz=application/x-compressed" fullword wide
		 $s230= "Toolhelp32ReadProcessMemory" fullword wide
		 $s231= ".torrent=application/x-bittorrent" fullword wide
		 $s232= ".trm=application/x-msterminal" fullword wide
		 $s233= ".troff=application/x-troff" fullword wide
		 $s234= ".urls=application/x-url-list" fullword wide
		 $s235= ".ustar=application/x-ustar" fullword wide
		 $s236= ".vcd=application/x-cdlink" fullword wide
		 $s237= ".vor=application/vnd.stardivision.writer" fullword wide
		 $s238= ".vsl=application/x-cnet-vsl" fullword wide
		 $s239= ".wb1=application/x-quattropro" fullword wide
		 $s240= ".wb2=application/x-quattropro" fullword wide
		 $s241= ".wb3=application/x-quattropro" fullword wide
		 $s242= "W:_BASEupd3AdobeReader.exe" fullword wide
		 $s243= ".wcm=application/vnd.ms-works" fullword wide
		 $s244= ".wdb=application/vnd.ms-works" fullword wide
		 $s245= ".wks=application/vnd.ms-works" fullword wide
		 $s246= ".wmd=application/x-ms-wmd" fullword wide
		 $s247= ".wmlc=application/vnd.wap.wmlc" fullword wide
		 $s248= ".wmlsc=application/vnd.wap.wmlscriptc" fullword wide
		 $s249= ".wmls=text/vnd.wap.wmlscript" fullword wide
		 $s250= ".wms=application/x-ms-wms" fullword wide
		 $s251= ".wmz=application/x-ms-wmz" fullword wide
		 $s252= ".wp5=application/wordperfect5.1" fullword wide
		 $s253= ".wpd=application/wordperfect" fullword wide
		 $s254= ".wpl=application/vnd.ms-wpl" fullword wide
		 $s255= ".wps=application/vnd.ms-works" fullword wide
		 $s256= ".wri=application/x-mswrite" fullword wide
		 $s257= "WSADeleteSocketPeerTargetName" fullword wide
		 $s258= "WSAEnumNameSpaceProvidersA" fullword wide
		 $s259= "WSAEnumNameSpaceProvidersW" fullword wide
		 $s260= "WSAGetServiceClassNameByClassIdA" fullword wide
		 $s261= "WSAGetServiceClassNameByClassIdW" fullword wide
		 $s262= "WSASetSocketPeerTargetName" fullword wide
		 $s263= "W:_upd12AdobeReader.exe" fullword wide
		 $s264= "W:_upd16AdobeReader.exe" fullword wide
		 $s265= "W:_upd17AdobeReader.exe" fullword wide
		 $s266= "W:_upd3AdobeReader.exe" fullword wide
		 $s267= "W:_upd4AdobeReader.exe" fullword wide
		 $s268= "W:_upd5AdobeReader.exe" fullword wide
		 $s269= "W:_upd7AdobeReader.exe" fullword wide
		 $s270= "W:_upd9AdobeReader.exe" fullword wide
		 $s271= "X509_EXTENSION_create_by_NID" fullword wide
		 $s272= "X509_NAME_add_entry_by_txt" fullword wide
		 $s273= "X509_STORE_CTX_get_current_cert" fullword wide
		 $s274= "X509_STORE_CTX_get_error_depth" fullword wide
		 $s275= "X509_STORE_CTX_get_ex_data" fullword wide
		 $s276= ".xfdf=application/vnd.adobe.xfdf" fullword wide
		 $s277= ".xlb=application/x-msexcel" fullword wide
		 $s278= ".xls=application/x-msexcel" fullword wide
		 $s279= ".xpi=application/x-xpinstall" fullword wide
		 $s280= ".xps=application/vnd.ms-xpsdocument" fullword wide
		 $s281= ".xsd=application/vnd.sun.xml.draw" fullword wide
		 $s282= ".xul=application/vnd.mozilla.xul+xml" fullword wide
		 $s283= ".z=application/x-compress" fullword wide
		 $s284= ".zip=application/x-zip-compressed" fullword wide

		 $hex1= {24733130303d202249}
		 $hex2= {24733130313d20222e}
		 $hex3= {24733130323d20222e}
		 $hex4= {24733130333d20222e}
		 $hex5= {24733130343d20222e}
		 $hex6= {24733130353d20222e}
		 $hex7= {24733130363d20222e}
		 $hex8= {24733130373d20222e}
		 $hex9= {24733130383d20222e}
		 $hex10= {24733130393d20222e}
		 $hex11= {247331303d20222e61}
		 $hex12= {24733131303d20222e}
		 $hex13= {24733131313d20222e}
		 $hex14= {24733131323d20222e}
		 $hex15= {24733131333d20222e}
		 $hex16= {24733131343d20222e}
		 $hex17= {24733131353d20222e}
		 $hex18= {24733131363d20222e}
		 $hex19= {24733131373d20224d}
		 $hex20= {24733131383d20224d}
		 $hex21= {24733131393d20222e}
		 $hex22= {247331313d20222e62}
		 $hex23= {24733132303d20222e}
		 $hex24= {24733132313d20222e}
		 $hex25= {24733132323d20222e}
		 $hex26= {24733132333d20222e}
		 $hex27= {24733132343d20226d}
		 $hex28= {24733132353d20222e}
		 $hex29= {24733132363d20222e}
		 $hex30= {24733132373d20222e}
		 $hex31= {24733132383d20222e}
		 $hex32= {24733132393d20222e}
		 $hex33= {247331323d20222e62}
		 $hex34= {24733133303d20222e}
		 $hex35= {24733133313d20222e}
		 $hex36= {24733133323d20222e}
		 $hex37= {24733133333d20222e}
		 $hex38= {24733133343d20222e}
		 $hex39= {24733133353d20222e}
		 $hex40= {24733133363d20225f}
		 $hex41= {24733133373d20225f}
		 $hex42= {24733133383d20222e}
		 $hex43= {24733133393d20222e}
		 $hex44= {247331333d20222e63}
		 $hex45= {24733134303d20222e}
		 $hex46= {24733134313d20222e}
		 $hex47= {24733134323d20222e}
		 $hex48= {24733134333d20222e}
		 $hex49= {24733134343d20222e}
		 $hex50= {24733134353d20222e}
		 $hex51= {24733134363d20222e}
		 $hex52= {24733134373d20222e}
		 $hex53= {24733134383d20222e}
		 $hex54= {24733134393d20222e}
		 $hex55= {247331343d20222e63}
		 $hex56= {24733135303d202250}
		 $hex57= {24733135313d20222e}
		 $hex58= {24733135323d20222e}
		 $hex59= {24733135333d20222e}
		 $hex60= {24733135343d20222e}
		 $hex61= {24733135353d20222e}
		 $hex62= {24733135363d20222e}
		 $hex63= {24733135373d20222e}
		 $hex64= {24733135383d20222e}
		 $hex65= {24733135393d20222e}
		 $hex66= {247331353d2022433a}
		 $hex67= {24733136303d20222e}
		 $hex68= {24733136313d20222e}
		 $hex69= {24733136323d20222e}
		 $hex70= {24733136333d20222e}
		 $hex71= {24733136343d20222e}
		 $hex72= {24733136353d20222e}
		 $hex73= {24733136363d20222e}
		 $hex74= {24733136373d20222e}
		 $hex75= {24733136383d20222e}
		 $hex76= {24733136393d20222e}
		 $hex77= {247331363d2022433a}
		 $hex78= {24733137303d20222e}
		 $hex79= {24733137313d20222e}
		 $hex80= {24733137323d20222e}
		 $hex81= {24733137333d20222e}
		 $hex82= {24733137343d20222e}
		 $hex83= {24733137353d20222e}
		 $hex84= {24733137363d20222e}
		 $hex85= {24733137373d20222e}
		 $hex86= {24733137383d20222e}
		 $hex87= {24733137393d20222e}
		 $hex88= {247331373d2022433a}
		 $hex89= {24733138303d20222e}
		 $hex90= {24733138313d20222e}
		 $hex91= {24733138323d20222e}
		 $hex92= {24733138333d20222e}
		 $hex93= {24733138343d20222e}
		 $hex94= {24733138353d20222e}
		 $hex95= {24733138363d20222e}
		 $hex96= {24733138373d20222e}
		 $hex97= {24733138383d20222e}
		 $hex98= {24733138393d202253}
		 $hex99= {247331383d2022433a}
		 $hex100= {24733139303d202253}
		 $hex101= {24733139313d202253}
		 $hex102= {24733139323d202253}
		 $hex103= {24733139333d202253}
		 $hex104= {24733139343d202253}
		 $hex105= {24733139353d202253}
		 $hex106= {24733139363d20222e}
		 $hex107= {24733139373d202253}
		 $hex108= {24733139383d202253}
		 $hex109= {24733139393d202253}
		 $hex110= {247331393d2022433a}
		 $hex111= {2473313d20227b2530}
		 $hex112= {24733230303d202253}
		 $hex113= {24733230313d202253}
		 $hex114= {24733230323d202253}
		 $hex115= {24733230333d202253}
		 $hex116= {24733230343d202253}
		 $hex117= {24733230353d202253}
		 $hex118= {24733230363d202253}
		 $hex119= {24733230373d20222e}
		 $hex120= {24733230383d20222e}
		 $hex121= {24733230393d20222e}
		 $hex122= {247332303d2022433a}
		 $hex123= {24733231303d20222e}
		 $hex124= {24733231313d20222e}
		 $hex125= {24733231323d20222e}
		 $hex126= {24733231333d20222e}
		 $hex127= {24733231343d202253}
		 $hex128= {24733231353d202253}
		 $hex129= {24733231363d20222e}
		 $hex130= {24733231373d20222e}
		 $hex131= {24733231383d20222e}
		 $hex132= {24733231393d20222e}
		 $hex133= {247332313d2022433a}
		 $hex134= {24733232303d20222e}
		 $hex135= {24733232313d20222e}
		 $hex136= {24733232323d20222e}
		 $hex137= {24733232333d20222e}
		 $hex138= {24733232343d20222e}
		 $hex139= {24733232353d202253}
		 $hex140= {24733232363d202253}
		 $hex141= {24733232373d20222e}
		 $hex142= {24733232383d20222e}
		 $hex143= {24733232393d20222e}
		 $hex144= {247332323d2022433a}
		 $hex145= {24733233303d202254}
		 $hex146= {24733233313d20222e}
		 $hex147= {24733233323d20222e}
		 $hex148= {24733233333d20222e}
		 $hex149= {24733233343d20222e}
		 $hex150= {24733233353d20222e}
		 $hex151= {24733233363d20222e}
		 $hex152= {24733233373d20222e}
		 $hex153= {24733233383d20222e}
		 $hex154= {24733233393d20222e}
		 $hex155= {247332333d2022433a}
		 $hex156= {24733234303d20222e}
		 $hex157= {24733234313d20222e}
		 $hex158= {24733234323d202257}
		 $hex159= {24733234333d20222e}
		 $hex160= {24733234343d20222e}
		 $hex161= {24733234353d20222e}
		 $hex162= {24733234363d20222e}
		 $hex163= {24733234373d20222e}
		 $hex164= {24733234383d20222e}
		 $hex165= {24733234393d20222e}
		 $hex166= {247332343d2022433a}
		 $hex167= {24733235303d20222e}
		 $hex168= {24733235313d20222e}
		 $hex169= {24733235323d20222e}
		 $hex170= {24733235333d20222e}
		 $hex171= {24733235343d20222e}
		 $hex172= {24733235353d20222e}
		 $hex173= {24733235363d20222e}
		 $hex174= {24733235373d202257}
		 $hex175= {24733235383d202257}
		 $hex176= {24733235393d202257}
		 $hex177= {247332353d2022433a}
		 $hex178= {24733236303d202257}
		 $hex179= {24733236313d202257}
		 $hex180= {24733236323d202257}
		 $hex181= {24733236333d202257}
		 $hex182= {24733236343d202257}
		 $hex183= {24733236353d202257}
		 $hex184= {24733236363d202257}
		 $hex185= {24733236373d202257}
		 $hex186= {24733236383d202257}
		 $hex187= {24733236393d202257}
		 $hex188= {247332363d2022433a}
		 $hex189= {24733237303d202257}
		 $hex190= {24733237313d202258}
		 $hex191= {24733237323d202258}
		 $hex192= {24733237333d202258}
		 $hex193= {24733237343d202258}
		 $hex194= {24733237353d202258}
		 $hex195= {24733237363d20222e}
		 $hex196= {24733237373d20222e}
		 $hex197= {24733237383d20222e}
		 $hex198= {24733237393d20222e}
		 $hex199= {247332373d2022433a}
		 $hex200= {24733238303d20222e}
		 $hex201= {24733238313d20222e}
		 $hex202= {24733238323d20222e}
		 $hex203= {24733238333d20222e}
		 $hex204= {24733238343d20222e}
		 $hex205= {247332383d2022433a}
		 $hex206= {247332393d2022433a}
		 $hex207= {2473323d2022362e31}
		 $hex208= {247333303d20222e63}
		 $hex209= {247333313d20224345}
		 $hex210= {247333323d20222e63}
		 $hex211= {247333333d20222e63}
		 $hex212= {247333343d20222e63}
		 $hex213= {247333353d20222e63}
		 $hex214= {247333363d20222e63}
		 $hex215= {247333373d20222e63}
		 $hex216= {247333383d2022436f}
		 $hex217= {247333393d2022436f}
		 $hex218= {2473333d20222e6161}
		 $hex219= {247334303d20222e63}
		 $hex220= {247334313d20222e63}
		 $hex221= {247334323d20222e63}
		 $hex222= {247334333d20222e63}
		 $hex223= {247334343d20224352}
		 $hex224= {247334353d20224352}
		 $hex225= {247334363d20224352}
		 $hex226= {247334373d20226373}
		 $hex227= {247334383d2022433a}
		 $hex228= {247334393d2022433a}
		 $hex229= {2473343d20222e6161}
		 $hex230= {247335303d20222e64}
		 $hex231= {247335313d20222e64}
		 $hex232= {247335323d20222e64}
		 $hex233= {247335333d20224469}
		 $hex234= {247335343d20222e64}
		 $hex235= {247335353d20222e64}
		 $hex236= {247335363d20222e64}
		 $hex237= {247335373d20222e64}
		 $hex238= {247335383d2022446f}
		 $hex239= {247335393d20222e64}
		 $hex240= {2473353d20222e6161}
		 $hex241= {247336303d20226562}
		 $hex242= {247336313d20222e65}
		 $hex243= {247336323d2022456e}
		 $hex244= {247336333d20222e65}
		 $hex245= {247336343d20222e65}
		 $hex246= {247336353d20224578}
		 $hex247= {247336363d20224578}
		 $hex248= {247336373d20222e66}
		 $hex249= {247336383d20222e66}
		 $hex250= {247336393d20222e66}
		 $hex251= {2473363d20222e6162}
		 $hex252= {247337303d20222e67}
		 $hex253= {247337313d20224841}
		 $hex254= {247337323d20224841}
		 $hex255= {247337333d20224841}
		 $hex256= {247337343d20224841}
		 $hex257= {247337353d20224841}
		 $hex258= {247337363d20224841}
		 $hex259= {247337373d20224841}
		 $hex260= {247337383d20224841}
		 $hex261= {247337393d20224861}
		 $hex262= {2473373d20222e6169}
		 $hex263= {247338303d20222e68}
		 $hex264= {247338313d20222e68}
		 $hex265= {247338323d20226874}
		 $hex266= {247338333d20226874}
		 $hex267= {247338343d20226874}
		 $hex268= {247338353d20226874}
		 $hex269= {247338363d20226874}
		 $hex270= {247338373d20226874}
		 $hex271= {247338383d20226874}
		 $hex272= {247338393d20226874}
		 $hex273= {2473383d2022617070}
		 $hex274= {247339303d20226874}
		 $hex275= {247339313d20224859}
		 $hex276= {247339323d20224859}
		 $hex277= {247339333d20222e69}
		 $hex278= {247339343d20222e69}
		 $hex279= {247339353d2022496e}
		 $hex280= {247339363d20222e69}
		 $hex281= {247339373d20224953}
		 $hex282= {247339383d20224953}
		 $hex283= {247339393d20224953}
		 $hex284= {2473393d20222e6173}

	condition:
		189 of them
}
