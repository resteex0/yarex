
/*
   YARA Rule Set
   Author: resteex
   Identifier: Bizarro 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Bizarro {
	meta: 
		 description= "Bizarro Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_23-03-31" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0403d605e6418cbdf8e946736d1497ad"
		 hash2= "38003677bfaa1c6729f7fa00da5c9109"
		 hash3= "5184776f72962859b704f7cc370460ea"
		 hash4= "73472698fe41df730682977c8e751a3e"
		 hash5= "7a1ce2f8f714367f92a31da1519a3de3"
		 hash6= "a083d5ff976347f1cd5ba1d9e3a7a4b3"
		 hash7= "b0d0990beefa11c9a78c701e2aa46f87"
		 hash8= "d6e4236aaade8c90366966d59e735568"
		 hash9= "daf028ddae0edbd3d7946bb26cf05fbf"
		 hash10= "e6c337d504b2d7d80d706899d964ab45"

	strings:

	
 		 $s1= "0x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x" fullword wide
		 $s2= "{43826D1E-E718-42EE-BC55-A1E261C37BFE}" fullword wide
		 $s3= ".7z=application/x-7z-compressed" fullword wide
		 $s4= ".aab=application/x-authorware-bin" fullword wide
		 $s5= ".aam=application/x-authorware-map" fullword wide
		 $s6= ".aas=application/x-authorware-seg" fullword wide
		 $s7= ".abw=application/x-abiword" fullword wide
		 $s8= ".ace=application/x-ace-compressed" fullword wide
		 $s9= "AcquireCredentialsHandleW" fullword wide
		 $s10= ".ai=application/postscript" fullword wide
		 $s11= ".alz=application/x-alz-compressed" fullword wide
		 $s12= ".ani=application/x-navi-animation" fullword wide
		 $s13= "application/xml-external-parsed-entity" fullword wide
		 $s14= ".asf=application/vnd.ms-asf" fullword wide
		 $s15= ".asx=video/x-ms-asf-plugin" fullword wide
		 $s16= ".bat=application/x-msdos-program" fullword wide
		 $s17= ".bcpio=application/x-bcpio" fullword wide
		 $s18= ".cab=application/vnd.ms-cab-compressed" fullword wide
		 $s19= ".cat=application/vnd.ms-pki.seccat" fullword wide
		 $s20= ".cdt=image/x-coreldrawtemplate" fullword wide
		 $s21= ".cer=application/x-x509-ca-cert" fullword wide
		 $s22= ".chm=application/vnd.ms-htmlhelp" fullword wide
		 $s23= ".chrt=application/vnd.kde.kchart" fullword wide
		 $s24= ".cil=application/vnd.ms-artgalry" fullword wide
		 $s25= ".class=application/java-vm" fullword wide
		 $s26= "clGradientInactiveCaption" fullword wide
		 $s27= ".clp=application/x-msclip" fullword wide
		 $s28= ".com=application/x-msdos-program" fullword wide
		 $s29= "Content-Transfer-Encoding: %s" fullword wide
		 $s30= ".cpt=application/mac-compactpro" fullword wide
		 $s31= ".cpt=image/x-corelphotopaint" fullword wide
		 $s32= ".cqk=application/x-calquick" fullword wide
		 $s33= ".crd=application/x-mscardfile" fullword wide
		 $s34= ".crl=application/pkix-crl" fullword wide
		 $s35= "CRYPTO_cleanup_all_ex_data" fullword wide
		 $s36= "CRYPTO_set_locking_callback" fullword wide
		 $s37= "CRYPTO_set_mem_debug_functions" fullword wide
		 $s38= "csISO95JIS62291984handadd" fullword wide
		 $s39= "CurrentMajorVersionNumber" fullword wide
		 $s40= "CurrentMinorVersionNumber" fullword wide
		 $s41= ".dcr=application/x-director" fullword wide
		 $s42= ".deb=application/x-debian-package" fullword wide
		 $s43= "DelphiRM_GetObjectInstance" fullword wide
		 $s44= ".dir=application/x-director" fullword wide
		 $s45= ".dist=vnd.apple.installer+xml" fullword wide
		 $s46= ".distz=vnd.apple.installer+xml" fullword wide
		 $s47= ".dll=application/x-msdos-program" fullword wide
		 $s48= ".dmg=application/x-apple-diskimage" fullword wide
		 $s49= "DownlevelGetLocaleScripts" fullword wide
		 $s50= "DownlevelGetStringScripts" fullword wide
		 $s51= "DrawThemeParentBackground" fullword wide
		 $s52= ".dxr=application/x-director" fullword wide
		 $s53= "ebcdic-international-500+euro" fullword wide
		 $s54= ".ebk=application/x-expandedbook" fullword wide
		 $s55= "EnableNonClientDpiScaling" fullword wide
		 $s56= ".eps=application/postscript" fullword wide
		 $s57= "EVP_CIPHER_CTX_block_size" fullword wide
		 $s58= "EVP_CIPHER_CTX_get_app_data" fullword wide
		 $s59= "EVP_CIPHER_CTX_key_length" fullword wide
		 $s60= "EVP_CIPHER_CTX_set_app_data" fullword wide
		 $s61= "EVP_CIPHER_CTX_set_key_length" fullword wide
		 $s62= "EVP_PKEY_asn1_set_private" fullword wide
		 $s63= "EVP_PKEY_CTX_get0_peerkey" fullword wide
		 $s64= "EVP_PKEY_CTX_get_app_data" fullword wide
		 $s65= "EVP_PKEY_CTX_get_keygen_info" fullword wide
		 $s66= "EVP_PKEY_CTX_get_operation" fullword wide
		 $s67= "EVP_PKEY_CTX_set0_keygen_info" fullword wide
		 $s68= "EVP_PKEY_CTX_set_app_data" fullword wide
		 $s69= "EVP_PKEY_get_default_digest_nid" fullword wide
		 $s70= "EVP_PKEY_meth_set_cleanup" fullword wide
		 $s71= "EVP_PKEY_meth_set_decrypt" fullword wide
		 $s72= "EVP_PKEY_meth_set_encrypt" fullword wide
		 $s73= "EVP_PKEY_meth_set_paramgen" fullword wide
		 $s74= "EVP_PKEY_meth_set_signctx" fullword wide
		 $s75= "EVP_PKEY_meth_set_verifyctx" fullword wide
		 $s76= "EVP_PKEY_meth_set_verify_recover" fullword wide
		 $s77= "EVP_PKEY_missing_parameters" fullword wide
		 $s78= "EVP_PKEY_verify_recover_init" fullword wide
		 $s79= ".exe=application/x-msdos-program" fullword wide
		 $s80= "Extended_UNIX_Code_Fixed_Width_for_Japanese" fullword wide
		 $s81= "Extended_UNIX_Code_Packed_Format_for_Japanese" fullword wide
		 $s82= ".fif=application/fractals" fullword wide
		 $s83= ".flm=application/vnd.kde.kivio" fullword wide
		 $s84= ".fml=application/x-file-mirror-list" fullword wide
		 $s85= "GetThemeBackgroundContentRect" fullword wide
		 $s86= "GetThemeDocumentationProperty" fullword wide
		 $s87= "GetUniDirectionalAdapterInfo" fullword wide
		 $s88= ".gnumeric=application/x-gnumeric" fullword wide
		 $s89= ".hpf=application/x-icq-hpf" fullword wide
		 $s90= ".hqx=application/mac-binhex40" fullword wide
		 $s91= "http://www.indyproject.org/" fullword wide
		 $s92= "i2d_NETSCAPE_CERT_SEQUENCE" fullword wide
		 $s93= ".iii=application/x-iphone" fullword wide
		 $s94= ".ims=application/vnd.ms-ims" fullword wide
		 $s95= "InitializeConditionVariable" fullword wide
		 $s96= "InitializeProcessForWsWatch" fullword wide
		 $s97= "InitializeSecurityContextW" fullword wide
		 $s98= ".ins=application/x-internet-signup" fullword wide
		 $s99= "ISO-8859-1-Windows-3.0-Latin-1" fullword wide
		 $s100= "ISO-8859-1-Windows-3.1-Latin-1" fullword wide
		 $s101= "ISO-8859-2-Windows-Latin-2" fullword wide
		 $s102= "ISO-8859-9-Windows-Latin-5" fullword wide
		 $s103= ".iso=application/x-iso9660-image" fullword wide
		 $s104= "IsThemeBackgroundPartiallyTransparent" fullword wide
		 $s105= "IsThemeDialogTextureEnabled" fullword wide
		 $s106= ".jar=application/java-archive" fullword wide
		 $s107= ".karbon=application/vnd.kde.karbon" fullword wide
		 $s108= ".kfo=application/vnd.kde.kformula" fullword wide
		 $s109= ".kon=application/vnd.kde.kontour" fullword wide
		 $s110= ".kpr=application/vnd.kde.kpresenter" fullword wide
		 $s111= ".kpt=application/vnd.kde.kpresenter" fullword wide
		 $s112= ".kwd=application/vnd.kde.kword" fullword wide
		 $s113= ".kwt=application/vnd.kde.kword" fullword wide
		 $s114= ".latex=application/x-latex" fullword wide
		 $s115= ".lrm=application/vnd.ms-lrm" fullword wide
		 $s116= ".m13=application/x-msmediaview" fullword wide
		 $s117= ".m14=application/x-msmediaview" fullword wide
		 $s118= "MagSetImageScalingCallback" fullword wide
		 $s119= ".man=application/x-troff-man" fullword wide
		 $s120= ".mdb=application/x-msaccess" fullword wide
		 $s121= ".me=application/x-troff-me" fullword wide
		 $s122= "MIMEDatabaseContent Type" fullword wide
		 $s123= "MIMEDatabaseContent Type" fullword wide
		 $s124= ".mjf=audio/x-vnd.AudioExplosion.MjuiceMediaFile" fullword wide
		 $s125= ".mny=application/x-msmoney" fullword wide
		 $s126= ".mpkg=vnd.apple.installer+xml" fullword wide
		 $s127= ".mpp=application/vnd.ms-project" fullword wide
		 $s128= ".ms=application/x-troff-ms" fullword wide
		 $s129= "multipart/form-data; boundary=" fullword wide
		 $s130= ".mvb=application/x-msmediaview" fullword wide
		 $s131= ".nix=application/x-mix-transfer" fullword wide
		 $s132= ".odb=application/vnd.oasis.opendocument.database" fullword wide
		 $s133= ".odc=application/vnd.oasis.opendocument.chart" fullword wide
		 $s134= ".odf=application/vnd.oasis.opendocument.formula" fullword wide
		 $s135= ".odg=application/vnd.oasis.opendocument.graphics" fullword wide
		 $s136= ".odi=application/vnd.oasis.opendocument.image" fullword wide
		 $s137= ".odm=application/vnd.oasis.opendocument.text-master" fullword wide
		 $s138= ".odp=application/vnd.oasis.opendocument.presentation" fullword wide
		 $s139= ".ods=application/vnd.oasis.opendocument.spreadsheet" fullword wide
		 $s140= ".odt=application/vnd.oasis.opendocument.text" fullword wide
		 $s141= "OpenSSL_add_all_algorithms" fullword wide
		 $s142= "OPENSSL_add_all_algorithms_noconf" fullword wide
		 $s143= "_ossl_old_des_ecb_encrypt" fullword wide
		 $s144= "_ossl_old_des_set_odd_parity" fullword wide
		 $s145= ".otg=application/vnd.oasis.opendocument.graphics-template" fullword wide
		 $s146= ".oth=application/vnd.oasis.opendocument.text-web" fullword wide
		 $s147= ".otp=application/vnd.oasis.opendocument.presentation-template" fullword wide
		 $s148= ".ots=application/vnd.oasis.opendocument.spreadsheet-template" fullword wide
		 $s149= ".ott=application/vnd.oasis.opendocument.text-template" fullword wide
		 $s150= ".p12=application/x-pkcs12" fullword wide
		 $s151= ".p7b=application/x-pkcs7-certificates" fullword wide
		 $s152= ".p7m=application/pkcs7-mime" fullword wide
		 $s153= ".p7r=application/x-pkcs7-certreqresp" fullword wide
		 $s154= ".p7s=application/pkcs7-signature" fullword wide
		 $s155= ".package=application/vnd.autopackage" fullword wide
		 $s156= ".pat=image/x-coreldrawpattern" fullword wide
		 $s157= ".pbm=image/x-portable-bitmap" fullword wide
		 $s158= "PEM_read_bio_DSAPrivateKey" fullword wide
		 $s159= "PEM_read_bio_NETSCAPE_CERT_SEQUENCE" fullword wide
		 $s160= "PEM_read_bio_RSAPrivateKey" fullword wide
		 $s161= "PEM_read_bio_RSAPublicKey" fullword wide
		 $s162= "PEM_write_bio_DSAPrivateKey" fullword wide
		 $s163= "PEM_write_bio_NETSCAPE_CERT_SEQUENCE" fullword wide
		 $s164= "PEM_write_bio_PKCS8PrivateKey" fullword wide
		 $s165= "PEM_write_bio_RSAPrivateKey" fullword wide
		 $s166= "PEM_write_bio_RSAPublicKey" fullword wide
		 $s167= ".pfr=application/font-tdpfr" fullword wide
		 $s168= ".pgm=image/x-portable-graymap" fullword wide
		 $s169= ".pkg=vnd.apple.installer+xml" fullword wide
		 $s170= ".pko=application/vnd.ms-pki.pko" fullword wide
		 $s171= ".pnm=image/x-portable-anymap" fullword wide
		 $s172= ".pnq=application/x-icq-pnq" fullword wide
		 $s173= ".pot=application/mspowerpoint" fullword wide
		 $s174= ".ppm=image/x-portable-pixmap" fullword wide
		 $s175= ".pps=application/mspowerpoint" fullword wide
		 $s176= ".ppt=application/mspowerpoint" fullword wide
		 $s177= ".ppz=application/mspowerpoint" fullword wide
		 $s178= ".ps=application/postscript" fullword wide
		 $s179= ".pub=application/x-mspublisher" fullword wide
		 $s180= ".qpw=application/x-quattropro" fullword wide
		 $s181= ".qtl=application/x-quicktimeplayer" fullword wide
		 $s182= "QuerySecurityPackageInfoW" fullword wide
		 $s183= ".ram=audio/x-pn-realaudio" fullword wide
		 $s184= ".rf=image/vnd.rn-realflash" fullword wide
		 $s185= ".rjs=application/vnd.rn-realsystem-rjs" fullword wide
		 $s186= ".rm=application/vnd.rn-realmedia" fullword wide
		 $s187= ".rmp=application/vnd.rn-rn_music_package" fullword wide
		 $s188= ".rms=video/vnd.rn-realvideo-secure" fullword wide
		 $s189= ".rmx=application/vnd.rn-realsystem-rmx" fullword wide
		 $s190= ".rnx=application/vnd.rn-realplayer" fullword wide
		 $s191= ".rpm=application/x-redhat-package-manager" fullword wide
		 $s192= ".rsml=application/vnd.rn-rsml" fullword wide
		 $s193= ".rv=video/vnd.rn-realvideo" fullword wide
		 $s194= ".scd=application/x-msschedule" fullword wide
		 $s195= ".scm=application/x-icq-scm" fullword wide
		 $s196= ".sda=application/vnd.stardivision.draw" fullword wide
		 $s197= ".sdc=application/vnd.stardivision.calc" fullword wide
		 $s198= ".sdd=application/vnd.stardivision.impress" fullword wide
		 $s199= ".ser=application/java-serialized-object" fullword wide
		 $s200= "SetLayeredWindowAttributes" fullword wide
		 $s201= ".setpay=application/set-payment-initiation" fullword wide
		 $s202= ".setreg=application/set-registration-initiation" fullword wide
		 $s203= ".shtml=server-parsed-html" fullword wide
		 $s204= ".shw=application/presentations" fullword wide
		 $s205= ".sit=application/x-stuffit" fullword wide
		 $s206= ".sitx=application/x-stuffitx" fullword wide
		 $s207= ".smf=application/vnd.stardivision.math" fullword wide
		 $s208= "SoftwareBorlandDelphiLocales" fullword wide
		 $s209= "SoftwareCodeGearLocales" fullword wide
		 $s210= "SoftwareEmbarcaderoLocales" fullword wide
		 $s211= "SOFTWAREMicrosoftWindows NTCurrentVersion" fullword wide
		 $s212= "SOFTWAREMicrosoftWindows NTCurrentVersionFontSubstitutes" fullword wide
		 $s213= ".spl=application/futuresplash" fullword wide
		 $s214= "sqlite3_bind_parameter_index" fullword wide
		 $s215= "SSL_alert_desc_string_long" fullword wide
		 $s216= "SSL_alert_type_string_long" fullword wide
		 $s217= "SSL_COMP_get_compression_methods" fullword wide
		 $s218= "SSL_CTX_check_private_key" fullword wide
		 $s219= "SSL_CTX_load_verify_locations" fullword wide
		 $s220= "SSL_CTX_set_client_CA_list" fullword wide
		 $s221= "SSL_CTX_set_default_passwd_cb" fullword wide
		 $s222= "SSL_CTX_set_default_passwd_cb_userdata" fullword wide
		 $s223= "SSL_CTX_set_default_verify_paths" fullword wide
		 $s224= "SSL_CTX_set_session_id_context" fullword wide
		 $s225= "SSL_CTX_use_certificate_chain_file" fullword wide
		 $s226= "SSL_CTX_use_certificate_file" fullword wide
		 $s227= "SSL_CTX_use_PrivateKey_file" fullword wide
		 $s228= ".ssm=application/streamingmedia" fullword wide
		 $s229= ".sst=application/vnd.ms-pki.certstore" fullword wide
		 $s230= ".stc=application/vnd.sun.xml.calc.template" fullword wide
		 $s231= ".std=application/vnd.sun.xml.draw.template" fullword wide
		 $s232= ".sti=application/vnd.sun.xml.impress.template" fullword wide
		 $s233= ".stl=application/vnd.ms-pki.stl" fullword wide
		 $s234= ".stw=application/vnd.sun.xml.writer.template" fullword wide
		 $s235= ".sv4cpio=application/x-sv4cpio" fullword wide
		 $s236= ".sv4crc=application/x-sv4crc" fullword wide
		 $s237= ".svi=application/softvision" fullword wide
		 $s238= ".swf1=application/x-shockwave-flash" fullword wide
		 $s239= ".swf=application/x-shockwave-flash" fullword wide
		 $s240= ".sxc=application/vnd.sun.xml.calc" fullword wide
		 $s241= ".sxg=application/vnd.sun.xml.writer.global" fullword wide
		 $s242= ".sxi=application/vnd.sun.xml.impress" fullword wide
		 $s243= ".sxm=application/vnd.sun.xml.math" fullword wide
		 $s244= ".sxw=application/vnd.sun.xml.writer" fullword wide
		 $s245= "SYSTEMCurrentControlSetControlKeyboard Layouts" fullword wide
		 $s246= "SystemCurrentControlSetControlKeyboard Layouts%.8x" fullword wide
		 $s247= ".tbz2=application/x-bzip-compressed-tar" fullword wide
		 $s248= ".tbz=application/x-bzip-compressed-tar" fullword wide
		 $s249= ".texi=application/x-texinfo" fullword wide
		 $s250= ".texinfo=application/x-texinfo" fullword wide
		 $s251= "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" fullword wide
		 $s252= ".tgz=application/x-compressed-tar" fullword wide
		 $s253= ".tlz=application/x-lzma-compressed-tar" fullword wide
		 $s254= "Toolhelp32ReadProcessMemory" fullword wide
		 $s255= ".torrent=application/x-bittorrent" fullword wide
		 $s256= ".trm=application/x-msterminal" fullword wide
		 $s257= ".troff=application/x-troff" fullword wide
		 $s258= ".txz=application/x-xz-compressed-tar" fullword wide
		 $s259= ".udeb=application/x-debian-package" fullword wide
		 $s260= ".urls=application/x-url-list" fullword wide
		 $s261= ".ustar=application/x-ustar" fullword wide
		 $s262= ".vcd=application/x-cdlink" fullword wide
		 $s263= ".vor=application/vnd.stardivision.writer" fullword wide
		 $s264= ".vsl=application/x-cnet-vsl" fullword wide
		 $s265= ".wb1=application/x-quattropro" fullword wide
		 $s266= ".wb2=application/x-quattropro" fullword wide
		 $s267= ".wb3=application/x-quattropro" fullword wide
		 $s268= ".wcm=application/vnd.ms-works" fullword wide
		 $s269= ".wdb=application/vnd.ms-works" fullword wide
		 $s270= ".wks=application/vnd.ms-works" fullword wide
		 $s271= ".wmd=application/x-ms-wmd" fullword wide
		 $s272= ".wmlc=application/vnd.wap.wmlc" fullword wide
		 $s273= ".wmlsc=application/vnd.wap.wmlscriptc" fullword wide
		 $s274= ".wmls=text/vnd.wap.wmlscript" fullword wide
		 $s275= ".wms=application/x-ms-wms" fullword wide
		 $s276= ".wmz=application/x-ms-wmz" fullword wide
		 $s277= ".wp5=application/wordperfect5.1" fullword wide
		 $s278= ".wpd=application/wordperfect" fullword wide
		 $s279= ".wpl=application/vnd.ms-wpl" fullword wide
		 $s280= ".wps=application/vnd.ms-works" fullword wide
		 $s281= ".wri=application/x-mswrite" fullword wide
		 $s282= "WSADeleteSocketPeerTargetName" fullword wide
		 $s283= "WSAEnumNameSpaceProvidersA" fullword wide
		 $s284= "WSAEnumNameSpaceProvidersW" fullword wide
		 $s285= "WSAGetServiceClassNameByClassIdA" fullword wide
		 $s286= "WSAGetServiceClassNameByClassIdW" fullword wide
		 $s287= "WSASetSocketPeerTargetName" fullword wide
		 $s288= "X509_EXTENSION_create_by_NID" fullword wide
		 $s289= "X509_get_default_cert_file" fullword wide
		 $s290= "X509_get_default_cert_file_env" fullword wide
		 $s291= "X509_NAME_add_entry_by_txt" fullword wide
		 $s292= "X509_STORE_CTX_get_current_cert" fullword wide
		 $s293= "X509_STORE_CTX_get_error_depth" fullword wide
		 $s294= "X509_STORE_CTX_get_ex_data" fullword wide
		 $s295= "X509_STORE_load_locations" fullword wide
		 $s296= "x-EBCDIC-CyrillicSerbianBulgarian" fullword wide
		 $s297= "x-ebcdic-denmarknorway-euro" fullword wide
		 $s298= "x-ebcdic-finlandsweden-euro" fullword wide
		 $s299= "x-ebcdic-international-euro" fullword wide
		 $s300= "x-EBCDIC-JapaneseAndJapaneseLatin" fullword wide
		 $s301= "x-EBCDIC-JapaneseAndUSCanada" fullword wide
		 $s302= "x-EBCDIC-JapaneseKatakana" fullword wide
		 $s303= "x-EBCDIC-KoreanAndKoreanExtended" fullword wide
		 $s304= "x-EBCDIC-SimplifiedChinese" fullword wide
		 $s305= "x-EBCDIC-TraditionalChinese" fullword wide
		 $s306= ".xfdf=application/vnd.adobe.xfdf" fullword wide
		 $s307= ".xht=application/xhtml+xml" fullword wide
		 $s308= ".xhtml=application/xhtml+xml" fullword wide
		 $s309= ".xlb=application/x-msexcel" fullword wide
		 $s310= ".xls=application/x-msexcel" fullword wide
		 $s311= "xml-external-parsed-entity" fullword wide
		 $s312= ".xpi=application/x-xpinstall" fullword wide
		 $s313= ".xps=application/vnd.ms-xpsdocument" fullword wide
		 $s314= ".xsd=application/vnd.sun.xml.draw" fullword wide
		 $s315= ".xul=application/vnd.mozilla.xul+xml" fullword wide
		 $s316= ".z=application/x-compress" fullword wide
		 $s317= ".zip=application/x-zip-compressed" fullword wide
		 $a1= ".odm=application/vnd.oasis.opendocument.text-master" fullword ascii
		 $a2= ".odp=application/vnd.oasis.opendocument.presentation" fullword ascii
		 $a3= ".ods=application/vnd.oasis.opendocument.spreadsheet" fullword ascii
		 $a4= ".otg=application/vnd.oasis.opendocument.graphics-template" fullword ascii
		 $a5= ".otp=application/vnd.oasis.opendocument.presentation-template" fullword ascii
		 $a6= ".ots=application/vnd.oasis.opendocument.spreadsheet-template" fullword ascii
		 $a7= ".ott=application/vnd.oasis.opendocument.text-template" fullword ascii
		 $a8= "SOFTWAREMicrosoftWindows NTCurrentVersionFontSubstitutes" fullword ascii
		 $a9= "SYSTEMCurrentControlSetControlKeyboard Layouts" fullword ascii
		 $a10= "SystemCurrentControlSetControlKeyboard Layouts%.8x" fullword ascii
		 $a11= "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" fullword ascii

		 $hex1= {246131303d20225379}
		 $hex2= {246131313d20227465}
		 $hex3= {2461313d20222e6f64}
		 $hex4= {2461323d20222e6f64}
		 $hex5= {2461333d20222e6f64}
		 $hex6= {2461343d20222e6f74}
		 $hex7= {2461353d20222e6f74}
		 $hex8= {2461363d20222e6f74}
		 $hex9= {2461373d20222e6f74}
		 $hex10= {2461383d2022534f46}
		 $hex11= {2461393d2022535953}
		 $hex12= {24733130303d202249}
		 $hex13= {24733130313d202249}
		 $hex14= {24733130323d202249}
		 $hex15= {24733130333d20222e}
		 $hex16= {24733130343d202249}
		 $hex17= {24733130353d202249}
		 $hex18= {24733130363d20222e}
		 $hex19= {24733130373d20222e}
		 $hex20= {24733130383d20222e}
		 $hex21= {24733130393d20222e}
		 $hex22= {247331303d20222e61}
		 $hex23= {24733131303d20222e}
		 $hex24= {24733131313d20222e}
		 $hex25= {24733131323d20222e}
		 $hex26= {24733131333d20222e}
		 $hex27= {24733131343d20222e}
		 $hex28= {24733131353d20222e}
		 $hex29= {24733131363d20222e}
		 $hex30= {24733131373d20222e}
		 $hex31= {24733131383d20224d}
		 $hex32= {24733131393d20222e}
		 $hex33= {247331313d20222e61}
		 $hex34= {24733132303d20222e}
		 $hex35= {24733132313d20222e}
		 $hex36= {24733132323d20224d}
		 $hex37= {24733132333d20224d}
		 $hex38= {24733132343d20222e}
		 $hex39= {24733132353d20222e}
		 $hex40= {24733132363d20222e}
		 $hex41= {24733132373d20222e}
		 $hex42= {24733132383d20222e}
		 $hex43= {24733132393d20226d}
		 $hex44= {247331323d20222e61}
		 $hex45= {24733133303d20222e}
		 $hex46= {24733133313d20222e}
		 $hex47= {24733133323d20222e}
		 $hex48= {24733133333d20222e}
		 $hex49= {24733133343d20222e}
		 $hex50= {24733133353d20222e}
		 $hex51= {24733133363d20222e}
		 $hex52= {24733133373d20222e}
		 $hex53= {24733133383d20222e}
		 $hex54= {24733133393d20222e}
		 $hex55= {247331333d20226170}
		 $hex56= {24733134303d20222e}
		 $hex57= {24733134313d20224f}
		 $hex58= {24733134323d20224f}
		 $hex59= {24733134333d20225f}
		 $hex60= {24733134343d20225f}
		 $hex61= {24733134353d20222e}
		 $hex62= {24733134363d20222e}
		 $hex63= {24733134373d20222e}
		 $hex64= {24733134383d20222e}
		 $hex65= {24733134393d20222e}
		 $hex66= {247331343d20222e61}
		 $hex67= {24733135303d20222e}
		 $hex68= {24733135313d20222e}
		 $hex69= {24733135323d20222e}
		 $hex70= {24733135333d20222e}
		 $hex71= {24733135343d20222e}
		 $hex72= {24733135353d20222e}
		 $hex73= {24733135363d20222e}
		 $hex74= {24733135373d20222e}
		 $hex75= {24733135383d202250}
		 $hex76= {24733135393d202250}
		 $hex77= {247331353d20222e61}
		 $hex78= {24733136303d202250}
		 $hex79= {24733136313d202250}
		 $hex80= {24733136323d202250}
		 $hex81= {24733136333d202250}
		 $hex82= {24733136343d202250}
		 $hex83= {24733136353d202250}
		 $hex84= {24733136363d202250}
		 $hex85= {24733136373d20222e}
		 $hex86= {24733136383d20222e}
		 $hex87= {24733136393d20222e}
		 $hex88= {247331363d20222e62}
		 $hex89= {24733137303d20222e}
		 $hex90= {24733137313d20222e}
		 $hex91= {24733137323d20222e}
		 $hex92= {24733137333d20222e}
		 $hex93= {24733137343d20222e}
		 $hex94= {24733137353d20222e}
		 $hex95= {24733137363d20222e}
		 $hex96= {24733137373d20222e}
		 $hex97= {24733137383d20222e}
		 $hex98= {24733137393d20222e}
		 $hex99= {247331373d20222e62}
		 $hex100= {24733138303d20222e}
		 $hex101= {24733138313d20222e}
		 $hex102= {24733138323d202251}
		 $hex103= {24733138333d20222e}
		 $hex104= {24733138343d20222e}
		 $hex105= {24733138353d20222e}
		 $hex106= {24733138363d20222e}
		 $hex107= {24733138373d20222e}
		 $hex108= {24733138383d20222e}
		 $hex109= {24733138393d20222e}
		 $hex110= {247331383d20222e63}
		 $hex111= {24733139303d20222e}
		 $hex112= {24733139313d20222e}
		 $hex113= {24733139323d20222e}
		 $hex114= {24733139333d20222e}
		 $hex115= {24733139343d20222e}
		 $hex116= {24733139353d20222e}
		 $hex117= {24733139363d20222e}
		 $hex118= {24733139373d20222e}
		 $hex119= {24733139383d20222e}
		 $hex120= {24733139393d20222e}
		 $hex121= {247331393d20222e63}
		 $hex122= {2473313d2022307825}
		 $hex123= {24733230303d202253}
		 $hex124= {24733230313d20222e}
		 $hex125= {24733230323d20222e}
		 $hex126= {24733230333d20222e}
		 $hex127= {24733230343d20222e}
		 $hex128= {24733230353d20222e}
		 $hex129= {24733230363d20222e}
		 $hex130= {24733230373d20222e}
		 $hex131= {24733230383d202253}
		 $hex132= {24733230393d202253}
		 $hex133= {247332303d20222e63}
		 $hex134= {24733231303d202253}
		 $hex135= {24733231313d202253}
		 $hex136= {24733231323d202253}
		 $hex137= {24733231333d20222e}
		 $hex138= {24733231343d202273}
		 $hex139= {24733231353d202253}
		 $hex140= {24733231363d202253}
		 $hex141= {24733231373d202253}
		 $hex142= {24733231383d202253}
		 $hex143= {24733231393d202253}
		 $hex144= {247332313d20222e63}
		 $hex145= {24733232303d202253}
		 $hex146= {24733232313d202253}
		 $hex147= {24733232323d202253}
		 $hex148= {24733232333d202253}
		 $hex149= {24733232343d202253}
		 $hex150= {24733232353d202253}
		 $hex151= {24733232363d202253}
		 $hex152= {24733232373d202253}
		 $hex153= {24733232383d20222e}
		 $hex154= {24733232393d20222e}
		 $hex155= {247332323d20222e63}
		 $hex156= {24733233303d20222e}
		 $hex157= {24733233313d20222e}
		 $hex158= {24733233323d20222e}
		 $hex159= {24733233333d20222e}
		 $hex160= {24733233343d20222e}
		 $hex161= {24733233353d20222e}
		 $hex162= {24733233363d20222e}
		 $hex163= {24733233373d20222e}
		 $hex164= {24733233383d20222e}
		 $hex165= {24733233393d20222e}
		 $hex166= {247332333d20222e63}
		 $hex167= {24733234303d20222e}
		 $hex168= {24733234313d20222e}
		 $hex169= {24733234323d20222e}
		 $hex170= {24733234333d20222e}
		 $hex171= {24733234343d20222e}
		 $hex172= {24733234353d202253}
		 $hex173= {24733234363d202253}
		 $hex174= {24733234373d20222e}
		 $hex175= {24733234383d20222e}
		 $hex176= {24733234393d20222e}
		 $hex177= {247332343d20222e63}
		 $hex178= {24733235303d20222e}
		 $hex179= {24733235313d202274}
		 $hex180= {24733235323d20222e}
		 $hex181= {24733235333d20222e}
		 $hex182= {24733235343d202254}
		 $hex183= {24733235353d20222e}
		 $hex184= {24733235363d20222e}
		 $hex185= {24733235373d20222e}
		 $hex186= {24733235383d20222e}
		 $hex187= {24733235393d20222e}
		 $hex188= {247332353d20222e63}
		 $hex189= {24733236303d20222e}
		 $hex190= {24733236313d20222e}
		 $hex191= {24733236323d20222e}
		 $hex192= {24733236333d20222e}
		 $hex193= {24733236343d20222e}
		 $hex194= {24733236353d20222e}
		 $hex195= {24733236363d20222e}
		 $hex196= {24733236373d20222e}
		 $hex197= {24733236383d20222e}
		 $hex198= {24733236393d20222e}
		 $hex199= {247332363d2022636c}
		 $hex200= {24733237303d20222e}
		 $hex201= {24733237313d20222e}
		 $hex202= {24733237323d20222e}
		 $hex203= {24733237333d20222e}
		 $hex204= {24733237343d20222e}
		 $hex205= {24733237353d20222e}
		 $hex206= {24733237363d20222e}
		 $hex207= {24733237373d20222e}
		 $hex208= {24733237383d20222e}
		 $hex209= {24733237393d20222e}
		 $hex210= {247332373d20222e63}
		 $hex211= {24733238303d20222e}
		 $hex212= {24733238313d20222e}
		 $hex213= {24733238323d202257}
		 $hex214= {24733238333d202257}
		 $hex215= {24733238343d202257}
		 $hex216= {24733238353d202257}
		 $hex217= {24733238363d202257}
		 $hex218= {24733238373d202257}
		 $hex219= {24733238383d202258}
		 $hex220= {24733238393d202258}
		 $hex221= {247332383d20222e63}
		 $hex222= {24733239303d202258}
		 $hex223= {24733239313d202258}
		 $hex224= {24733239323d202258}
		 $hex225= {24733239333d202258}
		 $hex226= {24733239343d202258}
		 $hex227= {24733239353d202258}
		 $hex228= {24733239363d202278}
		 $hex229= {24733239373d202278}
		 $hex230= {24733239383d202278}
		 $hex231= {24733239393d202278}
		 $hex232= {247332393d2022436f}
		 $hex233= {2473323d20227b3433}
		 $hex234= {24733330303d202278}
		 $hex235= {24733330313d202278}
		 $hex236= {24733330323d202278}
		 $hex237= {24733330333d202278}
		 $hex238= {24733330343d202278}
		 $hex239= {24733330353d202278}
		 $hex240= {24733330363d20222e}
		 $hex241= {24733330373d20222e}
		 $hex242= {24733330383d20222e}
		 $hex243= {24733330393d20222e}
		 $hex244= {247333303d20222e63}
		 $hex245= {24733331303d20222e}
		 $hex246= {24733331313d202278}
		 $hex247= {24733331323d20222e}
		 $hex248= {24733331333d20222e}
		 $hex249= {24733331343d20222e}
		 $hex250= {24733331353d20222e}
		 $hex251= {24733331363d20222e}
		 $hex252= {24733331373d20222e}
		 $hex253= {247333313d20222e63}
		 $hex254= {247333323d20222e63}
		 $hex255= {247333333d20222e63}
		 $hex256= {247333343d20222e63}
		 $hex257= {247333353d20224352}
		 $hex258= {247333363d20224352}
		 $hex259= {247333373d20224352}
		 $hex260= {247333383d20226373}
		 $hex261= {247333393d20224375}
		 $hex262= {2473333d20222e377a}
		 $hex263= {247334303d20224375}
		 $hex264= {247334313d20222e64}
		 $hex265= {247334323d20222e64}
		 $hex266= {247334333d20224465}
		 $hex267= {247334343d20222e64}
		 $hex268= {247334353d20222e64}
		 $hex269= {247334363d20222e64}
		 $hex270= {247334373d20222e64}
		 $hex271= {247334383d20222e64}
		 $hex272= {247334393d2022446f}
		 $hex273= {2473343d20222e6161}
		 $hex274= {247335303d2022446f}
		 $hex275= {247335313d20224472}
		 $hex276= {247335323d20222e64}
		 $hex277= {247335333d20226562}
		 $hex278= {247335343d20222e65}
		 $hex279= {247335353d2022456e}
		 $hex280= {247335363d20222e65}
		 $hex281= {247335373d20224556}
		 $hex282= {247335383d20224556}
		 $hex283= {247335393d20224556}
		 $hex284= {2473353d20222e6161}
		 $hex285= {247336303d20224556}
		 $hex286= {247336313d20224556}
		 $hex287= {247336323d20224556}
		 $hex288= {247336333d20224556}
		 $hex289= {247336343d20224556}
		 $hex290= {247336353d20224556}
		 $hex291= {247336363d20224556}
		 $hex292= {247336373d20224556}
		 $hex293= {247336383d20224556}
		 $hex294= {247336393d20224556}
		 $hex295= {2473363d20222e6161}
		 $hex296= {247337303d20224556}
		 $hex297= {247337313d20224556}
		 $hex298= {247337323d20224556}
		 $hex299= {247337333d20224556}
		 $hex300= {247337343d20224556}
		 $hex301= {247337353d20224556}
		 $hex302= {247337363d20224556}
		 $hex303= {247337373d20224556}
		 $hex304= {247337383d20224556}
		 $hex305= {247337393d20222e65}
		 $hex306= {2473373d20222e6162}
		 $hex307= {247338303d20224578}
		 $hex308= {247338313d20224578}
		 $hex309= {247338323d20222e66}
		 $hex310= {247338333d20222e66}
		 $hex311= {247338343d20222e66}
		 $hex312= {247338353d20224765}
		 $hex313= {247338363d20224765}
		 $hex314= {247338373d20224765}
		 $hex315= {247338383d20222e67}
		 $hex316= {247338393d20222e68}
		 $hex317= {2473383d20222e6163}
		 $hex318= {247339303d20222e68}
		 $hex319= {247339313d20226874}
		 $hex320= {247339323d20226932}
		 $hex321= {247339333d20222e69}
		 $hex322= {247339343d20222e69}
		 $hex323= {247339353d2022496e}
		 $hex324= {247339363d2022496e}
		 $hex325= {247339373d2022496e}
		 $hex326= {247339383d20222e69}
		 $hex327= {247339393d20224953}
		 $hex328= {2473393d2022416371}

	condition:
		218 of them
}
