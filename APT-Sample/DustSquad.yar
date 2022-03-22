
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_DustSquad 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_DustSquad {
	meta: 
		 description= "APT_Sample_DustSquad Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-22_14-15-19" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1610cddb80d1be5d711feb46610f8a77"
		 hash2= "979eff03faeaeea5310df53ee1a2fc8e"
		 hash3= "ea241313acb27429d04a4e4a790d2703"

	strings:

	
 		 $s1= ".7z=application/x-7z-compressed" fullword wide
		 $s2= ".aab=application/x-authorware-bin" fullword wide
		 $s3= ".aam=application/x-authorware-map" fullword wide
		 $s4= ".aas=application/x-authorware-seg" fullword wide
		 $s5= ".abw=application/x-abiword" fullword wide
		 $s6= ".ace=application/x-ace-compressed" fullword wide
		 $s7= "AcquireCredentialsHandleW" fullword wide
		 $s8= ".ai=application/postscript" fullword wide
		 $s9= ".alz=application/x-alz-compressed" fullword wide
		 $s10= ".ani=application/x-navi-animation" fullword wide
		 $s11= "application/xml-external-parsed-entity" fullword wide
		 $s12= "application/x-www-form-urlencoded" fullword wide
		 $s13= ".asf=application/vnd.ms-asf" fullword wide
		 $s14= ".asx=video/x-ms-asf-plugin" fullword wide
		 $s15= "b240c3073284942148b1c0244125494a" fullword wide
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
		 $s26= ".clp=application/x-msclip" fullword wide
		 $s27= ".com=application/x-msdos-program" fullword wide
		 $s28= "Content-Transfer-Encoding: %s" fullword wide
		 $s29= ".cpt=application/mac-compactpro" fullword wide
		 $s30= ".cpt=image/x-corelphotopaint" fullword wide
		 $s31= ".cqk=application/x-calquick" fullword wide
		 $s32= ".crd=application/x-mscardfile" fullword wide
		 $s33= ".crl=application/pkix-crl" fullword wide
		 $s34= "CRYPTO_cleanup_all_ex_data" fullword wide
		 $s35= "CRYPTO_set_locking_callback" fullword wide
		 $s36= "CRYPTO_set_mem_debug_functions" fullword wide
		 $s37= "csISO95JIS62291984handadd" fullword wide
		 $s38= ".dcr=application/x-director" fullword wide
		 $s39= ".deb=application/x-debian-package" fullword wide
		 $s40= ".dir=application/x-director" fullword wide
		 $s41= ".dist=vnd.apple.installer+xml" fullword wide
		 $s42= ".distz=vnd.apple.installer+xml" fullword wide
		 $s43= ".dll=application/x-msdos-program" fullword wide
		 $s44= ".dmg=application/x-apple-diskimage" fullword wide
		 $s45= "DownlevelGetLocaleScripts" fullword wide
		 $s46= "DownlevelGetStringScripts" fullword wide
		 $s47= ".dxr=application/x-director" fullword wide
		 $s48= "ebcdic-international-500+euro" fullword wide
		 $s49= ".ebk=application/x-expandedbook" fullword wide
		 $s50= ".eps=application/postscript" fullword wide
		 $s51= "EVP_CIPHER_CTX_block_size" fullword wide
		 $s52= "EVP_CIPHER_CTX_get_app_data" fullword wide
		 $s53= "EVP_CIPHER_CTX_key_length" fullword wide
		 $s54= "EVP_CIPHER_CTX_set_app_data" fullword wide
		 $s55= "EVP_CIPHER_CTX_set_key_length" fullword wide
		 $s56= "EVP_PKEY_asn1_set_private" fullword wide
		 $s57= "EVP_PKEY_CTX_get0_peerkey" fullword wide
		 $s58= "EVP_PKEY_CTX_get_app_data" fullword wide
		 $s59= "EVP_PKEY_CTX_get_keygen_info" fullword wide
		 $s60= "EVP_PKEY_CTX_get_operation" fullword wide
		 $s61= "EVP_PKEY_CTX_set0_keygen_info" fullword wide
		 $s62= "EVP_PKEY_CTX_set_app_data" fullword wide
		 $s63= "EVP_PKEY_get_default_digest_nid" fullword wide
		 $s64= "EVP_PKEY_meth_set_cleanup" fullword wide
		 $s65= "EVP_PKEY_meth_set_decrypt" fullword wide
		 $s66= "EVP_PKEY_meth_set_encrypt" fullword wide
		 $s67= "EVP_PKEY_meth_set_paramgen" fullword wide
		 $s68= "EVP_PKEY_meth_set_signctx" fullword wide
		 $s69= "EVP_PKEY_meth_set_verifyctx" fullword wide
		 $s70= "EVP_PKEY_meth_set_verify_recover" fullword wide
		 $s71= "EVP_PKEY_missing_parameters" fullword wide
		 $s72= "EVP_PKEY_verify_recover_init" fullword wide
		 $s73= ".exe=application/x-msdos-program" fullword wide
		 $s74= "Extended_UNIX_Code_Fixed_Width_for_Japanese" fullword wide
		 $s75= "Extended_UNIX_Code_Packed_Format_for_Japanese" fullword wide
		 $s76= ".fif=application/fractals" fullword wide
		 $s77= ".flm=application/vnd.kde.kivio" fullword wide
		 $s78= ".fml=application/x-file-mirror-list" fullword wide
		 $s79= "GetUniDirectionalAdapterInfo" fullword wide
		 $s80= ".gnumeric=application/x-gnumeric" fullword wide
		 $s81= ".hpf=application/x-icq-hpf" fullword wide
		 $s82= ".hqx=application/mac-binhex40" fullword wide
		 $s83= "http://148.251.185.168/d4.php?check" fullword wide
		 $s84= "http://88.198.204.196/d4.php?check" fullword wide
		 $s85= "http://92.63.88.142/d4.php?check" fullword wide
		 $s86= "http://www.indyproject.org/" fullword wide
		 $s87= "i2d_NETSCAPE_CERT_SEQUENCE" fullword wide
		 $s88= ".iii=application/x-iphone" fullword wide
		 $s89= ".ims=application/vnd.ms-ims" fullword wide
		 $s90= "InitializeConditionVariable" fullword wide
		 $s91= "InitializeProcessForWsWatch" fullword wide
		 $s92= "InitializeSecurityContextW" fullword wide
		 $s93= ".ins=application/x-internet-signup" fullword wide
		 $s94= "ISO-8859-1-Windows-3.0-Latin-1" fullword wide
		 $s95= "ISO-8859-1-Windows-3.1-Latin-1" fullword wide
		 $s96= "ISO-8859-2-Windows-Latin-2" fullword wide
		 $s97= "ISO-8859-9-Windows-Latin-5" fullword wide
		 $s98= ".iso=application/x-iso9660-image" fullword wide
		 $s99= ".jar=application/java-archive" fullword wide
		 $s100= ".karbon=application/vnd.kde.karbon" fullword wide
		 $s101= ".kfo=application/vnd.kde.kformula" fullword wide
		 $s102= ".kon=application/vnd.kde.kontour" fullword wide
		 $s103= ".kpr=application/vnd.kde.kpresenter" fullword wide
		 $s104= ".kpt=application/vnd.kde.kpresenter" fullword wide
		 $s105= ".kwd=application/vnd.kde.kword" fullword wide
		 $s106= ".kwt=application/vnd.kde.kword" fullword wide
		 $s107= ".latex=application/x-latex" fullword wide
		 $s108= ".lrm=application/vnd.ms-lrm" fullword wide
		 $s109= ".m13=application/x-msmediaview" fullword wide
		 $s110= ".m14=application/x-msmediaview" fullword wide
		 $s111= ".man=application/x-troff-man" fullword wide
		 $s112= ".mdb=application/x-msaccess" fullword wide
		 $s113= ".me=application/x-troff-me" fullword wide
		 $s114= "MIMEDatabaseContent Type" fullword wide
		 $s115= "MIMEDatabaseContent Type" fullword wide
		 $s116= ".mjf=audio/x-vnd.AudioExplosion.MjuiceMediaFile" fullword wide
		 $s117= ".mny=application/x-msmoney" fullword wide
		 $s118= "MozillaFirefoxProfiles" fullword wide
		 $s119= ".mpkg=vnd.apple.installer+xml" fullword wide
		 $s120= ".mpp=application/vnd.ms-project" fullword wide
		 $s121= ".ms=application/x-troff-ms" fullword wide
		 $s122= "multipart/form-data; boundary=" fullword wide
		 $s123= ".mvb=application/x-msmediaview" fullword wide
		 $s124= ".nix=application/x-mix-transfer" fullword wide
		 $s125= ".odb=application/vnd.oasis.opendocument.database" fullword wide
		 $s126= ".odc=application/vnd.oasis.opendocument.chart" fullword wide
		 $s127= ".odf=application/vnd.oasis.opendocument.formula" fullword wide
		 $s128= ".odg=application/vnd.oasis.opendocument.graphics" fullword wide
		 $s129= ".odi=application/vnd.oasis.opendocument.image" fullword wide
		 $s130= ".odm=application/vnd.oasis.opendocument.text-master" fullword wide
		 $s131= ".odp=application/vnd.oasis.opendocument.presentation" fullword wide
		 $s132= ".ods=application/vnd.oasis.opendocument.spreadsheet" fullword wide
		 $s133= ".odt=application/vnd.oasis.opendocument.text" fullword wide
		 $s134= "OpenSSL_add_all_algorithms" fullword wide
		 $s135= "OPENSSL_add_all_algorithms_noconf" fullword wide
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
		 $s149= ".pat=image/x-coreldrawpattern" fullword wide
		 $s150= ".pbm=image/x-portable-bitmap" fullword wide
		 $s151= "PEM_read_bio_DSAPrivateKey" fullword wide
		 $s152= "PEM_read_bio_NETSCAPE_CERT_SEQUENCE" fullword wide
		 $s153= "PEM_read_bio_RSAPrivateKey" fullword wide
		 $s154= "PEM_read_bio_RSAPublicKey" fullword wide
		 $s155= "PEM_write_bio_DSAPrivateKey" fullword wide
		 $s156= "PEM_write_bio_NETSCAPE_CERT_SEQUENCE" fullword wide
		 $s157= "PEM_write_bio_PKCS8PrivateKey" fullword wide
		 $s158= "PEM_write_bio_RSAPublicKey" fullword wide
		 $s159= ".pfr=application/font-tdpfr" fullword wide
		 $s160= ".pgm=image/x-portable-graymap" fullword wide
		 $s161= ".pkg=vnd.apple.installer+xml" fullword wide
		 $s162= ".pko=application/vnd.ms-pki.pko" fullword wide
		 $s163= ".pnm=image/x-portable-anymap" fullword wide
		 $s164= ".pnq=application/x-icq-pnq" fullword wide
		 $s165= ".pot=application/mspowerpoint" fullword wide
		 $s166= ".ppm=image/x-portable-pixmap" fullword wide
		 $s167= ".pps=application/mspowerpoint" fullword wide
		 $s168= ".ppt=application/mspowerpoint" fullword wide
		 $s169= ".ppz=application/mspowerpoint" fullword wide
		 $s170= ".ps=application/postscript" fullword wide
		 $s171= ".pub=application/x-mspublisher" fullword wide
		 $s172= ".qpw=application/x-quattropro" fullword wide
		 $s173= ".qtl=application/x-quicktimeplayer" fullword wide
		 $s174= "QuerySecurityPackageInfoW" fullword wide
		 $s175= ".ram=audio/x-pn-realaudio" fullword wide
		 $s176= ".rf=image/vnd.rn-realflash" fullword wide
		 $s177= ".rjs=application/vnd.rn-realsystem-rjs" fullword wide
		 $s178= ".rm=application/vnd.rn-realmedia" fullword wide
		 $s179= ".rmp=application/vnd.rn-rn_music_package" fullword wide
		 $s180= ".rms=video/vnd.rn-realvideo-secure" fullword wide
		 $s181= ".rmx=application/vnd.rn-realsystem-rmx" fullword wide
		 $s182= ".rnx=application/vnd.rn-realplayer" fullword wide
		 $s183= ".rpm=application/x-redhat-package-manager" fullword wide
		 $s184= ".rsml=application/vnd.rn-rsml" fullword wide
		 $s185= ".rv=video/vnd.rn-realvideo" fullword wide
		 $s186= ".scd=application/x-msschedule" fullword wide
		 $s187= ".scm=application/x-icq-scm" fullword wide
		 $s188= ".sda=application/vnd.stardivision.draw" fullword wide
		 $s189= ".sdc=application/vnd.stardivision.calc" fullword wide
		 $s190= ".sdd=application/vnd.stardivision.impress" fullword wide
		 $s191= ".ser=application/java-serialized-object" fullword wide
		 $s192= ".setpay=application/set-payment-initiation" fullword wide
		 $s193= ".setreg=application/set-registration-initiation" fullword wide
		 $s194= ".shtml=server-parsed-html" fullword wide
		 $s195= ".shw=application/presentations" fullword wide
		 $s196= ".sit=application/x-stuffit" fullword wide
		 $s197= ".sitx=application/x-stuffitx" fullword wide
		 $s198= ".smf=application/vnd.stardivision.math" fullword wide
		 $s199= "SoftwareBorlandDelphiLocales" fullword wide
		 $s200= "SoftwareCodeGearLocales" fullword wide
		 $s201= "SoftwareEmbarcaderoLocales" fullword wide
		 $s202= "SoftwareMicrosoftWindowsCurrentVersionInternet Settings" fullword wide
		 $s203= ".spl=application/futuresplash" fullword wide
		 $s204= "SSL_alert_desc_string_long" fullword wide
		 $s205= "SSL_alert_type_string_long" fullword wide
		 $s206= "SSL_COMP_get_compression_methods" fullword wide
		 $s207= "SSL_CTX_check_private_key" fullword wide
		 $s208= "SSL_CTX_load_verify_locations" fullword wide
		 $s209= "SSL_CTX_set_client_CA_list" fullword wide
		 $s210= "SSL_CTX_set_default_passwd_cb" fullword wide
		 $s211= "SSL_CTX_set_default_passwd_cb_userdata" fullword wide
		 $s212= "SSL_CTX_set_default_verify_paths" fullword wide
		 $s213= "SSL_CTX_set_session_id_context" fullword wide
		 $s214= "SSL_CTX_use_certificate_file" fullword wide
		 $s215= "SSL_CTX_use_PrivateKey_file" fullword wide
		 $s216= ".ssm=application/streamingmedia" fullword wide
		 $s217= ".sst=application/vnd.ms-pki.certstore" fullword wide
		 $s218= ".stc=application/vnd.sun.xml.calc.template" fullword wide
		 $s219= ".std=application/vnd.sun.xml.draw.template" fullword wide
		 $s220= ".sti=application/vnd.sun.xml.impress.template" fullword wide
		 $s221= ".stl=application/vnd.ms-pki.stl" fullword wide
		 $s222= ".stw=application/vnd.sun.xml.writer.template" fullword wide
		 $s223= ".sv4cpio=application/x-sv4cpio" fullword wide
		 $s224= ".sv4crc=application/x-sv4crc" fullword wide
		 $s225= ".svi=application/softvision" fullword wide
		 $s226= ".swf1=application/x-shockwave-flash" fullword wide
		 $s227= ".swf=application/x-shockwave-flash" fullword wide
		 $s228= ".sxc=application/vnd.sun.xml.calc" fullword wide
		 $s229= ".sxg=application/vnd.sun.xml.writer.global" fullword wide
		 $s230= ".sxi=application/vnd.sun.xml.impress" fullword wide
		 $s231= ".sxm=application/vnd.sun.xml.math" fullword wide
		 $s232= ".sxw=application/vnd.sun.xml.writer" fullword wide
		 $s233= "TAbSpanReadStream.Seek unsupported" fullword wide
		 $s234= "TAbSpanReadStream.Write unsupported" fullword wide
		 $s235= "TAbSpanWriteStream.Read unsupported" fullword wide
		 $s236= "TAbSpanWriteStream.Seek unsupported" fullword wide
		 $s237= ".tbz2=application/x-bzip-compressed-tar" fullword wide
		 $s238= ".tbz=application/x-bzip-compressed-tar" fullword wide
		 $s239= ".texi=application/x-texinfo" fullword wide
		 $s240= ".texinfo=application/x-texinfo" fullword wide
		 $s241= "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" fullword wide
		 $s242= ".tgz=application/x-compressed-tar" fullword wide
		 $s243= ".tlz=application/x-lzma-compressed-tar" fullword wide
		 $s244= ".torrent=application/x-bittorrent" fullword wide
		 $s245= ".trm=application/x-msterminal" fullword wide
		 $s246= ".troff=application/x-troff" fullword wide
		 $s247= ".txz=application/x-xz-compressed-tar" fullword wide
		 $s248= "U:Codingcomponents_delphiXE7Abbrevia 5.2sourceAbDfBase.pas" fullword wide
		 $s249= "U:Codingcomponents_delphiXE7Abbrevia 5.2sourceAbDfCryS.pas" fullword wide
		 $s250= "U:Codingcomponents_delphiXE7Abbrevia 5.2sourceAbDfDec.pas" fullword wide
		 $s251= "U:Codingcomponents_delphiXE7Abbrevia 5.2sourceAbDfEnc.pas" fullword wide
		 $s252= "U:Codingcomponents_delphiXE7Abbrevia 5.2sourceAbDfHufD.pas" fullword wide
		 $s253= "U:Codingcomponents_delphiXE7Abbrevia 5.2sourceAbDfInW.pas" fullword wide
		 $s254= "U:Codingcomponents_delphiXE7Abbrevia 5.2sourceAbDfPkMg.pas" fullword wide
		 $s255= "U:Codingcomponents_delphiXE7Abbrevia 5.2sourceAbDfStrm.pas" fullword wide
		 $s256= "U:Codingcomponents_delphiXE7Abbrevia 5.2sourceAbDfXlat.pas" fullword wide
		 $s257= "U:Codingcomponents_delphiXE7Abbrevia 5.2sourceAbWavPack.pas" fullword wide
		 $s258= "U:Codingcomponents_delphiXE7Abbrevia 5.2sourceAbZipTyp.pas" fullword wide
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
		 $a1= "System.DateUtils.TLocalTimeZone.TYearlyChanges>" fullword ascii
		 $a2= "System.DateUtils.TLocalTimeZone.TYearlyChanges>'" fullword ascii
		 $a3= "System.DateUtils.TLocalTimeZone.TYearlyChanges>(" fullword ascii
		 $a4= "System.DateUtils.TLocalTimeZone.TYearlyChanges>$GN" fullword ascii
		 $a5= "System.DateUtils.TLocalTimeZone.TYearlyChanges>0!@" fullword ascii
		 $a6= "System.DateUtils.TLocalTimeZone.TYearlyChanges>.arrayofT" fullword ascii
		 $a7= "System.DateUtils.TLocalTimeZone.TYearlyChanges>g" fullword ascii
		 $a8= "System.Integer,System.Classes.IInterfaceList>.TItem" fullword ascii
		 $a9= "System.Pointer,System.Rtti.TRttiObject>.TItemArray" fullword ascii
		 $a10= "System.Rtti.TMethodImplementation.TParamLoc>" fullword ascii
		 $a11= "System.Rtti.TMethodImplementation.TParamLoc>0!@" fullword ascii
		 $a12= "System.Rtti.TMethodImplementation.TParamLoc>.arrayofT" fullword ascii
		 $a13= "System.Rtti.TMethodImplementation.TParamLoc>g" fullword ascii
		 $a14= "System.Rtti.TMethodImplementation.TParamLoc>.TEmptyFunc" fullword ascii
		 $a15= "System.Rtti.TMethodImplementation.TParamLoc>.TEnumerator" fullword ascii
		 $a16= "System.Rtti.TMethodImplementation.TParamLoc>.TEnumerator5" fullword ascii
		 $a17= "System.string,System.Classes.TPersistentClass>9" fullword ascii
		 $a18= "System.string,System.TypInfo.PTypeInfo>.TItemArray" fullword ascii
		 $a19= "System.TypInfo.PTypeInfo,System.string>.TItemArray" fullword ascii

		 $hex1= {2e377a3d6170706c69}
		 $hex2= {2e6161623d6170706c}
		 $hex3= {2e61616d3d6170706c}
		 $hex4= {2e6161733d6170706c}
		 $hex5= {2e6162773d6170706c}
		 $hex6= {2e6163653d6170706c}
		 $hex7= {2e61693d6170706c69}
		 $hex8= {2e616c7a3d6170706c}
		 $hex9= {2e616e693d6170706c}
		 $hex10= {2e6173663d6170706c}
		 $hex11= {2e6173783d76696465}
		 $hex12= {2e6261743d6170706c}
		 $hex13= {2e626370696f3d6170}
		 $hex14= {2e6361623d6170706c}
		 $hex15= {2e6361743d6170706c}
		 $hex16= {2e6364743d696d6167}
		 $hex17= {2e6365723d6170706c}
		 $hex18= {2e63686d3d6170706c}
		 $hex19= {2e636872743d617070}
		 $hex20= {2e63696c3d6170706c}
		 $hex21= {2e636c6173733d6170}
		 $hex22= {2e636c703d6170706c}
		 $hex23= {2e636f6d3d6170706c}
		 $hex24= {2e6370743d6170706c}
		 $hex25= {2e6370743d696d6167}
		 $hex26= {2e63716b3d6170706c}
		 $hex27= {2e6372643d6170706c}
		 $hex28= {2e63726c3d6170706c}
		 $hex29= {2e6463723d6170706c}
		 $hex30= {2e6465623d6170706c}
		 $hex31= {2e6469723d6170706c}
		 $hex32= {2e646973743d766e64}
		 $hex33= {2e646973747a3d766e}
		 $hex34= {2e646c6c3d6170706c}
		 $hex35= {2e646d673d6170706c}
		 $hex36= {2e6478723d6170706c}
		 $hex37= {2e65626b3d6170706c}
		 $hex38= {2e6570733d6170706c}
		 $hex39= {2e6578653d6170706c}
		 $hex40= {2e6669663d6170706c}
		 $hex41= {2e666c6d3d6170706c}
		 $hex42= {2e666d6c3d6170706c}
		 $hex43= {2e676e756d65726963}
		 $hex44= {2e6870663d6170706c}
		 $hex45= {2e6871783d6170706c}
		 $hex46= {2e6969693d6170706c}
		 $hex47= {2e696d733d6170706c}
		 $hex48= {2e696e733d6170706c}
		 $hex49= {2e69736f3d6170706c}
		 $hex50= {2e6a61723d6170706c}
		 $hex51= {2e6b6172626f6e3d61}
		 $hex52= {2e6b666f3d6170706c}
		 $hex53= {2e6b6f6e3d6170706c}
		 $hex54= {2e6b70723d6170706c}
		 $hex55= {2e6b70743d6170706c}
		 $hex56= {2e6b77643d6170706c}
		 $hex57= {2e6b77743d6170706c}
		 $hex58= {2e6c617465783d6170}
		 $hex59= {2e6c726d3d6170706c}
		 $hex60= {2e6d31333d6170706c}
		 $hex61= {2e6d31343d6170706c}
		 $hex62= {2e6d616e3d6170706c}
		 $hex63= {2e6d64623d6170706c}
		 $hex64= {2e6d653d6170706c69}
		 $hex65= {2e6d6a663d61756469}
		 $hex66= {2e6d6e793d6170706c}
		 $hex67= {2e6d706b673d766e64}
		 $hex68= {2e6d70703d6170706c}
		 $hex69= {2e6d733d6170706c69}
		 $hex70= {2e6d76623d6170706c}
		 $hex71= {2e6e69783d6170706c}
		 $hex72= {2e6f64623d6170706c}
		 $hex73= {2e6f64633d6170706c}
		 $hex74= {2e6f64663d6170706c}
		 $hex75= {2e6f64673d6170706c}
		 $hex76= {2e6f64693d6170706c}
		 $hex77= {2e6f646d3d6170706c}
		 $hex78= {2e6f64703d6170706c}
		 $hex79= {2e6f64733d6170706c}
		 $hex80= {2e6f64743d6170706c}
		 $hex81= {2e6f74673d6170706c}
		 $hex82= {2e6f74683d6170706c}
		 $hex83= {2e6f74703d6170706c}
		 $hex84= {2e6f74733d6170706c}
		 $hex85= {2e6f74743d6170706c}
		 $hex86= {2e7031323d6170706c}
		 $hex87= {2e7037623d6170706c}
		 $hex88= {2e70376d3d6170706c}
		 $hex89= {2e7037723d6170706c}
		 $hex90= {2e7037733d6170706c}
		 $hex91= {2e7061636b6167653d}
		 $hex92= {2e7061743d696d6167}
		 $hex93= {2e70626d3d696d6167}
		 $hex94= {2e7066723d6170706c}
		 $hex95= {2e70676d3d696d6167}
		 $hex96= {2e706b673d766e642e}
		 $hex97= {2e706b6f3d6170706c}
		 $hex98= {2e706e6d3d696d6167}
		 $hex99= {2e706e713d6170706c}
		 $hex100= {2e706f743d6170706c}
		 $hex101= {2e70706d3d696d6167}
		 $hex102= {2e7070733d6170706c}
		 $hex103= {2e7070743d6170706c}
		 $hex104= {2e70707a3d6170706c}
		 $hex105= {2e70733d6170706c69}
		 $hex106= {2e7075623d6170706c}
		 $hex107= {2e7170773d6170706c}
		 $hex108= {2e71746c3d6170706c}
		 $hex109= {2e72616d3d61756469}
		 $hex110= {2e72663d696d616765}
		 $hex111= {2e726a733d6170706c}
		 $hex112= {2e726d3d6170706c69}
		 $hex113= {2e726d703d6170706c}
		 $hex114= {2e726d733d76696465}
		 $hex115= {2e726d783d6170706c}
		 $hex116= {2e726e783d6170706c}
		 $hex117= {2e72706d3d6170706c}
		 $hex118= {2e72736d6c3d617070}
		 $hex119= {2e72763d766964656f}
		 $hex120= {2e7363643d6170706c}
		 $hex121= {2e73636d3d6170706c}
		 $hex122= {2e7364613d6170706c}
		 $hex123= {2e7364633d6170706c}
		 $hex124= {2e7364643d6170706c}
		 $hex125= {2e7365723d6170706c}
		 $hex126= {2e7365747061793d61}
		 $hex127= {2e7365747265673d61}
		 $hex128= {2e7368746d6c3d7365}
		 $hex129= {2e7368773d6170706c}
		 $hex130= {2e7369743d6170706c}
		 $hex131= {2e736974783d617070}
		 $hex132= {2e736d663d6170706c}
		 $hex133= {2e73706c3d6170706c}
		 $hex134= {2e73736d3d6170706c}
		 $hex135= {2e7373743d6170706c}
		 $hex136= {2e7374633d6170706c}
		 $hex137= {2e7374643d6170706c}
		 $hex138= {2e7374693d6170706c}
		 $hex139= {2e73746c3d6170706c}
		 $hex140= {2e7374773d6170706c}
		 $hex141= {2e7376346370696f3d}
		 $hex142= {2e7376346372633d61}
		 $hex143= {2e7376693d6170706c}
		 $hex144= {2e737766313d617070}
		 $hex145= {2e7377663d6170706c}
		 $hex146= {2e7378633d6170706c}
		 $hex147= {2e7378673d6170706c}
		 $hex148= {2e7378693d6170706c}
		 $hex149= {2e73786d3d6170706c}
		 $hex150= {2e7378773d6170706c}
		 $hex151= {2e74627a323d617070}
		 $hex152= {2e74627a3d6170706c}
		 $hex153= {2e746578693d617070}
		 $hex154= {2e746578696e666f3d}
		 $hex155= {2e74677a3d6170706c}
		 $hex156= {2e746c7a3d6170706c}
		 $hex157= {2e746f7272656e743d}
		 $hex158= {2e74726d3d6170706c}
		 $hex159= {2e74726f66663d6170}
		 $hex160= {2e74787a3d6170706c}
		 $hex161= {2e756465623d617070}
		 $hex162= {2e75726c733d617070}
		 $hex163= {2e75737461723d6170}
		 $hex164= {2e7663643d6170706c}
		 $hex165= {2e766f723d6170706c}
		 $hex166= {2e76736c3d6170706c}
		 $hex167= {2e7762313d6170706c}
		 $hex168= {2e7762323d6170706c}
		 $hex169= {2e7762333d6170706c}
		 $hex170= {2e77636d3d6170706c}
		 $hex171= {2e7764623d6170706c}
		 $hex172= {2e776b733d6170706c}
		 $hex173= {2e776d643d6170706c}
		 $hex174= {2e776d6c633d617070}
		 $hex175= {2e776d6c733d746578}
		 $hex176= {2e776d6c73633d6170}
		 $hex177= {2e776d733d6170706c}
		 $hex178= {2e776d7a3d6170706c}
		 $hex179= {2e7770353d6170706c}
		 $hex180= {2e7770643d6170706c}
		 $hex181= {2e77706c3d6170706c}
		 $hex182= {2e7770733d6170706c}
		 $hex183= {2e7772693d6170706c}
		 $hex184= {2e786664663d617070}
		 $hex185= {2e7868743d6170706c}
		 $hex186= {2e7868746d6c3d6170}
		 $hex187= {2e786c623d6170706c}
		 $hex188= {2e786c733d6170706c}
		 $hex189= {2e7870693d6170706c}
		 $hex190= {2e7870733d6170706c}
		 $hex191= {2e7873643d6170706c}
		 $hex192= {2e78756c3d6170706c}
		 $hex193= {2e7a3d6170706c6963}
		 $hex194= {2e7a69703d6170706c}
		 $hex195= {416371756972654372}
		 $hex196= {43525950544f5f636c}
		 $hex197= {43525950544f5f7365}
		 $hex198= {436f6e74656e742d54}
		 $hex199= {446f776e6c6576656c}
		 $hex200= {4556505f4349504845}
		 $hex201= {4556505f504b45595f}
		 $hex202= {457874656e6465645f}
		 $hex203= {476574556e69446972}
		 $hex204= {49534f2d383835392d}
		 $hex205= {496e697469616c697a}
		 $hex206= {4d494d454461746162}
		 $hex207= {4d6f7a696c6c614669}
		 $hex208= {4f50454e53534c5f61}
		 $hex209= {4f70656e53534c5f61}
		 $hex210= {50454d5f726561645f}
		 $hex211= {50454d5f7772697465}
		 $hex212= {517565727953656375}
		 $hex213= {53534c5f434f4d505f}
		 $hex214= {53534c5f4354585f63}
		 $hex215= {53534c5f4354585f6c}
		 $hex216= {53534c5f4354585f73}
		 $hex217= {53534c5f4354585f75}
		 $hex218= {53534c5f616c657274}
		 $hex219= {536f66747761726542}
		 $hex220= {536f66747761726543}
		 $hex221= {536f66747761726545}
		 $hex222= {536f6674776172654d}
		 $hex223= {53797374656d2e4461}
		 $hex224= {53797374656d2e496e}
		 $hex225= {53797374656d2e506f}
		 $hex226= {53797374656d2e5274}
		 $hex227= {53797374656d2e5479}
		 $hex228= {53797374656d2e7374}
		 $hex229= {5441625370616e5265}
		 $hex230= {5441625370616e5772}
		 $hex231= {553a436f64696e6763}
		 $hex232= {57534144656c657465}
		 $hex233= {575341456e756d4e61}
		 $hex234= {575341476574536572}
		 $hex235= {575341536574536f63}
		 $hex236= {583530395f45585445}
		 $hex237= {583530395f4e414d45}
		 $hex238= {583530395f53544f52}
		 $hex239= {583530395f6765745f}
		 $hex240= {5f6f73736c5f6f6c64}
		 $hex241= {6170706c6963617469}
		 $hex242= {623234306333303733}
		 $hex243= {637349534f39354a49}
		 $hex244= {6562636469632d696e}
		 $hex245= {687474703a2f2f3134}
		 $hex246= {687474703a2f2f3838}
		 $hex247= {687474703a2f2f3932}
		 $hex248= {687474703a2f2f7777}
		 $hex249= {6932645f4e45545343}
		 $hex250= {6d756c746970617274}
		 $hex251= {746578742f68746d6c}
		 $hex252= {782d4542434449432d}
		 $hex253= {782d6562636469632d}
		 $hex254= {786d6c2d6578746572}

	condition:
		196 of them
}
