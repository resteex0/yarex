
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
		 date = "2022-01-22_17-55-36" 
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

		 $hex1= {246131303d20225379}
		 $hex2= {246131313d20225379}
		 $hex3= {246131323d20225379}
		 $hex4= {246131333d20225379}
		 $hex5= {246131343d20225379}
		 $hex6= {246131353d20225379}
		 $hex7= {246131363d20225379}
		 $hex8= {246131373d20225379}
		 $hex9= {246131383d20225379}
		 $hex10= {246131393d20225379}
		 $hex11= {2461313d2022537973}
		 $hex12= {2461323d2022537973}
		 $hex13= {2461333d2022537973}
		 $hex14= {2461343d2022537973}
		 $hex15= {2461353d2022537973}
		 $hex16= {2461363d2022537973}
		 $hex17= {2461373d2022537973}
		 $hex18= {2461383d2022537973}
		 $hex19= {2461393d2022537973}
		 $hex20= {24733130303d20222e}
		 $hex21= {24733130313d20222e}
		 $hex22= {24733130323d20222e}
		 $hex23= {24733130333d20222e}
		 $hex24= {24733130343d20222e}
		 $hex25= {24733130353d20222e}
		 $hex26= {24733130363d20222e}
		 $hex27= {24733130373d20222e}
		 $hex28= {24733130383d20222e}
		 $hex29= {24733130393d20222e}
		 $hex30= {247331303d20222e61}
		 $hex31= {24733131303d20222e}
		 $hex32= {24733131313d20222e}
		 $hex33= {24733131323d20222e}
		 $hex34= {24733131333d20222e}
		 $hex35= {24733131343d20224d}
		 $hex36= {24733131353d20224d}
		 $hex37= {24733131363d20222e}
		 $hex38= {24733131373d20222e}
		 $hex39= {24733131383d20224d}
		 $hex40= {24733131393d20222e}
		 $hex41= {247331313d20226170}
		 $hex42= {24733132303d20222e}
		 $hex43= {24733132313d20222e}
		 $hex44= {24733132323d20226d}
		 $hex45= {24733132333d20222e}
		 $hex46= {24733132343d20222e}
		 $hex47= {24733132353d20222e}
		 $hex48= {24733132363d20222e}
		 $hex49= {24733132373d20222e}
		 $hex50= {24733132383d20222e}
		 $hex51= {24733132393d20222e}
		 $hex52= {247331323d20226170}
		 $hex53= {24733133303d20222e}
		 $hex54= {24733133313d20222e}
		 $hex55= {24733133323d20222e}
		 $hex56= {24733133333d20222e}
		 $hex57= {24733133343d20224f}
		 $hex58= {24733133353d20224f}
		 $hex59= {24733133363d20225f}
		 $hex60= {24733133373d20225f}
		 $hex61= {24733133383d20222e}
		 $hex62= {24733133393d20222e}
		 $hex63= {247331333d20222e61}
		 $hex64= {24733134303d20222e}
		 $hex65= {24733134313d20222e}
		 $hex66= {24733134323d20222e}
		 $hex67= {24733134333d20222e}
		 $hex68= {24733134343d20222e}
		 $hex69= {24733134353d20222e}
		 $hex70= {24733134363d20222e}
		 $hex71= {24733134373d20222e}
		 $hex72= {24733134383d20222e}
		 $hex73= {24733134393d20222e}
		 $hex74= {247331343d20222e61}
		 $hex75= {24733135303d20222e}
		 $hex76= {24733135313d202250}
		 $hex77= {24733135323d202250}
		 $hex78= {24733135333d202250}
		 $hex79= {24733135343d202250}
		 $hex80= {24733135353d202250}
		 $hex81= {24733135363d202250}
		 $hex82= {24733135373d202250}
		 $hex83= {24733135383d202250}
		 $hex84= {24733135393d20222e}
		 $hex85= {247331353d20226232}
		 $hex86= {24733136303d20222e}
		 $hex87= {24733136313d20222e}
		 $hex88= {24733136323d20222e}
		 $hex89= {24733136333d20222e}
		 $hex90= {24733136343d20222e}
		 $hex91= {24733136353d20222e}
		 $hex92= {24733136363d20222e}
		 $hex93= {24733136373d20222e}
		 $hex94= {24733136383d20222e}
		 $hex95= {24733136393d20222e}
		 $hex96= {247331363d20222e62}
		 $hex97= {24733137303d20222e}
		 $hex98= {24733137313d20222e}
		 $hex99= {24733137323d20222e}
		 $hex100= {24733137333d20222e}
		 $hex101= {24733137343d202251}
		 $hex102= {24733137353d20222e}
		 $hex103= {24733137363d20222e}
		 $hex104= {24733137373d20222e}
		 $hex105= {24733137383d20222e}
		 $hex106= {24733137393d20222e}
		 $hex107= {247331373d20222e62}
		 $hex108= {24733138303d20222e}
		 $hex109= {24733138313d20222e}
		 $hex110= {24733138323d20222e}
		 $hex111= {24733138333d20222e}
		 $hex112= {24733138343d20222e}
		 $hex113= {24733138353d20222e}
		 $hex114= {24733138363d20222e}
		 $hex115= {24733138373d20222e}
		 $hex116= {24733138383d20222e}
		 $hex117= {24733138393d20222e}
		 $hex118= {247331383d20222e63}
		 $hex119= {24733139303d20222e}
		 $hex120= {24733139313d20222e}
		 $hex121= {24733139323d20222e}
		 $hex122= {24733139333d20222e}
		 $hex123= {24733139343d20222e}
		 $hex124= {24733139353d20222e}
		 $hex125= {24733139363d20222e}
		 $hex126= {24733139373d20222e}
		 $hex127= {24733139383d20222e}
		 $hex128= {24733139393d202253}
		 $hex129= {247331393d20222e63}
		 $hex130= {2473313d20222e377a}
		 $hex131= {24733230303d202253}
		 $hex132= {24733230313d202253}
		 $hex133= {24733230323d202253}
		 $hex134= {24733230333d20222e}
		 $hex135= {24733230343d202253}
		 $hex136= {24733230353d202253}
		 $hex137= {24733230363d202253}
		 $hex138= {24733230373d202253}
		 $hex139= {24733230383d202253}
		 $hex140= {24733230393d202253}
		 $hex141= {247332303d20222e63}
		 $hex142= {24733231303d202253}
		 $hex143= {24733231313d202253}
		 $hex144= {24733231323d202253}
		 $hex145= {24733231333d202253}
		 $hex146= {24733231343d202253}
		 $hex147= {24733231353d202253}
		 $hex148= {24733231363d20222e}
		 $hex149= {24733231373d20222e}
		 $hex150= {24733231383d20222e}
		 $hex151= {24733231393d20222e}
		 $hex152= {247332313d20222e63}
		 $hex153= {24733232303d20222e}
		 $hex154= {24733232313d20222e}
		 $hex155= {24733232323d20222e}
		 $hex156= {24733232333d20222e}
		 $hex157= {24733232343d20222e}
		 $hex158= {24733232353d20222e}
		 $hex159= {24733232363d20222e}
		 $hex160= {24733232373d20222e}
		 $hex161= {24733232383d20222e}
		 $hex162= {24733232393d20222e}
		 $hex163= {247332323d20222e63}
		 $hex164= {24733233303d20222e}
		 $hex165= {24733233313d20222e}
		 $hex166= {24733233323d20222e}
		 $hex167= {24733233333d202254}
		 $hex168= {24733233343d202254}
		 $hex169= {24733233353d202254}
		 $hex170= {24733233363d202254}
		 $hex171= {24733233373d20222e}
		 $hex172= {24733233383d20222e}
		 $hex173= {24733233393d20222e}
		 $hex174= {247332333d20222e63}
		 $hex175= {24733234303d20222e}
		 $hex176= {24733234313d202274}
		 $hex177= {24733234323d20222e}
		 $hex178= {24733234333d20222e}
		 $hex179= {24733234343d20222e}
		 $hex180= {24733234353d20222e}
		 $hex181= {24733234363d20222e}
		 $hex182= {24733234373d20222e}
		 $hex183= {24733234383d202255}
		 $hex184= {24733234393d202255}
		 $hex185= {247332343d20222e63}
		 $hex186= {24733235303d202255}
		 $hex187= {24733235313d202255}
		 $hex188= {24733235323d202255}
		 $hex189= {24733235333d202255}
		 $hex190= {24733235343d202255}
		 $hex191= {24733235353d202255}
		 $hex192= {24733235363d202255}
		 $hex193= {24733235373d202255}
		 $hex194= {24733235383d202255}
		 $hex195= {24733235393d20222e}
		 $hex196= {247332353d20222e63}
		 $hex197= {24733236303d20222e}
		 $hex198= {24733236313d20222e}
		 $hex199= {24733236323d20222e}
		 $hex200= {24733236333d20222e}
		 $hex201= {24733236343d20222e}
		 $hex202= {24733236353d20222e}
		 $hex203= {24733236363d20222e}
		 $hex204= {24733236373d20222e}
		 $hex205= {24733236383d20222e}
		 $hex206= {24733236393d20222e}
		 $hex207= {247332363d20222e63}
		 $hex208= {24733237303d20222e}
		 $hex209= {24733237313d20222e}
		 $hex210= {24733237323d20222e}
		 $hex211= {24733237333d20222e}
		 $hex212= {24733237343d20222e}
		 $hex213= {24733237353d20222e}
		 $hex214= {24733237363d20222e}
		 $hex215= {24733237373d20222e}
		 $hex216= {24733237383d20222e}
		 $hex217= {24733237393d20222e}
		 $hex218= {247332373d20222e63}
		 $hex219= {24733238303d20222e}
		 $hex220= {24733238313d20222e}
		 $hex221= {24733238323d202257}
		 $hex222= {24733238333d202257}
		 $hex223= {24733238343d202257}
		 $hex224= {24733238353d202257}
		 $hex225= {24733238363d202257}
		 $hex226= {24733238373d202257}
		 $hex227= {24733238383d202258}
		 $hex228= {24733238393d202258}
		 $hex229= {247332383d2022436f}
		 $hex230= {24733239303d202258}
		 $hex231= {24733239313d202258}
		 $hex232= {24733239323d202258}
		 $hex233= {24733239333d202258}
		 $hex234= {24733239343d202258}
		 $hex235= {24733239353d202258}
		 $hex236= {24733239363d202278}
		 $hex237= {24733239373d202278}
		 $hex238= {24733239383d202278}
		 $hex239= {24733239393d202278}
		 $hex240= {247332393d20222e63}
		 $hex241= {2473323d20222e6161}
		 $hex242= {24733330303d202278}
		 $hex243= {24733330313d202278}
		 $hex244= {24733330323d202278}
		 $hex245= {24733330333d202278}
		 $hex246= {24733330343d202278}
		 $hex247= {24733330353d202278}
		 $hex248= {24733330363d20222e}
		 $hex249= {24733330373d20222e}
		 $hex250= {24733330383d20222e}
		 $hex251= {24733330393d20222e}
		 $hex252= {247333303d20222e63}
		 $hex253= {24733331303d20222e}
		 $hex254= {24733331313d202278}
		 $hex255= {24733331323d20222e}
		 $hex256= {24733331333d20222e}
		 $hex257= {24733331343d20222e}
		 $hex258= {24733331353d20222e}
		 $hex259= {24733331363d20222e}
		 $hex260= {24733331373d20222e}
		 $hex261= {247333313d20222e63}
		 $hex262= {247333323d20222e63}
		 $hex263= {247333333d20222e63}
		 $hex264= {247333343d20224352}
		 $hex265= {247333353d20224352}
		 $hex266= {247333363d20224352}
		 $hex267= {247333373d20226373}
		 $hex268= {247333383d20222e64}
		 $hex269= {247333393d20222e64}
		 $hex270= {2473333d20222e6161}
		 $hex271= {247334303d20222e64}
		 $hex272= {247334313d20222e64}
		 $hex273= {247334323d20222e64}
		 $hex274= {247334333d20222e64}
		 $hex275= {247334343d20222e64}
		 $hex276= {247334353d2022446f}
		 $hex277= {247334363d2022446f}
		 $hex278= {247334373d20222e64}
		 $hex279= {247334383d20226562}
		 $hex280= {247334393d20222e65}
		 $hex281= {2473343d20222e6161}
		 $hex282= {247335303d20222e65}
		 $hex283= {247335313d20224556}
		 $hex284= {247335323d20224556}
		 $hex285= {247335333d20224556}
		 $hex286= {247335343d20224556}
		 $hex287= {247335353d20224556}
		 $hex288= {247335363d20224556}
		 $hex289= {247335373d20224556}
		 $hex290= {247335383d20224556}
		 $hex291= {247335393d20224556}
		 $hex292= {2473353d20222e6162}
		 $hex293= {247336303d20224556}
		 $hex294= {247336313d20224556}
		 $hex295= {247336323d20224556}
		 $hex296= {247336333d20224556}
		 $hex297= {247336343d20224556}
		 $hex298= {247336353d20224556}
		 $hex299= {247336363d20224556}
		 $hex300= {247336373d20224556}
		 $hex301= {247336383d20224556}
		 $hex302= {247336393d20224556}
		 $hex303= {2473363d20222e6163}
		 $hex304= {247337303d20224556}
		 $hex305= {247337313d20224556}
		 $hex306= {247337323d20224556}
		 $hex307= {247337333d20222e65}
		 $hex308= {247337343d20224578}
		 $hex309= {247337353d20224578}
		 $hex310= {247337363d20222e66}
		 $hex311= {247337373d20222e66}
		 $hex312= {247337383d20222e66}
		 $hex313= {247337393d20224765}
		 $hex314= {2473373d2022416371}
		 $hex315= {247338303d20222e67}
		 $hex316= {247338313d20222e68}
		 $hex317= {247338323d20222e68}
		 $hex318= {247338333d20226874}
		 $hex319= {247338343d20226874}
		 $hex320= {247338353d20226874}
		 $hex321= {247338363d20226874}
		 $hex322= {247338373d20226932}
		 $hex323= {247338383d20222e69}
		 $hex324= {247338393d20222e69}
		 $hex325= {2473383d20222e6169}
		 $hex326= {247339303d2022496e}
		 $hex327= {247339313d2022496e}
		 $hex328= {247339323d2022496e}
		 $hex329= {247339333d20222e69}
		 $hex330= {247339343d20224953}
		 $hex331= {247339353d20224953}
		 $hex332= {247339363d20224953}
		 $hex333= {247339373d20224953}
		 $hex334= {247339383d20222e69}
		 $hex335= {247339393d20222e6a}
		 $hex336= {2473393d20222e616c}

	condition:
		224 of them
}
