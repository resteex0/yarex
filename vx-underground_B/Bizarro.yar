
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
		 date = "2022-01-14_00-18-40" 
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

	
 		 $s1= "21BA7CB35B98CD629245E527DD0734E14288BE01" fullword wide
		 $s2= "{43826D1E-E718-42EE-BC55-A1E261C37BFE}" fullword wide
		 $s3= "5VANV4SDMC3VEAFR8S2M3M9U6WRH3P7FDD9T9Q10IAG5WZJ5K5" fullword wide
		 $s4= "application/xml-external-parsed-entity" fullword wide
		 $s5= ".cab=application/vnd.ms-cab-compressed" fullword wide
		 $s6= "Extended_UNIX_Code_Fixed_Width_for_Japanese" fullword wide
		 $s7= "Extended_UNIX_Code_Packed_Format_for_Japanese" fullword wide
		 $s8= ".fml=application/x-file-mirror-list" fullword wide
		 $s9= "IsThemeBackgroundPartiallyTransparent" fullword wide
		 $s10= ".kpr=application/vnd.kde.kpresenter" fullword wide
		 $s11= ".kpt=application/vnd.kde.kpresenter" fullword wide
		 $s12= ".mjf=audio/x-vnd.AudioExplosion.MjuiceMediaFile" fullword wide
		 $s13= ".odb=application/vnd.oasis.opendocument.database" fullword wide
		 $s14= ".odc=application/vnd.oasis.opendocument.chart" fullword wide
		 $s15= ".odf=application/vnd.oasis.opendocument.formula" fullword wide
		 $s16= ".odg=application/vnd.oasis.opendocument.graphics" fullword wide
		 $s17= ".odi=application/vnd.oasis.opendocument.image" fullword wide
		 $s18= ".odm=application/vnd.oasis.opendocument.text-master" fullword wide
		 $s19= ".odp=application/vnd.oasis.opendocument.presentation" fullword wide
		 $s20= ".ods=application/vnd.oasis.opendocument.spreadsheet" fullword wide
		 $s21= ".odt=application/vnd.oasis.opendocument.text" fullword wide
		 $s22= ".otg=application/vnd.oasis.opendocument.graphics-template" fullword wide
		 $s23= ".oth=application/vnd.oasis.opendocument.text-web" fullword wide
		 $s24= ".otp=application/vnd.oasis.opendocument.presentation-template" fullword wide
		 $s25= ".ots=application/vnd.oasis.opendocument.spreadsheet-template" fullword wide
		 $s26= ".ott=application/vnd.oasis.opendocument.text-template" fullword wide
		 $s27= ".p7b=application/x-pkcs7-certificates" fullword wide
		 $s28= ".p7r=application/x-pkcs7-certreqresp" fullword wide
		 $s29= ".package=application/vnd.autopackage" fullword wide
		 $s30= "PEM_read_bio_NETSCAPE_CERT_SEQUENCE" fullword wide
		 $s31= "PEM_write_bio_NETSCAPE_CERT_SEQUENCE" fullword wide
		 $s32= ".rjs=application/vnd.rn-realsystem-rjs" fullword wide
		 $s33= ".rmp=application/vnd.rn-rn_music_package" fullword wide
		 $s34= ".rmx=application/vnd.rn-realsystem-rmx" fullword wide
		 $s35= ".rpm=application/x-redhat-package-manager" fullword wide
		 $s36= ".sda=application/vnd.stardivision.draw" fullword wide
		 $s37= ".sdc=application/vnd.stardivision.calc" fullword wide
		 $s38= ".sdd=application/vnd.stardivision.impress" fullword wide
		 $s39= ".ser=application/java-serialized-object" fullword wide
		 $s40= ".setpay=application/set-payment-initiation" fullword wide
		 $s41= ".setreg=application/set-registration-initiation" fullword wide
		 $s42= ".smf=application/vnd.stardivision.math" fullword wide
		 $s43= "SOFTWAREMicrosoftWindows NTCurrentVersion" fullword wide
		 $s44= "SOFTWAREMicrosoftWindows NTCurrentVersionFontSubstitutes" fullword wide
		 $s45= "SSL_CTX_set_default_passwd_cb_userdata" fullword wide
		 $s46= ".sst=application/vnd.ms-pki.certstore" fullword wide
		 $s47= ".stc=application/vnd.sun.xml.calc.template" fullword wide
		 $s48= ".std=application/vnd.sun.xml.draw.template" fullword wide
		 $s49= ".sti=application/vnd.sun.xml.impress.template" fullword wide
		 $s50= ".stw=application/vnd.sun.xml.writer.template" fullword wide
		 $s51= ".swf1=application/x-shockwave-flash" fullword wide
		 $s52= ".sxg=application/vnd.sun.xml.writer.global" fullword wide
		 $s53= ".sxi=application/vnd.sun.xml.impress" fullword wide
		 $s54= ".sxw=application/vnd.sun.xml.writer" fullword wide
		 $s55= "SYSTEMCurrentControlSetControlKeyboard Layouts" fullword wide
		 $s56= "SystemCurrentControlSetControlKeyboard Layouts%.8x" fullword wide
		 $s57= ".tbz2=application/x-bzip-compressed-tar" fullword wide
		 $s58= ".tbz=application/x-bzip-compressed-tar" fullword wide
		 $s59= "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" fullword wide
		 $s60= ".tlz=application/x-lzma-compressed-tar" fullword wide
		 $s61= ".txz=application/x-xz-compressed-tar" fullword wide
		 $s62= ".vor=application/vnd.stardivision.writer" fullword wide
		 $s63= ".wmlsc=application/vnd.wap.wmlscriptc" fullword wide
		 $s64= ".xps=application/vnd.ms-xpsdocument" fullword wide
		 $s65= ".xul=application/vnd.mozilla.xul+xml" fullword wide
		 $a1= "5VANV4SDMC3VEAFR8S2M3M9U6WRH3P7FDD9T9Q10IAG5WZJ5K5" fullword ascii
		 $a2= ".odm=application/vnd.oasis.opendocument.text-master" fullword ascii
		 $a3= ".odp=application/vnd.oasis.opendocument.presentation" fullword ascii
		 $a4= ".ods=application/vnd.oasis.opendocument.spreadsheet" fullword ascii
		 $a5= ".otg=application/vnd.oasis.opendocument.graphics-template" fullword ascii
		 $a6= ".otp=application/vnd.oasis.opendocument.presentation-template" fullword ascii
		 $a7= ".ots=application/vnd.oasis.opendocument.spreadsheet-template" fullword ascii
		 $a8= ".ott=application/vnd.oasis.opendocument.text-template" fullword ascii
		 $a9= "SOFTWAREMicrosoftWindows NTCurrentVersionFontSubstitutes" fullword ascii
		 $a10= "SYSTEMCurrentControlSetControlKeyboard Layouts" fullword ascii
		 $a11= "SystemCurrentControlSetControlKeyboard Layouts%.8x" fullword ascii
		 $a12= "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" fullword ascii

		 $hex1= {246131303d20225359}
		 $hex2= {246131313d20225379}
		 $hex3= {246131323d20227465}
		 $hex4= {2461313d2022355641}
		 $hex5= {2461323d20222e6f64}
		 $hex6= {2461333d20222e6f64}
		 $hex7= {2461343d20222e6f64}
		 $hex8= {2461353d20222e6f74}
		 $hex9= {2461363d20222e6f74}
		 $hex10= {2461373d20222e6f74}
		 $hex11= {2461383d20222e6f74}
		 $hex12= {2461393d2022534f46}
		 $hex13= {247331303d20222e6b}
		 $hex14= {247331313d20222e6b}
		 $hex15= {247331323d20222e6d}
		 $hex16= {247331333d20222e6f}
		 $hex17= {247331343d20222e6f}
		 $hex18= {247331353d20222e6f}
		 $hex19= {247331363d20222e6f}
		 $hex20= {247331373d20222e6f}
		 $hex21= {247331383d20222e6f}
		 $hex22= {247331393d20222e6f}
		 $hex23= {2473313d2022323142}
		 $hex24= {247332303d20222e6f}
		 $hex25= {247332313d20222e6f}
		 $hex26= {247332323d20222e6f}
		 $hex27= {247332333d20222e6f}
		 $hex28= {247332343d20222e6f}
		 $hex29= {247332353d20222e6f}
		 $hex30= {247332363d20222e6f}
		 $hex31= {247332373d20222e70}
		 $hex32= {247332383d20222e70}
		 $hex33= {247332393d20222e70}
		 $hex34= {2473323d20227b3433}
		 $hex35= {247333303d20225045}
		 $hex36= {247333313d20225045}
		 $hex37= {247333323d20222e72}
		 $hex38= {247333333d20222e72}
		 $hex39= {247333343d20222e72}
		 $hex40= {247333353d20222e72}
		 $hex41= {247333363d20222e73}
		 $hex42= {247333373d20222e73}
		 $hex43= {247333383d20222e73}
		 $hex44= {247333393d20222e73}
		 $hex45= {2473333d2022355641}
		 $hex46= {247334303d20222e73}
		 $hex47= {247334313d20222e73}
		 $hex48= {247334323d20222e73}
		 $hex49= {247334333d2022534f}
		 $hex50= {247334343d2022534f}
		 $hex51= {247334353d20225353}
		 $hex52= {247334363d20222e73}
		 $hex53= {247334373d20222e73}
		 $hex54= {247334383d20222e73}
		 $hex55= {247334393d20222e73}
		 $hex56= {2473343d2022617070}
		 $hex57= {247335303d20222e73}
		 $hex58= {247335313d20222e73}
		 $hex59= {247335323d20222e73}
		 $hex60= {247335333d20222e73}
		 $hex61= {247335343d20222e73}
		 $hex62= {247335353d20225359}
		 $hex63= {247335363d20225379}
		 $hex64= {247335373d20222e74}
		 $hex65= {247335383d20222e74}
		 $hex66= {247335393d20227465}
		 $hex67= {2473353d20222e6361}
		 $hex68= {247336303d20222e74}
		 $hex69= {247336313d20222e74}
		 $hex70= {247336323d20222e76}
		 $hex71= {247336333d20222e77}
		 $hex72= {247336343d20222e78}
		 $hex73= {247336353d20222e78}
		 $hex74= {2473363d2022457874}
		 $hex75= {2473373d2022457874}
		 $hex76= {2473383d20222e666d}
		 $hex77= {2473393d2022497354}

	condition:
		9 of them
}
