
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
		 date = "2022-01-13_15-15-39" 
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

		 $hex1= {247331303d20222e6b}
		 $hex2= {247331313d20222e6b}
		 $hex3= {247331323d20222e6d}
		 $hex4= {247331333d20222e6f}
		 $hex5= {247331343d20222e6f}
		 $hex6= {247331353d20222e6f}
		 $hex7= {247331363d20222e6f}
		 $hex8= {247331373d20222e6f}
		 $hex9= {247331383d20222e6f}
		 $hex10= {247331393d20222e6f}
		 $hex11= {2473313d2022323142}
		 $hex12= {247332303d20222e6f}
		 $hex13= {247332313d20222e6f}
		 $hex14= {247332323d20222e6f}
		 $hex15= {247332333d20222e6f}
		 $hex16= {247332343d20222e6f}
		 $hex17= {247332353d20222e6f}
		 $hex18= {247332363d20222e6f}
		 $hex19= {247332373d20222e70}
		 $hex20= {247332383d20222e70}
		 $hex21= {247332393d20222e70}
		 $hex22= {2473323d20227b3433}
		 $hex23= {247333303d20225045}
		 $hex24= {247333313d20225045}
		 $hex25= {247333323d20222e72}
		 $hex26= {247333333d20222e72}
		 $hex27= {247333343d20222e72}
		 $hex28= {247333353d20222e72}
		 $hex29= {247333363d20222e73}
		 $hex30= {247333373d20222e73}
		 $hex31= {247333383d20222e73}
		 $hex32= {247333393d20222e73}
		 $hex33= {2473333d2022355641}
		 $hex34= {247334303d20222e73}
		 $hex35= {247334313d20222e73}
		 $hex36= {247334323d20222e73}
		 $hex37= {247334333d2022534f}
		 $hex38= {247334343d2022534f}
		 $hex39= {247334353d20225353}
		 $hex40= {247334363d20222e73}
		 $hex41= {247334373d20222e73}
		 $hex42= {247334383d20222e73}
		 $hex43= {247334393d20222e73}
		 $hex44= {2473343d2022617070}
		 $hex45= {247335303d20222e73}
		 $hex46= {247335313d20222e73}
		 $hex47= {247335323d20222e73}
		 $hex48= {247335333d20222e73}
		 $hex49= {247335343d20222e73}
		 $hex50= {247335353d20225359}
		 $hex51= {247335363d20225379}
		 $hex52= {247335373d20222e74}
		 $hex53= {247335383d20222e74}
		 $hex54= {247335393d20227465}
		 $hex55= {2473353d20222e6361}
		 $hex56= {247336303d20222e74}
		 $hex57= {247336313d20222e74}
		 $hex58= {247336323d20222e76}
		 $hex59= {247336333d20222e77}
		 $hex60= {247336343d20222e78}
		 $hex61= {247336353d20222e78}
		 $hex62= {2473363d2022457874}
		 $hex63= {2473373d2022457874}
		 $hex64= {2473383d20222e666d}
		 $hex65= {2473393d2022497354}

	condition:
		8 of them
}
