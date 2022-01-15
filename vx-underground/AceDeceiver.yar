
/*
   YARA Rule Set
   Author: resteex
   Identifier: AceDeceiver 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_AceDeceiver {
	meta: 
		 description= "AceDeceiver Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-12_23-45-41" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1107c445289b2ac3912a9b4419c48f58"
		 hash2= "1dc2584cd2c167907ae547bd4b040710"
		 hash3= "2fbdfd6a94af3ad388450ccd4fbe4fe4"
		 hash4= "310acf02b0b5e748a2de353448904445"
		 hash5= "3652db89ace912e15628b45b80cf389a"
		 hash6= "3c1406453dbec9284caa1a10b4a83fd7"
		 hash7= "41e820885d1cc951a848fd586be3e894"
		 hash8= "5d9b59db4b8cc84bd2e14f9e1768fb87"
		 hash9= "5e74324567ab4ebe47044337beec6f99"
		 hash10= "6614bd786cd5e7d0c7fd419cf7cd79ac"
		 hash11= "6a6d7ee4d87d824340e8e08c34ed7891"
		 hash12= "7fde49574366e059d0454bdefceb1434"
		 hash13= "96724f179c3afd44ddcc60bed4a4089d"
		 hash14= "99910c48e7fc3bae3393013c8c797f43"
		 hash15= "a3b156f679a915c0c7a255151d73965b"
		 hash16= "a63124c34c6d5b4b33113af4288e248c"
		 hash17= "c1c335b98209ffa9336db47bfc0eea36"
		 hash18= "c6523b9cbce3dacd966ee7fac64e851a"
		 hash19= "c79492a303547697453438d321af4c50"
		 hash20= "d3186cb98e898c5364fa23b710ff1da4"
		 hash21= "d6f664197eadfd8e080ccc0bbeee6e1e"
		 hash22= "e2f05253fd536c7e01f6e0a4ce2b2b34"
		 hash23= "e777707b967cd2c4a312064397a5ef5c"
		 hash24= "ebfcecf97992fe3e707786462abb4fce"

	strings:

	
 		 $s1= "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}" fullword wide
		 $s2= "405096f6-8d6a-4957-a44c-fd4657a4fbf5" fullword wide
		 $s3= "file='messagebox_icon_48x48.png' source='0,0,48,48'" fullword wide
		 $s4= "file='messagebox_icon_48x48.png' source='0,144,48,192'" fullword wide
		 $s5= "file='messagebox_icon_48x48.png' source='0,48,48,96'" fullword wide
		 $s6= "file='messagebox_icon_48x48.png' source='0,96,48,144'" fullword wide
		 $s7= "file='tabel_header_Arrow.png' source='0,0,30,30'" fullword wide
		 $s8= "file='tabel_header_Arrow.png' source='0,30,30,60'" fullword wide
		 $s9= "grotation_loading_flash_260x260.png" fullword wide
		 $s10= "gvedio_convert_icon_del_20x20.png.png" fullword wide
		 $s11= "Head_label_icon_wallpaper_36x36.png" fullword wide
		 $s12= "http://app3.i4.cn/log/info/uploadActiveInfo.go?type=5" fullword wide
		 $s13= "http://app3.i4.cn/log/info/uploadLogFile.go" fullword wide
		 $s14= "http://www.i4.cn/newsContent-1854.html" fullword wide
		 $s15= "MicrosoftInternet ExplorerQuick Launch" fullword wide
		 $s16= "MismatchedApplicationIdentifierEntitlement" fullword wide
		 $s17= "mobileLibraryCachescom.apple.mobile.installation.plist" fullword wide
		 $s18= "privatevarmobileLibrarySMSsms.db" fullword wide
		 $s19= "privatevarmobileLibrarySMSsms.db-shm" fullword wide
		 $s20= "privatevarmobileLibrarySMSsms.db-wal" fullword wide
		 $s21= "%scacheCrashReporti4Tools_%04d%02d%02d-%02d%02d%02d.dmp" fullword wide
		 $s22= "SOFTWAREApple Computer, Inc.iPodRegisteredApps4" fullword wide
		 $s23= "SoftwareClasses%sshelli4Toolscommand" fullword wide
		 $s24= "SOFTWAREMicrosoftInternet Explorer" fullword wide
		 $s25= "SoftwareMicrosoftWindowsCurrentVersionApp PathsiTunes.exe" fullword wide
		 $s26= "SoftwareMicrosoftWindowsCurrentVersionExplorerFileExts.ipa" fullword wide
		 $s27= "SOFTWAREMicrosoftWindowsCurrentVersionUninstall" fullword wide
		 $s28= "%svarmobileLibraryCachescom.apple.mobile.installation.plist" fullword wide
		 $s29= "tools_icon_contactDeduplication_20x20.png" fullword wide
		 $a1= "?File2Dev@FileMgr@@QAEHAAV?$basic_string@GU?$char_traits@G@std@@V?$allocator@G@2@@std@@AAV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@3@@Z" fullword ascii
		 $a2= "%@getversioninfo.xhtml?%@&isAuth=%@&toolversion=%@&lastShowTime=%@&cid=%@&isjail=%@&authortype=%@&update=%@&serialnumber=%s&reachability=%@&bindaid=%d" fullword ascii
		 $a3= "idfa=%@&idfv=%@&openudid=%@&osversion=%@&udid=%@&macaddress=%@&model=%@&certificateid=%@&bundleid=%@&isAuth=%@&isjail=%@&authtime=%@&serialnumber=%s&c" fullword ascii
		 $a4= "setupCallback.xhtml?%@&toolversion=%@&appid=%@&isAuth=%@&remd=%@&cid=%@&isjail=%@&remdorder=%@&pkagetype=%ld&sort=%@&specialid=%@&type=%@&appdetail=1%" fullword ascii
		 $a5= "v16@0:4^{_xmlNode=^vi*^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlDoc}^{_xmlNs}*^{_xmlAttr}^{_xmlNs}^vSS}8^{_xmlNode=^vi*^{_xmlNode}^" fullword ascii
		 $a6= "v16@0:4^{_xmlNs=^{_xmlNs}i**^v^{_xmlDoc}}8^{_xmlNode=^vi*^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlDoc}^{_xmlNs}*^{_xmlAttr}^{_xmlN" fullword ascii
		 $a7= "v20@0:4^{_xmlNode=^vi*^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlDoc}^{_xmlNs}*^{_xmlAttr}^{_xmlNs}^vSS}8^{_xmlNode=^vi*^{_xmlNode}^" fullword ascii
		 $a8= "v32@0:8^{_xmlNode=^vi*^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlDoc}^{_xmlNs}*^{_xmlAttr}^{_xmlNs}^vSS}16^{_xmlNode=^vi*^{_xmlNode}" fullword ascii
		 $a9= "v32@0:8^{_xmlNs=^{_xmlNs}i**^v^{_xmlDoc}}16^{_xmlNode=^vi*^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlDoc}^{_xmlNs}*^{_xmlAttr}^{_xml" fullword ascii
		 $a10= "v40@0:8^{_xmlNode=^vi*^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlDoc}^{_xmlNs}*^{_xmlAttr}^{_xmlNs}^vSS}16^{_xmlNode=^vi*^{_xmlNode}" fullword ascii

		 $hex1= {246131303d20227634}
		 $hex2= {2461313d20223f4669}
		 $hex3= {2461323d2022254067}
		 $hex4= {2461333d2022696466}
		 $hex5= {2461343d2022736574}
		 $hex6= {2461353d2022763136}
		 $hex7= {2461363d2022763136}
		 $hex8= {2461373d2022763230}
		 $hex9= {2461383d2022763332}
		 $hex10= {2461393d2022763332}
		 $hex11= {247331303d20226776}
		 $hex12= {247331313d20224865}
		 $hex13= {247331323d20226874}
		 $hex14= {247331333d20226874}
		 $hex15= {247331343d20226874}
		 $hex16= {247331353d20224d69}
		 $hex17= {247331363d20224d69}
		 $hex18= {247331373d20226d6f}
		 $hex19= {247331383d20227072}
		 $hex20= {247331393d20227072}
		 $hex21= {2473313d20227b2530}
		 $hex22= {247332303d20227072}
		 $hex23= {247332313d20222573}
		 $hex24= {247332323d2022534f}
		 $hex25= {247332333d2022536f}
		 $hex26= {247332343d2022534f}
		 $hex27= {247332353d2022536f}
		 $hex28= {247332363d2022536f}
		 $hex29= {247332373d2022534f}
		 $hex30= {247332383d20222573}
		 $hex31= {247332393d2022746f}
		 $hex32= {2473323d2022343035}
		 $hex33= {2473333d202266696c}
		 $hex34= {2473343d202266696c}
		 $hex35= {2473353d202266696c}
		 $hex36= {2473363d202266696c}
		 $hex37= {2473373d202266696c}
		 $hex38= {2473383d202266696c}
		 $hex39= {2473393d202267726f}

	condition:
		4 of them
}
