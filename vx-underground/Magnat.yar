
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Magnat 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Magnat {
	meta: 
		 description= "vx_underground2_Magnat Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-10-39" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0fd5f285429395c1cbba43fdadcbbc4c"
		 hash2= "105e630c564f94d5d319b0d7575c114c"
		 hash3= "18280c16442216d8baebdcc253c13cfd"
		 hash4= "1e50206755319031dd6605552abd13e9"
		 hash5= "29b99f2547aae335a6731d3c590940ee"
		 hash6= "3c3e5f1195199410cee00c6bdceaea70"
		 hash7= "554aca311aef00b0570c12e8fd8d99cf"
		 hash8= "5e38d079333555bc9dcee024e038157c"
		 hash9= "61c54006c5c0ca3979c46b10036072d2"
		 hash10= "6668eb5420bf73654bc097f03cde7ab9"
		 hash11= "75e865f52859b62fb37533edf16f002d"
		 hash12= "7aaa757fa6b13340fa16c6c7eebb0c0f"
		 hash13= "8ddc4a228141b2459d6ae591c3b489c5"
		 hash14= "95c903da33ce721513a0c0ef531a09fb"
		 hash15= "9a3a57198f755e211d4be90a33320fcd"
		 hash16= "a001a93370e1a9796dcf95354273a110"
		 hash17= "aad78c0a09b378b1dcb210ba70456f59"
		 hash18= "b87f4d87da77365385819a9343b12ba7"
		 hash19= "bcf42b43d7ad95c921a129398d6382fd"
		 hash20= "c83af25b2ea00136554bafbd9bacff40"
		 hash21= "c840b83c441df8e761d53bae54bd657b"
		 hash22= "c85f80e8661c91340857d8ac868c95bb"
		 hash23= "cb153264fa4897f3db93a6f66fd91e7e"
		 hash24= "cf4bacc6ab225e6967a62ff54641ce42"
		 hash25= "d538b82a1b5ef585a9443512ca927033"
		 hash26= "dd350bc940b7c29221da31bcad52aa3c"
		 hash27= "ddcfc616fbb12ce8c8637516e9f7eb9f"
		 hash28= "e13dbfe3c647337c845e723dc9c1fb22"
		 hash29= "e470145bbc9104afcb27d5ecf109e863"
		 hash30= "e78cece14790e41bd1eac5a19ed3fb4b"
		 hash31= "e988d1994581870c6aac979f87ab2a5c"
		 hash32= "ebf1d9fce1d772bc12fff7e67240ec9b"
		 hash33= "f1fa27f78a8ded54bd94ac59b44d27de"
		 hash34= "f7caae75112060004fb29494cc14d70f"
		 hash35= "fcefd238308924c6efc33ac2b6a679fb"

	strings:

	
 		 $s1= "Control PanelDesktopResourceLocale" fullword wide
		 $s2= "COURSE~STATE~SIMILAR~LEAST~FENCE~CARE^" fullword wide
		 $s3= ".DEFAULTControl PanelInternational" fullword wide
		 $s4= "EXTRACTOPT FILESIZES FINISHMSG" fullword wide
		 $s5= "FSoftwareAutoIt v3AutoIt" fullword wide
		 $s6= "GUICTRLCREATELISTVIEWITEM" fullword wide
		 $s7= "GUICTRLCREATETREEVIEWITEM" fullword wide
		 $s8= "GUICTRLREGISTERLISTVIEWSORT" fullword wide
		 $s9= "http://nsis.sf.net/NSIS_Error" fullword wide
		 $s10= "SeAssignPrimaryTokenPrivilege" fullword wide
		 $s11= "SoftwareMicrosoftWindowsCurrentVersion" fullword wide
		 $s12= "SYSTEMCurrentControlSetControlNlsLanguage" fullword wide
		 $a1= "3861102017828998956061751690077967064031008804895134763044183861" fullword ascii
		 $a2= "8z1}0}0r7s28998w5c0{1{5~6z0{779f7q6a0`1u088s4y9e1`4{6|0w4z83861" fullword ascii
		 $a3= "9007796706403100880489513476304418386110201782899895606175)tp0" fullword ascii
		 $a4= "|dfd`dabf`jbmmlnmPPU[V]_^PP_][_XE@DJDEA@AOMKJINL1[0]8B4V9P1_4" fullword ascii
		 $a5= "http://cacerts.digicert.com/DigiCertEVCodeSigningCA-SHA2.crt0" fullword ascii
		 $a6= "http://secure.globalsign.com/cacert/gstimestampingsha2g2.crt0" fullword ascii
		 $a7= "pUZZQTUS__Y[XY_WCIDBEEDGINBiddggYTTSRTQRY_S[ZYVFFBE@EEFHIBCLIFF" fullword ascii
		 $a8= "sYTRUUTWY^RYTTWWIDDCBDABIOCkljifVvrupuuvxyrs|yvve`agcceglmkCOEHN" fullword ascii
		 $a9= "sytruutwy~ryttwwiddcbdabiockljifVvrupuuvxyrs|yvve`agcceglmkCOEHN" fullword ascii

		 $hex1= {2461313d2022333836}
		 $hex2= {2461323d2022387a31}
		 $hex3= {2461333d2022393030}
		 $hex4= {2461343d20227c6466}
		 $hex5= {2461353d2022687474}
		 $hex6= {2461363d2022687474}
		 $hex7= {2461373d202270555a}
		 $hex8= {2461383d2022735954}
		 $hex9= {2461393d2022737974}
		 $hex10= {247331303d20225365}
		 $hex11= {247331313d2022536f}
		 $hex12= {247331323d20225359}
		 $hex13= {2473313d2022436f6e}
		 $hex14= {2473323d2022434f55}
		 $hex15= {2473333d20222e4445}
		 $hex16= {2473343d2022455854}
		 $hex17= {2473353d202246536f}
		 $hex18= {2473363d2022475549}
		 $hex19= {2473373d2022475549}
		 $hex20= {2473383d2022475549}
		 $hex21= {2473393d2022687474}

	condition:
		14 of them
}
