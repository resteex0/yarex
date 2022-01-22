
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_APT28 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_APT28 {
	meta: 
		 description= "APT_Sample_APT28 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-22_17-55-02" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "085be1b8b8f3e90be00f6a3bcea2879f"
		 hash2= "10036063be45f92a9a743425fbf5abc7"
		 hash3= "1bcf064650aef06d83484d991bdf6750"
		 hash4= "2c27f24939144655677bb73d2790d668"
		 hash5= "4400ec9c4732a32149ca58e7c5806178"
		 hash6= "4fa6cd01571905b9c7c8fc9a359b655e"
		 hash7= "595aff5212df3534fb8af6a587c6038e"
		 hash8= "5debb3535cba6615526c64e44d0f5e2b"
		 hash9= "60e84516c6ec6dfdae7b422d1f7cab06"
		 hash10= "6e52b4466cf1dcedf82c8f7463114469"
		 hash11= "7f564a6a8910b513a851b2616af8d7ee"
		 hash12= "89503b7935a05b1d26cb26ce3793a3fb"
		 hash13= "8c2f9832b38b4c10f3b5b7924379d599"
		 hash14= "92b90b0208805daaa8ab45fa19d36b14"
		 hash15= "9b10685b774a783eabfecdb6119a8aa3"
		 hash16= "9e7053a4b6c9081220a694ec93211b4e"
		 hash17= "c6e95fb89df8e84eb21b3ce6b8947ce2"
		 hash18= "cc9e6578a47182a941a478b276320e06"
		 hash19= "cffcae5c5551b4b9489fec5d56269d84"
		 hash20= "d1755976a6f7e1cbf21132ac4fdcf553"
		 hash21= "e00216958f15f1db6371b583a3ea438a"
		 hash22= "e8e1fcf757fe06be13bead43eaa1338c"

	strings:

	
 		 $s1= "{084F01FA-E634-4D77-83EE-074817C03581}" fullword wide
		 $s2= "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}" fullword wide
		 $s3= "Accept-Encoding: gzip,deflate,sdch" fullword wide
		 $s4= "{AF9FFD67-EC10-488A-9DFC-6CBF5EE22C2E}" fullword wide
		 $s5= "ccdcoe-cmyk_horizontal-short" fullword wide
		 $s6= "Document.NewMacros.AutoOpen" fullword wide
		 $s7= "DocumentSummaryInformation" fullword wide
		 $s8= "enable_content_only_button" fullword wide
		 $s9= "enable_editing_only_button" fullword wide
		 $s10= "SeSystemEnvironmentPrivilege" fullword wide
		 $s11= "SOFTWAREMicrosoftVisualStudio10.0SetupVS" fullword wide
		 $s12= "TableStyleMedium2PivotStyleLight16" fullword wide
		 $s13= "U_i=V`j>Wak?Xbl@YcmAZdnB[eoCfpD]gq" fullword wide
		 $a1= "Bs!J{!Bs!Js!Bs!J{!Bs!Js!Bs!J{!Bs!Js!Bs!J{!Bs!Js!Bs!J{!Bs!Js!" fullword ascii
		 $a2= "Bs!Js!Bs!J{!Bs!Js!Bs!J{!Bs!Js!Bs!J{!Bs!Js!Bs!J{!Bs!Js!Bs!J{!" fullword ascii
		 $a3= "J{!Js!J{)Js!J{!Js!J{)Js!J{!Js!J{)Js!J{!Js!J{)Js!J{!Js!J{)Js!" fullword ascii
		 $a4= "J{)Js!J{!Js!J{)Js!J{!Js!J{)Js!J{!Js!J{)Js!J{!Js!J{)Js!J{!Js!" fullword ascii
		 $a5= "SoftwareMicrosoftWindowsCurrentVersionApp Pathsiexplore.exe" fullword ascii
		 $a6= "SOFTWAREMicrosoftWindows NTCurrentVersionFontSubstitutes" fullword ascii
		 $a7= "/xap:CreateDate>" fullword ascii
		 $a8= "/xap:ModifyDate>" fullword ascii
		 $a9= "__ZL32__arclite_objc_allocateClassPairP18glue_swift_class_tPKcm" fullword ascii
		 $a10= "__ZL36__arclite_object_setInstanceVariableP11objc_objectPKcPv" fullword ascii
		 $a11= "__ZL43__arclite_objc_retainAutoreleaseReturnValueP11objc_object" fullword ascii
		 $a12= "__ZL44__arclite_objc_retainAutoreleasedReturnValueP11objc_object" fullword ascii

		 $hex1= {246131303d20225f5f}
		 $hex2= {246131313d20225f5f}
		 $hex3= {246131323d20225f5f}
		 $hex4= {2461313d2022427321}
		 $hex5= {2461323d2022427321}
		 $hex6= {2461333d20224a7b21}
		 $hex7= {2461343d20224a7b29}
		 $hex8= {2461353d2022536f66}
		 $hex9= {2461363d2022534f46}
		 $hex10= {2461373d20222f7861}
		 $hex11= {2461383d20222f7861}
		 $hex12= {2461393d20225f5f5a}
		 $hex13= {247331303d20225365}
		 $hex14= {247331313d2022534f}
		 $hex15= {247331323d20225461}
		 $hex16= {247331333d2022555f}
		 $hex17= {2473313d20227b3038}
		 $hex18= {2473323d20227b3842}
		 $hex19= {2473333d2022416363}
		 $hex20= {2473343d20227b4146}
		 $hex21= {2473353d2022636364}
		 $hex22= {2473363d2022446f63}
		 $hex23= {2473373d2022446f63}
		 $hex24= {2473383d2022656e61}
		 $hex25= {2473393d2022656e61}

	condition:
		16 of them
}
