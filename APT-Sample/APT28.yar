
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
		 date = "2022-03-22_12-17-49" 
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

		 $hex1= {2f7861703a43726561}
		 $hex2= {2f7861703a4d6f6469}
		 $hex3= {4163636570742d456e}
		 $hex4= {4273214a7321427321}
		 $hex5= {4273214a7b21427321}
		 $hex6= {446f63756d656e742e}
		 $hex7= {446f63756d656e7453}
		 $hex8= {4a7b214a73214a7b29}
		 $hex9= {4a7b294a73214a7b21}
		 $hex10= {534f4654574152454d}
		 $hex11= {536553797374656d45}
		 $hex12= {536f6674776172654d}
		 $hex13= {5461626c655374796c}
		 $hex14= {555f693d56606a3e57}
		 $hex15= {5f5f5a4c33325f5f61}
		 $hex16= {5f5f5a4c33365f5f61}
		 $hex17= {5f5f5a4c34335f5f61}
		 $hex18= {5f5f5a4c34345f5f61}
		 $hex19= {636364636f652d636d}
		 $hex20= {656e61626c655f636f}
		 $hex21= {656e61626c655f6564}
		 $hex22= {7b3038344630314641}
		 $hex23= {7b3842453444463631}
		 $hex24= {7b4146394646443637}

	condition:
		4 of them
}
