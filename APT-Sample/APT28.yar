
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
		 date = "2022-03-27_08-10-04" 
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

		 $hex1= {2f??78??61??70??3a??43??72??65??61??74??65??44??61??74??65??3e??0a??}
		 $hex2= {2f??78??61??70??3a??4d??6f??64??69??66??79??44??61??74??65??3e??0a??}
		 $hex3= {41??63??63??65??70??74??2d??45??6e??63??6f??64??69??6e??67??3a??20??67??7a??69??70??2c??64??65??66??6c??61??74??65??2c??}
		 $hex4= {42??73??21??4a??73??21??42??73??21??4a??7b??21??42??73??21??4a??73??21??42??73??21??4a??7b??21??42??73??21??4a??73??21??}
		 $hex5= {42??73??21??4a??7b??21??42??73??21??4a??73??21??42??73??21??4a??7b??21??42??73??21??4a??73??21??42??73??21??4a??7b??21??}
		 $hex6= {44??6f??63??75??6d??65??6e??74??2e??4e??65??77??4d??61??63??72??6f??73??2e??41??75??74??6f??4f??70??65??6e??0a??}
		 $hex7= {44??6f??63??75??6d??65??6e??74??53??75??6d??6d??61??72??79??49??6e??66??6f??72??6d??61??74??69??6f??6e??0a??}
		 $hex8= {4a??7b??21??4a??73??21??4a??7b??29??4a??73??21??4a??7b??21??4a??73??21??4a??7b??29??4a??73??21??4a??7b??21??4a??73??21??}
		 $hex9= {4a??7b??29??4a??73??21??4a??7b??21??4a??73??21??4a??7b??29??4a??73??21??4a??7b??21??4a??73??21??4a??7b??29??4a??73??21??}
		 $hex10= {53??4f??46??54??57??41??52??45??4d??69??63??72??6f??73??6f??66??74??56??69??73??75??61??6c??53??74??75??64??69??6f??31??}
		 $hex11= {53??4f??46??54??57??41??52??45??4d??69??63??72??6f??73??6f??66??74??57??69??6e??64??6f??77??73??20??4e??54??43??75??72??}
		 $hex12= {53??65??53??79??73??74??65??6d??45??6e??76??69??72??6f??6e??6d??65??6e??74??50??72??69??76??69??6c??65??67??65??0a??}
		 $hex13= {53??6f??66??74??77??61??72??65??4d??69??63??72??6f??73??6f??66??74??57??69??6e??64??6f??77??73??43??75??72??72??65??6e??}
		 $hex14= {54??61??62??6c??65??53??74??79??6c??65??4d??65??64??69??75??6d??32??50??69??76??6f??74??53??74??79??6c??65??4c??69??67??}
		 $hex15= {55??5f??69??3d??56??60??6a??3e??57??61??6b??3f??58??62??6c??40??59??63??6d??41??5a??64??6e??42??5b??65??6f??43??66??70??}
		 $hex16= {5f??5f??5a??4c??33??32??5f??5f??61??72??63??6c??69??74??65??5f??6f??62??6a??63??5f??61??6c??6c??6f??63??61??74??65??43??}
		 $hex17= {5f??5f??5a??4c??33??36??5f??5f??61??72??63??6c??69??74??65??5f??6f??62??6a??65??63??74??5f??73??65??74??49??6e??73??74??}
		 $hex18= {5f??5f??5a??4c??34??33??5f??5f??61??72??63??6c??69??74??65??5f??6f??62??6a??63??5f??72??65??74??61??69??6e??41??75??74??}
		 $hex19= {5f??5f??5a??4c??34??34??5f??5f??61??72??63??6c??69??74??65??5f??6f??62??6a??63??5f??72??65??74??61??69??6e??41??75??74??}
		 $hex20= {63??63??64??63??6f??65??2d??63??6d??79??6b??5f??68??6f??72??69??7a??6f??6e??74??61??6c??2d??73??68??6f??72??74??0a??}
		 $hex21= {65??6e??61??62??6c??65??5f??63??6f??6e??74??65??6e??74??5f??6f??6e??6c??79??5f??62??75??74??74??6f??6e??0a??}
		 $hex22= {65??6e??61??62??6c??65??5f??65??64??69??74??69??6e??67??5f??6f??6e??6c??79??5f??62??75??74??74??6f??6e??0a??}
		 $hex23= {7b??30??38??34??46??30??31??46??41??2d??45??36??33??34??2d??34??44??37??37??2d??38??33??45??45??2d??30??37??34??38??31??}
		 $hex24= {7b??38??42??45??34??44??46??36??31??2d??39??33??43??41??2d??31??31??44??32??2d??41??41??30??44??2d??30??30??45??30??39??}
		 $hex25= {7b??41??46??39??46??46??44??36??37??2d??45??43??31??30??2d??34??38??38??41??2d??39??44??46??43??2d??36??43??42??46??35??}

	condition:
		27 of them
}