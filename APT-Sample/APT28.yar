
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
		 date = "2022-03-27_12-26-42" 
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

	
 		 $s1= "(1Normal.ThisDocument" fullword wide
		 $s2= "#(-27;@EJOTY^chmrw|" fullword wide
		 $s3= "%)+/5;=CGIOSYaegkmq" fullword wide
		 $s4= "Accept-Encoding: gzip,deflate,sdch" fullword wide
		 $s5= "Access violation" fullword wide
		 $s6= "AcpiGlobalVariable" fullword wide
		 $s7= "Adobe Photoshop" fullword wide
		 $s8= "Application_Win32" fullword wide
		 $s9= "Assertion failed" fullword wide
		 $s10= "August September" fullword wide
		 $s11= "Cache-Control: max-age=0" fullword wide
		 $s12= "ccdcoe-cmyk_horizontal-short" fullword wide
		 $s13= "ccdcoe-cmyk_suured2" fullword wide
		 $s14= "Celda vinculada" fullword wide
		 $s15= "Connection: keep-alive" fullword wide
		 $s16= "Connection refused." fullword wide
		 $s17= "CurrentLanguage" fullword wide
		 $s18= "DocumentCryptSecurity" fullword wide
		 $s19= "Document.NewMacros.AutoOpen" fullword wide
		 $s20= "DocumentOwnerPassword" fullword wide

		 $hex1= {23??28??2d??32??37??3b??40??45??4a??4f??54??59??5e??63??68??6d??72??77??7c??0a??}
		 $hex2= {25??29??2b??2f??35??3b??3d??43??47??49??4f??53??59??61??65??67??6b??6d??71??0a??}
		 $hex3= {28??31??4e??6f??72??6d??61??6c??2e??54??68??69??73??44??6f??63??75??6d??65??6e??74??0a??}
		 $hex4= {41??63??63??65??70??74??2d??45??6e??63??6f??64??69??6e??67??3a??20??67??7a??69??70??2c??64??65??66??6c??61??74??65??2c??}
		 $hex5= {41??63??63??65??73??73??20??76??69??6f??6c??61??74??69??6f??6e??0a??}
		 $hex6= {41??63??70??69??47??6c??6f??62??61??6c??56??61??72??69??61??62??6c??65??0a??}
		 $hex7= {41??64??6f??62??65??20??50??68??6f??74??6f??73??68??6f??70??0a??}
		 $hex8= {41??70??70??6c??69??63??61??74??69??6f??6e??5f??57??69??6e??33??32??0a??}
		 $hex9= {41??73??73??65??72??74??69??6f??6e??20??66??61??69??6c??65??64??0a??}
		 $hex10= {41??75??67??75??73??74??20??53??65??70??74??65??6d??62??65??72??0a??}
		 $hex11= {43??61??63??68??65??2d??43??6f??6e??74??72??6f??6c??3a??20??6d??61??78??2d??61??67??65??3d??30??0a??}
		 $hex12= {43??65??6c??64??61??20??76??69??6e??63??75??6c??61??64??61??0a??}
		 $hex13= {43??6f??6e??6e??65??63??74??69??6f??6e??20??72??65??66??75??73??65??64??2e??0a??}
		 $hex14= {43??6f??6e??6e??65??63??74??69??6f??6e??3a??20??6b??65??65??70??2d??61??6c??69??76??65??0a??}
		 $hex15= {43??75??72??72??65??6e??74??4c??61??6e??67??75??61??67??65??0a??}
		 $hex16= {44??6f??63??75??6d??65??6e??74??2e??4e??65??77??4d??61??63??72??6f??73??2e??41??75??74??6f??4f??70??65??6e??0a??}
		 $hex17= {44??6f??63??75??6d??65??6e??74??43??72??79??70??74??53??65??63??75??72??69??74??79??0a??}
		 $hex18= {44??6f??63??75??6d??65??6e??74??4f??77??6e??65??72??50??61??73??73??77??6f??72??64??0a??}
		 $hex19= {63??63??64??63??6f??65??2d??63??6d??79??6b??5f??68??6f??72??69??7a??6f??6e??74??61??6c??2d??73??68??6f??72??74??0a??}
		 $hex20= {63??63??64??63??6f??65??2d??63??6d??79??6b??5f??73??75??75??72??65??64??32??0a??}

	condition:
		22 of them
}