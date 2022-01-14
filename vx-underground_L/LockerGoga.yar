
/*
   YARA Rule Set
   Author: resteex
   Identifier: LockerGoga 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_LockerGoga {
	meta: 
		 description= "LockerGoga Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_04-07-02" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "164f72dfb729ca1e15f99d456b7cf811"
		 hash2= "16bcc3b7f32c41e7c7222bf37fe39fe6"
		 hash3= "174e3d9c7b0380dd7576187c715c4681"
		 hash4= "3b200c8173a92c94441cb062d38012f6"
		 hash5= "3ebca21b1d4e2f482b3eda6634e89211"
		 hash6= "438ebec995ad8e05a0cea2e409bfd488"
		 hash7= "4da135516f3da1c6ca04d17f83b99e65"
		 hash8= "52340664fe59e030790c48b66924b5bd"
		 hash9= "7e3f8b6b7ac0565bfcbf0a1e3e6fcfbc"
		 hash10= "9cad8641ac79688e09c5fa350aef2094"
		 hash11= "a1d732aa27e1ca2ae45a189451419ed5"
		 hash12= "a52f26575556d3c4eccd3b51265cb4e6"
		 hash13= "a5bc1f94e7505a2e73c866551f7996f9"
		 hash14= "b3d3da12ca3b9efd042953caa6c3b8cd"
		 hash15= "ba53d8910ec3e46864c3c86ebd628796"
		 hash16= "c2da604a2a469b1075e20c5a52ad3317"
		 hash17= "dece7ebb578772e466d3ecae5e2917f9"
		 hash18= "e11502659f6b5c5bd9f78f534bc38fea"
		 hash19= "e8c7c902bcb2191630e10a80ddf9d5de"
		 hash20= "faf4de4e1c5d8e4241088c90cfe8eddd"

	strings:

	
 		 $s1= "{095d0e3f-bb94-42e7-a18c-0e4e522e6325}" fullword wide
		 $s2= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s3= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s4= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s5= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s6= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s7= "CottleAkela@protonmail.com;QyavauZehyco1994@o2.pl" fullword wide
		 $s8= "__crt_strtox::floating_point_value::as_double" fullword wide
		 $s9= "__crt_strtox::floating_point_value::as_float" fullword wide
		 $s10= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s11= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s12= "Iapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s13= "jaharorajucozibubajoce jedamacaviyeyojele" fullword wide
		 $s14= "LRtBjlYsisDdsMLSuijl[sIsFdo>LSvBjlYsH" fullword wide
		 $s15= "minkernelcrtsucrtinccorecrt_internal_strtox.h" fullword wide
		 $s16= "Oapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s17= "sLLvt@jiYzI[FhsILQtCjoYrIsLesMJh@D3$S" fullword wide

		 $hex1= {247331303d20226578}
		 $hex2= {247331313d20226578}
		 $hex3= {247331323d20224961}
		 $hex4= {247331333d20226a61}
		 $hex5= {247331343d20224c52}
		 $hex6= {247331353d20226d69}
		 $hex7= {247331363d20224f61}
		 $hex8= {247331373d2022734c}
		 $hex9= {2473313d20227b3039}
		 $hex10= {2473323d2022617069}
		 $hex11= {2473333d2022617069}
		 $hex12= {2473343d2022617069}
		 $hex13= {2473353d2022617069}
		 $hex14= {2473363d2022617069}
		 $hex15= {2473373d2022436f74}
		 $hex16= {2473383d20225f5f63}
		 $hex17= {2473393d20225f5f63}

	condition:
		2 of them
}
