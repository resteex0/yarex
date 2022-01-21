
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_LockerGoga 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_LockerGoga {
	meta: 
		 description= "vx_underground2_LockerGoga Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-07-00" 
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

	
 		 $s1= "&%'%(%)%*%+%.-/-0-213141EDFDIHJH" fullword wide
		 $s2= "{095d0e3f-bb94-42e7-a18c-0e4e522e6325}" fullword wide
		 $s3= "AbbsChevis@protonmail.com" fullword wide
		 $s4= "api-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s5= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s6= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s7= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s8= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s9= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s10= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s11= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s12= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s13= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s14= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s15= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s16= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s17= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s18= "Application Activities Timestamp" fullword wide
		 $s19= "CottleAkela@protonmail.com;QyavauZehyco1994@o2.pl" fullword wide
		 $s20= "__crt_strtox::floating_point_value::as_double" fullword wide
		 $s21= "__crt_strtox::floating_point_value::as_float" fullword wide
		 $s22= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s23= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s24= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s25= "Iapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s26= "Iapi-ms-win-core-fibers-l1-1-1" fullword wide
		 $s27= "jaharorajucozibubajoce jedamacaviyeyojele" fullword wide
		 $s28= "j`YsIsFdsMLStBjlYsIsFdsMLSt" fullword wide
		 $s29= "LRtBjlYsisDdsMLSuijl[sIsFdo>LSvBjlYsH" fullword wide
		 $s30= "LRtBjlYsIsFdsMLStBjlYsIsFdsML" fullword wide
		 $s31= "minkernelcrtsucrtinccorecrt_internal_strtox.h" fullword wide
		 $s32= "MMSuBjlXsILFdsILQtBjlYsI7Fe%,>" fullword wide
		 $s33= ".NET Performance Structure" fullword wide
		 $s34= "Oapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s35= "Oapi-ms-win-core-fibers-l1-1-1" fullword wide
		 $s36= "pibawe sacavawicewecotuwi" fullword wide
		 $s37= "SchreiberEleonora@protonmail.com" fullword wide
		 $s38= "sLLvt@jiYzI[FhsILQtCjoYrIsLesMJh@D3$S" fullword wide
		 $s39= "spanish-dominican republic" fullword wide
		 $s40= "Unknown Analyzing Installer" fullword wide
		 $a1= ".?AV?$TwoBases@VBlockCipher@CryptoPP@@URC6_Info@2@@CryptoPP@@" fullword ascii
		 $a2= ".?AV?$value_semantic_codecvt_helper@D@program_options@boost@@" fullword ascii
		 $a3= ".?AV?$value_semantic_codecvt_helper@_W@program_options@boost@@" fullword ascii
		 $a4= ".?AV?$VariableKeyLength@$0BA@$0BA@$0CA@$07$03$0A@@CryptoPP@@" fullword ascii
		 $a5= ".?AV?$VariableKeyLength@$0BA@$0BA@$0CA@$07$03$0A@@GijWRdG_@@" fullword ascii
		 $a6= ".?AVCancellationTokenRegistration_TaskProc@details@Concurrency@@" fullword ascii
		 $a7= ".?AVinvalid_scheduler_policy_thread_specification@Concurrency@@" fullword ascii
		 $a8= ".?AVtoo_many_positional_options_error@program_options@boost@@" fullword ascii
		 $a9= ";http://crl.comodoca.com/COMODORSACertificationAuthority.crl0q" fullword ascii
		 $a10= "Namespace3http://www.smartassembly.com/webservices/Reporting/L" fullword ascii

		 $hex1= {246131303d20224e61}
		 $hex2= {2461313d20222e3f41}
		 $hex3= {2461323d20222e3f41}
		 $hex4= {2461333d20222e3f41}
		 $hex5= {2461343d20222e3f41}
		 $hex6= {2461353d20222e3f41}
		 $hex7= {2461363d20222e3f41}
		 $hex8= {2461373d20222e3f41}
		 $hex9= {2461383d20222e3f41}
		 $hex10= {2461393d20223b6874}
		 $hex11= {247331303d20226170}
		 $hex12= {247331313d20226170}
		 $hex13= {247331323d20226170}
		 $hex14= {247331333d20226170}
		 $hex15= {247331343d20226170}
		 $hex16= {247331353d20226170}
		 $hex17= {247331363d20226170}
		 $hex18= {247331373d20226170}
		 $hex19= {247331383d20224170}
		 $hex20= {247331393d2022436f}
		 $hex21= {2473313d2022262527}
		 $hex22= {247332303d20225f5f}
		 $hex23= {247332313d20225f5f}
		 $hex24= {247332323d20226578}
		 $hex25= {247332333d20226578}
		 $hex26= {247332343d20226578}
		 $hex27= {247332353d20224961}
		 $hex28= {247332363d20224961}
		 $hex29= {247332373d20226a61}
		 $hex30= {247332383d20226a60}
		 $hex31= {247332393d20224c52}
		 $hex32= {2473323d20227b3039}
		 $hex33= {247333303d20224c52}
		 $hex34= {247333313d20226d69}
		 $hex35= {247333323d20224d4d}
		 $hex36= {247333333d20222e4e}
		 $hex37= {247333343d20224f61}
		 $hex38= {247333353d20224f61}
		 $hex39= {247333363d20227069}
		 $hex40= {247333373d20225363}
		 $hex41= {247333383d2022734c}
		 $hex42= {247333393d20227370}
		 $hex43= {2473333d2022416262}
		 $hex44= {247334303d2022556e}
		 $hex45= {2473343d2022617069}
		 $hex46= {2473353d2022617069}
		 $hex47= {2473363d2022617069}
		 $hex48= {2473373d2022617069}
		 $hex49= {2473383d2022617069}
		 $hex50= {2473393d2022617069}

	condition:
		33 of them
}
