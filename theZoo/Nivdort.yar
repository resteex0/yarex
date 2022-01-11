
/*
   YARA Rule Set
   Author: resteex
   Identifier: Nivdort 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Nivdort {
	meta: 
		 description= "Nivdort Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-26-50" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "ed2cd14a28ff2d00a5cefcf6a074af8d"

	strings:

	
 		 $a1= "abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a2= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" fullword ascii
		 $a3= ".?AV?$basic_ios@DU?$char_traits@D@std@@@std@@" fullword ascii
		 $a4= ".?AV?$basic_ostream@DU?$char_traits@D@std@@@std@@" fullword ascii
		 $a5= ".?AV?$basic_ostringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@" fullword ascii
		 $a6= ".?AV?$basic_streambuf@DU?$char_traits@D@std@@@std@@" fullword ascii
		 $a7= ".?AV?$basic_stringbuf@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@" fullword ascii
		 $a8= ".?AV?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@std@@@std@@" fullword ascii
		 $a9= ".?AVfailure@ios_base@std@@" fullword ascii
		 $a10= "GAIsProcessorFeaturePresent" fullword ascii
		 $a11= "GetMenuCheckMarkDimensions" fullword ascii
		 $a12= "GetUserObjectInformationA" fullword ascii
		 $a13= "InitializeCriticalSection" fullword ascii
		 $a14= "InitializeCriticalSectionAndSpinCount" fullword ascii
		 $a15= "IsProcessorFeaturePresent" fullword ascii
		 $a16= "JanFebMarAprMayJunJulAugSepOctNovDec" fullword ascii
		 $a17= "SetUnhandledExceptionFilter" fullword ascii

		 $hex1= {246131303d20224741}
		 $hex2= {246131313d20224765}
		 $hex3= {246131323d20224765}
		 $hex4= {246131333d2022496e}
		 $hex5= {246131343d2022496e}
		 $hex6= {246131353d20224973}
		 $hex7= {246131363d20224a61}
		 $hex8= {246131373d20225365}
		 $hex9= {2461313d2022616263}
		 $hex10= {2461323d2022414243}
		 $hex11= {2461333d20222e3f41}
		 $hex12= {2461343d20222e3f41}
		 $hex13= {2461353d20222e3f41}
		 $hex14= {2461363d20222e3f41}
		 $hex15= {2461373d20222e3f41}
		 $hex16= {2461383d20222e3f41}
		 $hex17= {2461393d20222e3f41}

	condition:
		2 of them
}
