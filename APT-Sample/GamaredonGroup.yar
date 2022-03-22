
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_GamaredonGroup 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_GamaredonGroup {
	meta: 
		 description= "APT_Sample_GamaredonGroup Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-22_12-20-11" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "04449f25e64ba893acdcba5f1694cd41"
		 hash2= "19ddb00f3eaa750c1316bd615b3d1622"
		 hash3= "304576ff20117ffc0b743dc64349451b"
		 hash4= "369a82f8bb8c906b8cde4f688c08bd71"
		 hash5= "3fc1cd6eade766fc989684dd1390d640"
		 hash6= "49b4a1123ff61b6a9c8229886cdd8e12"
		 hash7= "51ab00c724a29198eed3cb9b50925046"
		 hash8= "52815c0c8dd35e80f52576be8d02e620"
		 hash9= "6bf9d9d41243568dc917df768de68529"
		 hash10= "b835bf9188ed749da201403a51481399"
		 hash11= "c7bda65e820338a42a02eb0c1e20d961"

	strings:

	
 		 $s1= "8.00.7600.16385 (win7_rtm.090713-1255)" fullword wide
		 $s2= "api-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s3= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s5= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s6= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s7= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s8= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s9= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s10= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s11= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s12= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s13= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s14= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s15= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s16= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s17= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s18= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $a1= "aicivPqAwuWsBIuLfRtFeSLOwUCBBugpsLZNkWaLcBlaBHIycyYhtkyDWGmrS" fullword ascii
		 $a2= "JcLboWwKDqbkRDhiioHwOgeZmSgZbuOnlrXAgdTvKkFZXInwxTuGcUyqdBnTZ" fullword ascii
		 $a3= "tnVQhxJSTxLaAdtWecdqqGcEZuaFPdKcTHKoCvWMbiGXjSjPhkSFsaTkyXNoTe" fullword ascii

		 $hex1= {382e30302e37363030}
		 $hex2= {4a634c626f57774b44}
		 $hex3= {616963697650714177}
		 $hex4= {6170692d6d732d7769}
		 $hex5= {6578742d6d732d7769}
		 $hex6= {746e565168784a5354}

	condition:
		2 of them
}
