
/*
   YARA Rule Set
   Author: resteex
   Identifier: Babadeda 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Babadeda {
	meta: 
		 description= "Babadeda Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-13_15-14-35" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0013ee610f83b401007adbefef051305"
		 hash2= "73311d203988335dea75e92d7d8eb1f5"
		 hash3= "bacfa288e5c0f18a8f2c94d208d7c760"
		 hash4= "e653f13bf4b225f1c7dce0e6404fc52a"
		 hash5= "ec538ff191a52b5ca9f67ae5d5d56908"

	strings:

	
 		 $s1= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s2= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s3= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s4= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s5= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s6= "__crt_strtox::floating_point_value::as_double" fullword wide
		 $s7= "__crt_strtox::floating_point_value::as_float" fullword wide
		 $s8= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s9= "minkernelcrtsucrtinccorecrt_internal_strtox.h" fullword wide
		 $s10= "SOFTWAREMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s11= "}{ywusqonkigfdb`^[YVVSRPMLJIGECB@?=;976431/.,+)(&$#! " fullword wide

		 $hex1= {247331303d2022534f}
		 $hex2= {247331313d20227d7b}
		 $hex3= {2473313d2022617069}
		 $hex4= {2473323d2022617069}
		 $hex5= {2473333d2022617069}
		 $hex6= {2473343d2022617069}
		 $hex7= {2473353d2022617069}
		 $hex8= {2473363d20225f5f63}
		 $hex9= {2473373d20225f5f63}
		 $hex10= {2473383d2022657874}
		 $hex11= {2473393d20226d696e}

	condition:
		1 of them
}
