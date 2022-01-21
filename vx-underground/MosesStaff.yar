
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_MosesStaff 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_MosesStaff {
	meta: 
		 description= "vx_underground2_MosesStaff Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-11-45" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "3dfb7626dbe46136bc19404b63c6d1dc"
		 hash2= "93c19436e6e5207e2e2bed425107f080"

	strings:

	
 		 $s1= "Aapi-ms-win-core-datetime-l1-1-1" fullword wide
		 $s2= "Aapi-ms-win-core-fibers-l1-1-1" fullword wide
		 $s3= "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		 $s4= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s5= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s6= "api-ms-win-core-file-l1-2-2" fullword wide
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
		 $s18= "Bapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s19= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s20= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s21= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s22= "SYSTEMCurrentControlSetServicesDCDrvconfig" fullword wide
		 $s23= "SYSTEMCurrentControlSetServicesDCDrvInstances" fullword wide
		 $a1= "opyi-windows-manifest-filename oSDdJXknDgDCEdVeHeQh.exe.manifest" fullword ascii

		 $hex1= {2461313d20226f7079}
		 $hex2= {247331303d20226170}
		 $hex3= {247331313d20226170}
		 $hex4= {247331323d20226170}
		 $hex5= {247331333d20226170}
		 $hex6= {247331343d20226170}
		 $hex7= {247331353d20226170}
		 $hex8= {247331363d20226170}
		 $hex9= {247331373d20226170}
		 $hex10= {247331383d20224261}
		 $hex11= {247331393d20226578}
		 $hex12= {2473313d2022416170}
		 $hex13= {247332303d20226578}
		 $hex14= {247332313d20226578}
		 $hex15= {247332323d20225359}
		 $hex16= {247332333d20225359}
		 $hex17= {2473323d2022416170}
		 $hex18= {2473333d2022617069}
		 $hex19= {2473343d2022617069}
		 $hex20= {2473353d2022617069}
		 $hex21= {2473363d2022617069}
		 $hex22= {2473373d2022617069}
		 $hex23= {2473383d2022617069}
		 $hex24= {2473393d2022617069}

	condition:
		16 of them
}
