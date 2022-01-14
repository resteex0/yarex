
/*
   YARA Rule Set
   Author: resteex
   Identifier: MosesStaff 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_MosesStaff {
	meta: 
		 description= "MosesStaff Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_06-52-45" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "3dfb7626dbe46136bc19404b63c6d1dc"
		 hash2= "93c19436e6e5207e2e2bed425107f080"

	strings:

	
 		 $s1= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s2= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s3= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s4= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s5= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s6= "Bapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s7= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s8= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s9= "SYSTEMCurrentControlSetServicesDCDrvconfig" fullword wide
		 $s10= "SYSTEMCurrentControlSetServicesDCDrvInstances" fullword wide

		 $hex1= {247331303d20225359}
		 $hex2= {2473313d2022617069}
		 $hex3= {2473323d2022617069}
		 $hex4= {2473333d2022617069}
		 $hex5= {2473343d2022617069}
		 $hex6= {2473353d2022617069}
		 $hex7= {2473363d2022426170}
		 $hex8= {2473373d2022657874}
		 $hex9= {2473383d2022657874}
		 $hex10= {2473393d2022535953}

	condition:
		1 of them
}
