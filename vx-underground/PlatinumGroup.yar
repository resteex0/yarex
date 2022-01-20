
/*
   YARA Rule Set
   Author: resteex
   Identifier: PlatinumGroup 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_PlatinumGroup {
	meta: 
		 description= "PlatinumGroup Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_11-21-38" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "05e48b00754007843e1fdf72083a1538"
		 hash2= "1c7123dd51906327c37ed12b68cf435f"
		 hash3= "6561e8fad70cfdd25e4a1f8d64f2c0a0"
		 hash4= "71a76adeadc7b51218d265771fc2b0d1"
		 hash5= "739daf91938f4bdab973c5ef519d6543"
		 hash6= "a3edf69b6b419e5ac3de3d99e636f59c"
		 hash7= "cf386d884135b195fb6d11727bc06056"
		 hash8= "d4a26b0926171dc4f969955d157d1311"
		 hash9= "d9af02de733584e4c91fc107c50538d3"
		 hash10= "e6c27747a61038a641b8fa1239a35291"
		 hash11= "e9a99f7b2ac4a8aceed2c3a9fcb78eb8"
		 hash12= "eaec3e5334b937a526a418b88d63291c"

	strings:

	
 		 $a1= "C:unityrsawindowsCertC-2.8.0.1providercryptorsarsacsp.c" fullword ascii
		 $a2= "C:unityrsawindowsCertC-2.8.0.1providerdbcapicapiprov.c" fullword ascii
		 $a3= "C:unityrsawindowsCertC-2.8.0.1providerdbimimdbcert.c" fullword ascii
		 $a4= "C:unityrsawindowsCertC-2.8.0.1providerdbrsarsadbcer.c" fullword ascii
		 $a5= "C:unityrsawindowsCertC-2.8.0.1providerdbrsarsadbcrl.c" fullword ascii
		 $a6= "C:unityrsawindowsCertC-2.8.0.1providerdbrsarsadbkey.c" fullword ascii
		 $a7= "C:unityrsawindowsCertC-2.8.0.1providerdbrsarsadbmas.c" fullword ascii
		 $a8= "C:unityrsawindowsCertC-2.8.0.1providerdbrsarsadbpbe.c" fullword ascii
		 $a9= "C:unityrsawindowsCertC-2.8.0.1provideriofilefileio.c" fullword ascii
		 $a10= "C:unityrsawindowsCertC-2.8.0.1providerpathpkixpkixpath.c" fullword ascii
		 $a11= "SYSTEMCurrentControlSetServicesNetBTParametersInterfaces" fullword ascii
		 $a12= "SYSTEMCurrentControlSetServicesTcpipParametersinterfaces" fullword ascii

		 $hex1= {246131303d2022433a}
		 $hex2= {246131313d20225359}
		 $hex3= {246131323d20225359}
		 $hex4= {2461313d2022433a75}
		 $hex5= {2461323d2022433a75}
		 $hex6= {2461333d2022433a75}
		 $hex7= {2461343d2022433a75}
		 $hex8= {2461353d2022433a75}
		 $hex9= {2461363d2022433a75}
		 $hex10= {2461373d2022433a75}
		 $hex11= {2461383d2022433a75}
		 $hex12= {2461393d2022433a75}

	condition:
		6 of them
}
