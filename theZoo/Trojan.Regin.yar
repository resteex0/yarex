
/*
   YARA Rule Set
   Author: resteex
   Identifier: Trojan_Regin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Trojan_Regin {
	meta: 
		 description= "Trojan_Regin Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-30-50" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "06665b96e293b23acc80451abb413e50"
		 hash2= "187044596bc1328efa0ed636d8aa4a5c"
		 hash3= "1c024e599ac055312a4ab75b3950040a"
		 hash4= "2c8b9d2885543d7ade3cae98225e263b"
		 hash5= "4b6b86c7fec1c574706cecedf44abded"
		 hash6= "6662c390b2bbbd291ec7987388fc75d7"
		 hash7= "b269894f434657db2b15949641a67532"
		 hash8= "b29ca4f22ae7b7b25f79c1d4a421139d"
		 hash9= "b505d65721bb2453d5039a389113b566"
		 hash10= "ba7bb65634ce1e30c1e5415be3d1db1d"
		 hash11= "bfbe8c3ee78750c3a520480700e440f8"
		 hash12= "d240f06e98c8d3e647cbf4d442d79475"
		 hash13= "ffb0b9b5b610191051a7bdf0806e1e47"

	strings:

	
 		 $s1= "5.2.3790.0 (srv03_rtm.030324-2048)" fullword wide
		 $s2= "FileDescription" fullword wide
		 $s3= "Microsoft Corporation" fullword wide
		 $s4= "Microsoft Corporation. All rights reserved." fullword wide
		 $s5= "Operating System" fullword wide
		 $s6= "OriginalFilename" fullword wide
		 $s7= "Universal Serial Bus Class Driver" fullword wide
		 $s8= "VS_VERSION_INFO" fullword wide
		 $a1= "KeQueryPerformanceCounter" fullword ascii
		 $a2= "RtlAnsiStringToUnicodeString" fullword ascii
		 $a3= "RtlUnicodeStringToInteger" fullword ascii

		 $hex1= {2461313d20224b6551}
		 $hex2= {2461323d202252746c}
		 $hex3= {2461333d202252746c}
		 $hex4= {2473313d2022352e32}
		 $hex5= {2473323d202246696c}
		 $hex6= {2473333d20224d6963}
		 $hex7= {2473343d20224d6963}
		 $hex8= {2473353d20224f7065}
		 $hex9= {2473363d20224f7269}
		 $hex10= {2473373d2022556e69}
		 $hex11= {2473383d202256535f}

	condition:
		1 of them
}
