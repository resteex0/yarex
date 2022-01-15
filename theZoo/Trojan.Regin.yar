
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
		 date = "2022-01-14_21-38-21" 
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
		 $s4= "OriginalFilename" fullword wide
		 $s5= "VS_VERSION_INFO" fullword wide

		 $hex1= {2473313d2022352e32}
		 $hex2= {2473323d202246696c}
		 $hex3= {2473333d20224d6963}
		 $hex4= {2473343d20224f7269}
		 $hex5= {2473353d202256535f}

	condition:
		1 of them
}
