
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Tor2Mine 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Tor2Mine {
	meta: 
		 description= "vx_underground2_Tor2Mine Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-17-42" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1f9ff22965274cbaa410139d1dfd0d1e"
		 hash2= "1ff598510ed92bc4f36038b25ca1eed9"
		 hash3= "2d61a45b7c49e7f370ae2da3ab8c1f0c"
		 hash4= "46c5de17bdf8ff4f9590da47b79c96a2"
		 hash5= "550eb6b647d440d21e957027d24afd03"
		 hash6= "59e747e8313bf4d401e2277ab5f7072d"
		 hash7= "94616abe302aec88a55c1dfda5fea253"
		 hash8= "9bc9ff8cf4d71ba22cdab051c037ba96"
		 hash9= "ec1323ec317f1aa6a03c4c5c84e37d5e"

	strings:

	
 		 $s1= "Function PowershellInstalled()" fullword wide
		 $s2= "Function RestoreAndUpdate()" fullword wide
		 $s3= "SaveBinaryData myPath,objWinHttp.responseBody" fullword wide

		 $hex1= {2473313d202246756e}
		 $hex2= {2473323d202246756e}
		 $hex3= {2473333d2022536176}

	condition:
		2 of them
}
