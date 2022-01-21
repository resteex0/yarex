
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Punkey 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Punkey {
	meta: 
		 description= "vx_underground2_Punkey Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-13-49" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "073cf350a20eb8ee14e21f62840cb0ce"
		 hash2= "327dd038203369e6f855fd53e633dde8"
		 hash3= "51b0d6b54a2fab3638f8aea0b923d7e0"
		 hash4= "b1fe4120e3b38784f9fe57f6bb154517"

	strings:

	
 		 $s1= "SOFTWAREMicrosoftVisualStudio10.0SetupVS" fullword wide
		 $a1= "softwareMicrosoftwindowscurrentversionexplorershell folders" fullword ascii

		 $hex1= {2461313d2022736f66}
		 $hex2= {2473313d2022534f46}

	condition:
		1 of them
}
