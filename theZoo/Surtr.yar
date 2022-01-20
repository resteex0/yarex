
/*
   YARA Rule Set
   Author: resteex
   Identifier: Surtr 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Surtr {
	meta: 
		 description= "Surtr Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-43-28" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "36e194f7df2f2fd020e3800ab77f7e82"
		 hash2= "4f03b86e4d6631c26ff5fffc7332be1d"
		 hash3= "4fe6f4655cc5b5689916ec9ae63e1135"
		 hash4= "63133c371a0e67b0904a2b32b659a6b3"
		 hash5= "7fc56270e7a70fa81a5935b72eacbe29"
		 hash6= "acda60ce8350b6f9c20f9d10bb09f9c9"
		 hash7= "d41d8cd98f00b204e9800998ecf8427e"
		 hash8= "eb1ef1b908b16e264dd4e0e8b480ee37"
		 hash9= "ebd086b193c06f7b735179abf3237965"
		 hash10= "fc88beeb7425aefa5e8936e06849f484"

	strings:

	
 		 $a1= "paperw12240paperh15840margl666margr133margt666margb173" fullword ascii
		 $a2= "SoftwareMicrosoftWindowsCurrentVersionPoliciesExplorerrun" fullword ascii
		 $a3= "SoftwareMicrosoftWindows NTCurrentVersionWinlogon" fullword ascii

		 $hex1= {2461313d2022706170}
		 $hex2= {2461323d2022536f66}
		 $hex3= {2461333d2022536f66}

	condition:
		2 of them
}
