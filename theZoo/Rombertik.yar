
/*
   YARA Rule Set
   Author: resteex
   Identifier: Rombertik 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Rombertik {
	meta: 
		 description= "Rombertik Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-43-23" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "d2b5a2547e2246694148ece3cf74de0e"
		 hash2= "efc9040f587a5dd9e1de4707ec1ed8c5"

	strings:

	
 		 $a1= "SoftwareMicrosoftWindowsCurrentVersionInternet Settings" fullword ascii

		 $hex1= {2461313d2022536f66}

	condition:
		0 of them
}
