
/*
   YARA Rule Set
   Author: resteex
   Identifier: Siloscape 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Siloscape {
	meta: 
		 description= "Siloscape Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-18-44" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "fecf803f7d84d4cfa81277298574d6e6"

	strings:

	
 		 $s1= "http://www.info-zip.org/UnZip.html" fullword wide
		 $s2= "www.info-zip.org>" fullword wide

		 $hex1= {2473313d2022687474}
		 $hex2= {2473323d2022777777}

	condition:
		1 of them
}
