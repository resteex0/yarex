
/*
   YARA Rule Set
   Author: resteex
   Identifier: ZeroAccess 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_ZeroAccess {
	meta: 
		 description= "ZeroAccess Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-45-31" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "a2611095f689fadffd3068e0d4e3e7ed"
		 hash2= "fe756584b159fd24dc4b6a572917354c"

	strings:

	
 		 $s1= "$%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x" fullword wide

		 $hex1= {2473313d2022242530}

	condition:
		0 of them
}
