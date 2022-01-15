
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
		 date = "2022-01-14_21-39-40" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "a2611095f689fadffd3068e0d4e3e7ed"
		 hash2= "fe756584b159fd24dc4b6a572917354c"

	strings:

	
 		 $s1= "$%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x" fullword wide
		 $s2= "c:windowssystem32z" fullword wide
		 $s3= "wbemfastprox.dll" fullword wide
		 $a1= "$%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x" fullword ascii

		 $hex1= {2461313d2022242530}
		 $hex2= {2473313d2022242530}
		 $hex3= {2473323d2022633a77}
		 $hex4= {2473333d2022776265}

	condition:
		1 of them
}
