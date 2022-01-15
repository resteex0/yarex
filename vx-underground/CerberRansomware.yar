
/*
   YARA Rule Set
   Author: resteex
   Identifier: CerberRansomware 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_CerberRansomware {
	meta: 
		 description= "CerberRansomware Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-01-20" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "ae99e6a451bc53830be799379f5c1104"
		 hash2= "e278d253cae5bc102190e33f99596966"

	strings:

	
 		 $s1= "D:boost_1_64_0boost/filesystem/operations.hpp" fullword wide
		 $s2= "D:boost_1_64_0boost/smart_ptr/shared_ptr.hpp" fullword wide

		 $hex1= {2473313d2022443a62}
		 $hex2= {2473323d2022443a62}

	condition:
		1 of them
}
