
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Careto_Feb2014 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Careto_Feb2014 {
	meta: 
		 description= "theZoo_Careto_Feb2014 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-34-49" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "5cfd31b1573461a381f5bffa49ea1ed6"
		 hash2= "8102aef50b9c7456f62cdbeefa5fa9de"
		 hash3= "ad6590e0df575228911852b1e401d46e"
		 hash4= "c2ba81c0de01038a54703de26b18e9ee"

	strings:

	
 		 $s1= "6.1.7601.17965 (win7sp1_gdr.121004-0333)" fullword wide
		 $s2= "7.00.5730.13 (longhorn(wmbla).070711-1130)" fullword wide

		 $hex1= {2473313d2022362e31}
		 $hex2= {2473323d2022372e30}

	condition:
		1 of them
}
