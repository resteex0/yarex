
/*
   YARA Rule Set
   Author: resteex
   Identifier: CryptoLocker_22Jan2014 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_CryptoLocker_22Jan2014 {
	meta: 
		 description= "CryptoLocker_22Jan2014 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-37-22" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0246bb54723bd4a49444aa4ca254845a"
		 hash2= "829dde7015c32d7d77d8128665390dab"

	strings:

	
 		 $s1= "Assembly Version" fullword wide
		 $s2= "COR_ENABLE_PROFILING" fullword wide
		 $s3= "FileDescription" fullword wide
		 $s4= "OriginalFilename" fullword wide
		 $s5= "Profiler detected" fullword wide
		 $s6= "VS_VERSION_INFO" fullword wide

		 $hex1= {2473313d2022417373}
		 $hex2= {2473323d2022434f52}
		 $hex3= {2473333d202246696c}
		 $hex4= {2473343d20224f7269}
		 $hex5= {2473353d202250726f}
		 $hex6= {2473363d202256535f}

	condition:
		2 of them
}
