
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Unnamed_0 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Unnamed_0 {
	meta: 
		 description= "Ransomware_Unnamed_0 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-37-56" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "96afc9cdef3c623e0c5420e339c57283"

	strings:

	
 		 $s1= "Assembly Version" fullword wide
		 $s2= "ekp5blhVaktUbFpw" fullword wide
		 $s3= "FileDescription" fullword wide
		 $s4= "OriginalFilename" fullword wide
		 $s5= "U3lzdGVtLkRyYXdpbmcuZGxs" fullword wide
		 $s6= "VS_VERSION_INFO" fullword wide
		 $s7= "VVVlb0NvaXBHdVZj" fullword wide

		 $hex1= {2473313d2022417373}
		 $hex2= {2473323d2022656b70}
		 $hex3= {2473333d202246696c}
		 $hex4= {2473343d20224f7269}
		 $hex5= {2473353d202255336c}
		 $hex6= {2473363d202256535f}
		 $hex7= {2473373d2022565656}

	condition:
		2 of them
}
