
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Lephic 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Lephic {
	meta: 
		 description= "Win32_Lephic Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-39-05" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "39192da38ad821d5e6cd6b68843dc81d"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "OriginalFilename" fullword wide
		 $s3= "VS_VERSION_INFO" fullword wide
		 $s4= "www.nat32.com/xampp" fullword wide

		 $hex1= {2473313d202246696c}
		 $hex2= {2473323d20224f7269}
		 $hex3= {2473333d202256535f}
		 $hex4= {2473343d2022777777}

	condition:
		1 of them
}
