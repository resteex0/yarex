
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Zurgop 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Zurgop {
	meta: 
		 description= "Win32_Zurgop Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-35-23" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "c1e5dae72a51a7b7219346c4a360d867"

	strings:

	
 		 $s1= "Cairo Dibs Fast Credo 1999-2010" fullword wide
		 $s2= "Equal Tiny Finale Area Seduce" fullword wide
		 $s3= "FileDescription" fullword wide
		 $s4= "Guide Hide Cape" fullword wide
		 $s5= "Lighttek Software" fullword wide
		 $s6= "OriginalFilename" fullword wide
		 $s7= "Tree Draft Came Gummy Awe" fullword wide
		 $s8= "VS_VERSION_INFO" fullword wide

		 $hex1= {2473313d2022436169}
		 $hex2= {2473323d2022457175}
		 $hex3= {2473333d202246696c}
		 $hex4= {2473343d2022477569}
		 $hex5= {2473353d20224c6967}
		 $hex6= {2473363d20224f7269}
		 $hex7= {2473373d2022547265}
		 $hex8= {2473383d202256535f}

	condition:
		1 of them
}
