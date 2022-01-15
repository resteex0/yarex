
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Emotet 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Emotet {
	meta: 
		 description= "Win32_Emotet Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-38-45" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8baa9b809b591a11af423824f4d9726a"

	strings:

	
 		 $s1= "5665778782565768827838" fullword wide
		 $s2= "57576736879580478257258376974939" fullword wide
		 $s3= "FileDescription" fullword wide
		 $s4= "OriginalFilename" fullword wide
		 $s5= "Remounter (2)RemounterVeladonACCOJ.vbp" fullword wide
		 $s6= "VS_VERSION_INFO" fullword wide
		 $a1= "Remounter (2)RemounterVeladonACCOJ.vbp" fullword ascii

		 $hex1= {2461313d202252656d}
		 $hex2= {2473313d2022353636}
		 $hex3= {2473323d2022353735}
		 $hex4= {2473333d202246696c}
		 $hex5= {2473343d20224f7269}
		 $hex6= {2473353d202252656d}
		 $hex7= {2473363d202256535f}

	condition:
		2 of them
}
