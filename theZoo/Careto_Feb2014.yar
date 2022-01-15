
/*
   YARA Rule Set
   Author: resteex
   Identifier: Careto_Feb2014 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Careto_Feb2014 {
	meta: 
		 description= "Careto_Feb2014 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-37-19" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "5cfd31b1573461a381f5bffa49ea1ed6"
		 hash2= "8102aef50b9c7456f62cdbeefa5fa9de"
		 hash3= "ad6590e0df575228911852b1e401d46e"
		 hash4= "c2ba81c0de01038a54703de26b18e9ee"

	strings:

	
 		 $s1= "6.1.7601.17965 (win7sp1_gdr.121004-0333)" fullword wide
		 $s2= "7.00.5730.13 (longhorn(wmbla).070711-1130)" fullword wide
		 $s3= "BaseNamedObjects" fullword wide
		 $s4= "FileDescription" fullword wide
		 $s5= "Microsoft Corporation" fullword wide
		 $s6= "OriginalFilename" fullword wide
		 $s7= "VS_VERSION_INFO" fullword wide
		 $s8= "WinFXDocObj.exe" fullword wide
		 $a1= "6.1.7601.17965 (win7sp1_gdr.121004-0333)" fullword ascii
		 $a2= "7.00.5730.13 (longhorn(wmbla).070711-1130)" fullword ascii

		 $hex1= {2461313d2022362e31}
		 $hex2= {2461323d2022372e30}
		 $hex3= {2473313d2022362e31}
		 $hex4= {2473323d2022372e30}
		 $hex5= {2473333d2022426173}
		 $hex6= {2473343d202246696c}
		 $hex7= {2473353d20224d6963}
		 $hex8= {2473363d20224f7269}
		 $hex9= {2473373d202256535f}
		 $hex10= {2473383d202257696e}

	condition:
		3 of them
}
