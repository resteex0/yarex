
/*
   YARA Rule Set
   Author: resteex
   Identifier: Oski 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Oski {
	meta: 
		 description= "Oski Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-16-20" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "24dd86688a277a16ca013809c71ab8c0"
		 hash2= "6064c0f23e9504edc9940d8a78b1de3b"
		 hash3= "ad81745667752ef8094ef646ed870d3d"

	strings:

	
 		 $s1= "WindowsMicrosoft.NETFrameworkv4.0.30319RegAsm.exe" fullword wide
		 $a1= "WindowsMicrosoft.NETFrameworkv4.0.30319RegAsm.exe" fullword ascii

		 $hex1= {2461313d202257696e}
		 $hex2= {2473313d202257696e}

	condition:
		1 of them
}
