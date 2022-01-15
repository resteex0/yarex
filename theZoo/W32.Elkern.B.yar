
/*
   YARA Rule Set
   Author: resteex
   Identifier: W32_Elkern_B 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W32_Elkern_B {
	meta: 
		 description= "W32_Elkern_B Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-38-28" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0a8a4950d9d71b448fde1f741608921e"
		 hash2= "15eb3a656f9e83138cdb4c3a16b6ab60"

	strings:

	
 		 $s1= "Brightness/Contrast" fullword wide
		 $s2= "Photograph Newspaper" fullword wide
		 $s3= "Resolution Automatic" fullword wide
		 $s4= "Scaling X-Scaling Y-Scaling" fullword wide
		 $s5= "Scanner AstraSlim" fullword wide
		 $s6= "Shutdown AutoFrame" fullword wide
		 $s7= "Transferring Image..." fullword wide
		 $s8= "TWAIN_32ABOR650C.EXE" fullword wide
		 $s9= "TWAIN_32HUI2650C.DLL" fullword wide
		 $s10= "TWAIN_32RES2650C.DLL" fullword wide

		 $hex1= {247331303d20225457}
		 $hex2= {2473313d2022427269}
		 $hex3= {2473323d202250686f}
		 $hex4= {2473333d2022526573}
		 $hex5= {2473343d2022536361}
		 $hex6= {2473353d2022536361}
		 $hex7= {2473363d2022536875}
		 $hex8= {2473373d2022547261}
		 $hex9= {2473383d2022545741}
		 $hex10= {2473393d2022545741}

	condition:
		3 of them
}
