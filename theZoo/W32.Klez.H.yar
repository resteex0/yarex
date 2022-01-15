
/*
   YARA Rule Set
   Author: resteex
   Identifier: W32_Klez_H 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W32_Klez_H {
	meta: 
		 description= "W32_Klez_H Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_22-52-02" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "07c19da3a33f9ec6a97f3837aef6fde0"
		 hash2= "4ae9a4a8b8ce22c7b52c2eaec75ca536"
		 hash3= "60c271a141c1cbd29489e1a2925b639f"
		 hash4= "b023af582bfe56ae0c32401599b7d082"
		 hash5= "bbb1522b1db750efbcf7813e9153d424"

	strings:

	
 		 $s1= "http://www.bitdefender.com" fullword wide
		 $s2= "Win32.Klez.A@mm, Win32.Klez.B@mm," fullword wide
		 $s3= "Win32.Klez.C@mm, Win32.Klez.D@mm," fullword wide

		 $hex1= {2473313d2022687474}
		 $hex2= {2473323d202257696e}
		 $hex3= {2473333d202257696e}

	condition:
		2 of them
}
