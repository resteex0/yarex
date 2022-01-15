
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Vipasana 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Vipasana {
	meta: 
		 description= "Ransomware_Vipasana Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-37-57" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2aea3b217e6a3d08ef684594192cafc8"
		 hash2= "a890e2f924dea3cb3e46a95431ffae39"
		 hash3= "adb5c262ca4f95fee36ae4b9b5d41d45"

	strings:

	
 		 $s1= "Access violation" fullword wide
		 $s2= "Adobe Photoshop" fullword wide
		 $s3= "Assertion failed" fullword wide
		 $s4= "August September" fullword wide
		 $s5= "Enhanced Metafiles" fullword wide
		 $s6= "Invalid argument" fullword wide
		 $s7= "Invalid filename" fullword wide
		 $s8= "Tuesday Wednesday" fullword wide
		 $s9= "Variant overflow" fullword wide

		 $hex1= {2473313d2022416363}
		 $hex2= {2473323d202241646f}
		 $hex3= {2473333d2022417373}
		 $hex4= {2473343d2022417567}
		 $hex5= {2473353d2022456e68}
		 $hex6= {2473363d2022496e76}
		 $hex7= {2473373d2022496e76}
		 $hex8= {2473383d2022547565}
		 $hex9= {2473393d2022566172}

	condition:
		3 of them
}
