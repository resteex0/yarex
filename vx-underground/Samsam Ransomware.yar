
/*
   YARA Rule Set
   Author: resteex
   Identifier: Samsam_Ransomware 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Samsam_Ransomware {
	meta: 
		 description= "Samsam_Ransomware Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-18-35" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "025c1c35c3198e6e3497d5dbf97ae81f"
		 hash2= "58b39bb94660958b6180588109c34f51"
		 hash3= "7e50f6e752b1335cbb4afe5aee93e317"

	strings:

	
 		 $s1= "90928fd1250435589cc0150849bc0cff" fullword wide
		 $s2= "bffe72ccbadadc8c3fb178799681755c" fullword wide
		 $s3= "djysyfasfgjhkashfi8atwtfegs" fullword wide
		 $s4= "jei4tgvrcqbwaunkerki7fywetuyg" fullword wide
		 $s5= "jsbggye984s76t5gwnekfqwurrtwiesyfg" fullword wide

		 $hex1= {2473313d2022393039}
		 $hex2= {2473323d2022626666}
		 $hex3= {2473333d2022646a79}
		 $hex4= {2473343d20226a6569}
		 $hex5= {2473353d20226a7362}

	condition:
		3 of them
}
