
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Ransomware_Petrwrap 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Ransomware_Petrwrap {
	meta: 
		 description= "theZoo_Ransomware_Petrwrap Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-35-17" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0487382a4daf8eb9660f1c67e30f8b25"
		 hash2= "51c028cd5f3afe9bf179d81def8d7a8e"
		 hash3= "65d9d04ea080e04e9d0aebf55aecd5d0"
		 hash4= "71b6a493388e7d0b40c83ce903bc6b04"
		 hash5= "b2303c3eb127d1ce6906d21d9d2d07a5"
		 hash6= "d2ec63b63e88ece47fbaab1ca22da1ef"

	strings:

	
 		 $s1= "{71461f04-2faa-4bb9-a0dd-28a79101b599}" fullword wide
		 $s2= "{8175e2c1-d077-43b3-8e9b-6232d4603826}" fullword wide
		 $s3= "wowsmith123456@posteo.net." fullword wide

		 $hex1= {2473313d20227b3731}
		 $hex2= {2473323d20227b3831}
		 $hex3= {2473333d2022776f77}

	condition:
		2 of them
}
