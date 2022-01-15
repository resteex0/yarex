
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Cerber 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Cerber {
	meta: 
		 description= "Ransomware_Cerber Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-37-44" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8b6bc16fd137c09a08b02bbe1bb7d670"

	strings:

	
 		 $s1= "$i$i$Y$Y$i$i$Y$Y$)$)$" fullword wide
		 $s2= "E8E(E,EPE@EHELE" fullword wide
		 $s3= "VS_VERSION_INFO" fullword wide

		 $hex1= {2473313d2022246924}
		 $hex2= {2473323d2022453845}
		 $hex3= {2473333d202256535f}

	condition:
		1 of them
}
