
/*
   YARA Rule Set
   Author: resteex
   Identifier: Artemis 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Artemis {
	meta: 
		 description= "Artemis Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-42-11" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "caff801a280d42dbd1ad6b1266d3c43a"

	strings:

	
 		 $s1= "{1E453EA8-BB42-419D-8067-D2477A36B761}" fullword wide
		 $s2= "ActivationDepartment@FedRetireSoftware.com" fullword wide
		 $s3= "{D449BC32-6D28-4AF0-BB00-AB3391EF0F9A}" fullword wide
		 $s4= "http://www.FedRetireSoftware.com" fullword wide
		 $s5= "StringFileInfo%04x%04xArguments" fullword wide

		 $hex1= {2473313d20227b3145}
		 $hex2= {2473323d2022416374}
		 $hex3= {2473333d20227b4434}
		 $hex4= {2473343d2022687474}
		 $hex5= {2473353d2022537472}

	condition:
		3 of them
}
