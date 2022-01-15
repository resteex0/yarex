
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
		 date = "2022-01-14_20-53-07" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "caff801a280d42dbd1ad6b1266d3c43a"

	strings:

	
 		 $s1= "{1E453EA8-BB42-419D-8067-D2477A36B761}" fullword wide
		 $s2= "ActivationDepartment@FedRetireSoftware.com" fullword wide
		 $s3= "{D449BC32-6D28-4AF0-BB00-AB3391EF0F9A}" fullword wide
		 $s4= "FileDescription" fullword wide
		 $s5= "http://www.FedRetireSoftware.com" fullword wide
		 $s6= "OriginalFilename" fullword wide
		 $s7= "StringFileInfo%04x%04xArguments" fullword wide
		 $s8= "VarFileInfoTranslation" fullword wide
		 $s9= "VS_VERSION_INFO" fullword wide
		 $a1= "{1E453EA8-BB42-419D-8067-D2477A36B761}" fullword ascii
		 $a2= "ActivationDepartment@FedRetireSoftware.com" fullword ascii
		 $a3= "{D449BC32-6D28-4AF0-BB00-AB3391EF0F9A}" fullword ascii

		 $hex1= {2461313d20227b3145}
		 $hex2= {2461323d2022416374}
		 $hex3= {2461333d20227b4434}
		 $hex4= {2473313d20227b3145}
		 $hex5= {2473323d2022416374}
		 $hex6= {2473333d20227b4434}
		 $hex7= {2473343d202246696c}
		 $hex8= {2473353d2022687474}
		 $hex9= {2473363d20224f7269}
		 $hex10= {2473373d2022537472}
		 $hex11= {2473383d2022566172}
		 $hex12= {2473393d202256535f}

	condition:
		1 of them
}
