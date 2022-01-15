
/*
   YARA Rule Set
   Author: resteex
   Identifier: Loda_RAT 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Loda_RAT {
	meta: 
		 description= "Loda_RAT Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-13-12" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "dc14cd48169a1ab64074a09521fdcf1d"

	strings:

	
 		 $s1= "DSeAssignPrimaryTokenPrivilege" fullword wide
		 $s2= "GUICTRLCREATELISTVIEWITEM" fullword wide
		 $s3= "GUICTRLCREATETREEVIEWITEM" fullword wide
		 $s4= "GUICTRLREGISTERLISTVIEWSORT" fullword wide
		 $s5= "SoftwareAutoIt v3AutoIt" fullword wide
		 $s6= "SYSTEMCurrentControlSetControlNlsLanguage" fullword wide

		 $hex1= {2473313d2022445365}
		 $hex2= {2473323d2022475549}
		 $hex3= {2473333d2022475549}
		 $hex4= {2473343d2022475549}
		 $hex5= {2473353d2022536f66}
		 $hex6= {2473363d2022535953}

	condition:
		4 of them
}
