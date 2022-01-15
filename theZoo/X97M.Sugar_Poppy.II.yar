
/*
   YARA Rule Set
   Author: resteex
   Identifier: X97M_Sugar_Poppy_II 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_X97M_Sugar_Poppy_II {
	meta: 
		 description= "X97M_Sugar_Poppy_II Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-39-39" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "5620fa07c51c3cf57d7b78016f81fa68"
		 hash2= "90b5684d749d3b23b6bac6e592a4c30a"

	strings:

	
 		 $s1= "DocumentSummaryInformation" fullword wide
		 $s2= "SummaryInformation" fullword wide
		 $s3= "_VBA_PROJECT_CUR" fullword wide

		 $hex1= {2473313d2022446f63}
		 $hex2= {2473323d202253756d}
		 $hex3= {2473333d20225f5642}

	condition:
		1 of them
}
