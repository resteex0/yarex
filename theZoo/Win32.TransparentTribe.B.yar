
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_TransparentTribe_B 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_TransparentTribe_B {
	meta: 
		 description= "Win32_TransparentTribe_B Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_22-52-42" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "15da10765b7becfcca3325a91d90db37"
		 hash2= "48476da4403243b342a166d8a6be7a3f"
		 hash3= "53cd72147b0ef6bf6e64d266bf3ccafe"
		 hash4= "6c3308cd8a060327d841626a677a0549"
		 hash5= "d7d6889bfa96724f7b3f951bc06e8c02"

	strings:

	
 		 $s1= "8BFFDB8BB9D}#2.0#0#C:Users" fullword wide
		 $s2= "DocumentSummaryInformation" fullword wide
		 $s3= "spanish-dominican republic" fullword wide
		 $s4= "TableStyleMedium9PivotStyleLight16" fullword wide

		 $hex1= {2473313d2022384246}
		 $hex2= {2473323d2022446f63}
		 $hex3= {2473333d2022737061}
		 $hex4= {2473343d2022546162}

	condition:
		2 of them
}
