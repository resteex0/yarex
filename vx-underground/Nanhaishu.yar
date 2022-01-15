
/*
   YARA Rule Set
   Author: resteex
   Identifier: Nanhaishu 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Nanhaishu {
	meta: 
		 description= "Nanhaishu Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-15-47" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "97da0784fddfef932d7d31884f088b40"
		 hash2= "c0326d13c9619ebf6ee302cebda6cbfe"
		 hash3= "d1de5bf033ee31da7babc6fa270f55bb"
		 hash4= "e1f88bc02e9bd15cecc7ae97a009e0d2"

	strings:

	
 		 $s1= "DocumentSummaryInformation" fullword wide
		 $s2= "TableStyleMedium9PivotStyleLight16" fullword wide

		 $hex1= {2473313d2022446f63}
		 $hex2= {2473323d2022546162}

	condition:
		1 of them
}
