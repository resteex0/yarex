
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Win32_Powerstats 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Win32_Powerstats {
	meta: 
		 description= "theZoo_Win32_Powerstats Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-36-44" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2c3a634953a9a2c227a51e8eeac9f137"
		 hash2= "66c783e41480e65e287081ff853cc737"
		 hash3= "7ed6c5e8c3ec4f9499eb793d69a06758"
		 hash4= "b100c0cfbe59fa66cbb75de65c505ce2"
		 hash5= "b9ee416f2d9557be692abf448bf2f937"

	strings:

	
 		 $s1= "{084F01FA-E634-4D77-83EE-074817C03581}" fullword wide
		 $s2= "{133619e4-143b-463a-b809-b1f51d05f973}" fullword wide
		 $s3= "-2] #,##0.00_);[Red]([$" fullword wide
		 $s4= "DocumentSummaryInformation" fullword wide
		 $s5= "TableStyleMedium2PivotStyleLight16" fullword wide

		 $hex1= {2473313d20227b3038}
		 $hex2= {2473323d20227b3133}
		 $hex3= {2473333d20222d325d}
		 $hex4= {2473343d2022446f63}
		 $hex5= {2473353d2022546162}

	condition:
		3 of them
}
