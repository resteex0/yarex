
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Powerstats 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Powerstats {
	meta: 
		 description= "Win32_Powerstats Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-54-58" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2c3a634953a9a2c227a51e8eeac9f137"
		 hash2= "66c783e41480e65e287081ff853cc737"
		 hash3= "7ed6c5e8c3ec4f9499eb793d69a06758"
		 hash4= "b100c0cfbe59fa66cbb75de65c505ce2"
		 hash5= "b9ee416f2d9557be692abf448bf2f937"

	strings:

	
 		 $s1= "{084F01FA-E634-4D77-83EE-074817C03581}" fullword wide
		 $s2= "{133619e4-143b-463a-b809-b1f51d05f973}" fullword wide
		 $s3= "-2] #,##0.00)" fullword wide
		 $s4= "-2] #,##0.00_);[Red]([$" fullword wide
		 $s5= "Calibri Light1*" fullword wide
		 $s6= "DocumentCryptSecurity" fullword wide
		 $s7= "DocumentOwnerPassword" fullword wide
		 $s8= "DocumentSummaryInformation" fullword wide
		 $s9= "DocumentUserPassword" fullword wide
		 $s10= "Explanatory Text" fullword wide
		 $s11= "Microsoft Excel" fullword wide
		 $s12= "SummaryInformation" fullword wide
		 $s13= "TableStyleMedium2PivotStyleLight16" fullword wide
		 $s14= "_VBA_PROJECT_CUR" fullword wide
		 $a1= "{084F01FA-E634-4D77-83EE-074817C03581}" fullword ascii
		 $a2= "{133619e4-143b-463a-b809-b1f51d05f973}" fullword ascii

		 $hex1= {2461313d20227b3038}
		 $hex2= {2461323d20227b3133}
		 $hex3= {247331303d20224578}
		 $hex4= {247331313d20224d69}
		 $hex5= {247331323d20225375}
		 $hex6= {247331333d20225461}
		 $hex7= {247331343d20225f56}
		 $hex8= {2473313d20227b3038}
		 $hex9= {2473323d20227b3133}
		 $hex10= {2473333d20222d325d}
		 $hex11= {2473343d20222d325d}
		 $hex12= {2473353d202243616c}
		 $hex13= {2473363d2022446f63}
		 $hex14= {2473373d2022446f63}
		 $hex15= {2473383d2022446f63}
		 $hex16= {2473393d2022446f63}

	condition:
		2 of them
}
