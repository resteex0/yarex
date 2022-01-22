
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_MuddyWaterAPT 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_MuddyWaterAPT {
	meta: 
		 description= "APT_Sample_MuddyWaterAPT Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-22_17-57-06" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0cf25597343240f88358c694d7ae7e0a"
		 hash2= "5b5b3cb0948ee56ea761ed31d53c29ad"
		 hash3= "ca9230a54f40a6a0fe52d7379459189c"

	strings:

	
 		 $s1= "052103123124134106130133126117130130126065120" fullword wide
		 $s2= "084118118120134134105085098096" fullword wide
		 $s3= "084118135124137120106130133126117130130126" fullword wide
		 $s4= "086133120116135120098117125120118135" fullword wide
		 $s5= "087124134131127116140084127120133135134" fullword wide
		 $s6= "087130118136128120129135051088133133130133" fullword wide
		 $s7= "088139118120127065084131131127124118116135124130129" fullword wide
		 $s8= "102120135087106098101087105116127136120" fullword wide
		 $s9= "106130133126117130130126134" fullword wide
		 $s10= "106134118133124131135065102123120127127" fullword wide
		 $s11= "DocumentSummaryInformation" fullword wide

		 $hex1= {247331303d20223130}
		 $hex2= {247331313d2022446f}
		 $hex3= {2473313d2022303532}
		 $hex4= {2473323d2022303834}
		 $hex5= {2473333d2022303834}
		 $hex6= {2473343d2022303836}
		 $hex7= {2473353d2022303837}
		 $hex8= {2473363d2022303837}
		 $hex9= {2473373d2022303838}
		 $hex10= {2473383d2022313032}
		 $hex11= {2473393d2022313036}

	condition:
		7 of them
}
