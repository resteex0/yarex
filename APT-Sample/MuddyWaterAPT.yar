
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
		 date = "2022-03-22_14-19-20" 
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

		 $hex1= {303532313033313233}
		 $hex2= {303834313138313138}
		 $hex3= {303834313138313335}
		 $hex4= {303836313333313230}
		 $hex5= {303837313234313334}
		 $hex6= {303837313330313138}
		 $hex7= {303838313339313138}
		 $hex8= {313032313230313335}
		 $hex9= {313036313330313333}
		 $hex10= {313036313334313138}
		 $hex11= {446f63756d656e7453}

	condition:
		7 of them
}
