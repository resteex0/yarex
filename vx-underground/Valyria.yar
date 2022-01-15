
/*
   YARA Rule Set
   Author: resteex
   Identifier: Valyria 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Valyria {
	meta: 
		 description= "Valyria Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-19-11" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "03838097f3d8dda6ecfa16b0d962c69d"
		 hash2= "599ca0ac39275450110826612f2e7afe"
		 hash3= "6ccee1577e173df379620a9c11766cf5"
		 hash4= "88db701ebe8c84654bfcb5b3a7c3cf10"
		 hash5= "a411479d9de4f5c8bcc364d6adad2854"
		 hash6= "aff93b04065918031cbc82aa0c44ebc9"
		 hash7= "d679532a2b0796fbf2cab5884e646839"

	strings:

	
 		 $s1= "DocumentSummaryInformation" fullword wide
		 $s2= "mailto:michael@emotrans.com.au" fullword wide
		 $s3= "TableStyleMedium2PivotStyleLight16" fullword wide

		 $hex1= {2473313d2022446f63}
		 $hex2= {2473323d20226d6169}
		 $hex3= {2473333d2022546162}

	condition:
		2 of them
}
