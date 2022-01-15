
/*
   YARA Rule Set
   Author: resteex
   Identifier: SmokeLoader 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_SmokeLoader {
	meta: 
		 description= "SmokeLoader Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-18-47" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "66a2a7f0d83b797068895f9fcd2c886c"
		 hash2= "96428fec8fcdc425c07cb6874bfdfa74"
		 hash3= "d5efb3fa1e49790e1ab38141b089e379"
		 hash4= "e2d17019baf2d59634af4c4c219bcfc3"

	strings:

	
 		 $s1= "podofomiwuxofaluzetigijenowucos" fullword wide
		 $s2= "SEJUWUSIZABUTUXAKAYUPIGIGEYOKAHA" fullword wide
		 $s3= "Tilonodagokolul roduvacexir" fullword wide
		 $s4= "tixetusepobirabuxawevomepenetis" fullword wide

		 $hex1= {2473313d2022706f64}
		 $hex2= {2473323d202253454a}
		 $hex3= {2473333d202254696c}
		 $hex4= {2473343d2022746978}

	condition:
		2 of them
}
