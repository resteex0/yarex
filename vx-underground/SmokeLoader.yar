
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_SmokeLoader 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_SmokeLoader {
	meta: 
		 description= "vx_underground2_SmokeLoader Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-17-20" 
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
		 $a1= "cahenokejocijugujinugacokimugizirafehewisamiwetutonuwacogohatudo" fullword ascii
		 $a2= "C:juxisemiv6sefehoy-foyifugew36tadimoviyoruzwosal1.pdb" fullword ascii

		 $hex1= {2461313d2022636168}
		 $hex2= {2461323d2022433a6a}
		 $hex3= {2473313d2022706f64}
		 $hex4= {2473323d202253454a}
		 $hex5= {2473333d202254696c}
		 $hex6= {2473343d2022746978}

	condition:
		4 of them
}
