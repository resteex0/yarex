
/*
   YARA Rule Set
   Author: resteex
   Identifier: Grief 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Grief {
	meta: 
		 description= "Grief Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-05-04" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0c6889688b060544205620fe1fdbfa4d"
		 hash2= "3eed5f9a1d57b6ae71a5d434ea38814d"
		 hash3= "41b279fa879354ce8a47970758efe40a"
		 hash4= "72ba727d7441954ecaefd9732d12a36c"

	strings:

	
 		 $s1= "7HFsubmission.82immediatelyGMVXy" fullword wide
		 $s2= "8ininstalled,kJanuarywarnedwindow5B" fullword wide
		 $s3= "could88that510essentiallyPG" fullword wide
		 $s4= "enwinston0yevenyyAdeprecated" fullword wide
		 $s5= "is3standardizationNmaggieVwasthe" fullword wide
		 $s6= "iwantu123321starwarsmr0enhancedLeaked" fullword wide
		 $s7= "kreplacedshowingBssixaasq" fullword wide
		 $s8= "NoenablekbrevampedbeSincewithqb" fullword wide
		 $s9= "RusersLocalhousegXrelease" fullword wide
		 $s10= "theGharmful.TbOmniboxtabs.68from" fullword wide
		 $s11= "webRPChromewherewintoWebRTC.75are" fullword wide
		 $s12= "WebuextensiontnNbuilt-in).142" fullword wide
		 $s13= "Yfishingeventually8theStopMC" fullword wide

		 $hex1= {247331303d20227468}
		 $hex2= {247331313d20227765}
		 $hex3= {247331323d20225765}
		 $hex4= {247331333d20225966}
		 $hex5= {2473313d2022374846}
		 $hex6= {2473323d202238696e}
		 $hex7= {2473333d2022636f75}
		 $hex8= {2473343d2022656e77}
		 $hex9= {2473353d2022697333}
		 $hex10= {2473363d2022697761}
		 $hex11= {2473373d20226b7265}
		 $hex12= {2473383d20224e6f65}
		 $hex13= {2473393d2022527573}

	condition:
		8 of them
}
