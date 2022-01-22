
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_Dridex 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_Dridex {
	meta: 
		 description= "APT_Sample_Dridex Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-22_17-55-27" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "6164228ed2cc0eceba9ce1828d87d827"
		 hash2= "925da3a10f7dde802c8d87047b14fda6"
		 hash3= "97a26d9e3598fea2e1715c6c77b645c2"
		 hash4= "c26203af4b3e9c81a9e634178b603601"
		 hash5= "ce5cc55792fdd3a3b1b976fafa3a6396"
		 hash6= "dbf96ab40b728c12951d317642fbd9da"
		 hash7= "f38c13c32a66eb461bb2ed07b3a911b2"
		 hash8= "f824211c4989bfe615dcbd07c9171a65"

	strings:

	
 		 $s1= "6.1.7600.16385 (win7_rtm.090713-1255)" fullword wide
		 $s2= "Bprocess-allocationslutmechanismswithGChromeusers" fullword wide
		 $s3= "Ericresearchers,Ore-electedNUplandedicatedthe" fullword wide
		 $s4= "ExtensionscontestSPDYsupportR3g" fullword wide
		 $s5= "MainTUsendingh0firstthatuses" fullword wide
		 $s6= "tabspbuttons.thumbnails.gthemtheeH" fullword wide
		 $s7= "Utwebwillno51Chromium).100the" fullword wide
		 $s8= "wchrome:flagspermanent6khasthatbLO" fullword wide
		 $s9= "yamahaneedseither.11368mthatjackass" fullword wide
		 $s10= "ZnperiodicallyGDChrome9sitesweach" fullword wide

		 $hex1= {247331303d20225a6e}
		 $hex2= {2473313d2022362e31}
		 $hex3= {2473323d2022427072}
		 $hex4= {2473333d2022457269}
		 $hex5= {2473343d2022457874}
		 $hex6= {2473353d20224d6169}
		 $hex7= {2473363d2022746162}
		 $hex8= {2473373d2022557477}
		 $hex9= {2473383d2022776368}
		 $hex10= {2473393d202279616d}

	condition:
		6 of them
}
