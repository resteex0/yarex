
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
		 date = "2022-03-22_12-18-59" 
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

		 $hex1= {362e312e373630302e}
		 $hex2= {4270726f636573732d}
		 $hex3= {457269637265736561}
		 $hex4= {457874656e73696f6e}
		 $hex5= {4d61696e545573656e}
		 $hex6= {557477656277696c6c}
		 $hex7= {5a6e706572696f6469}
		 $hex8= {746162737062757474}
		 $hex9= {776368726f6d653a66}
		 $hex10= {79616d6168616e6565}

	condition:
		2 of them
}
