
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
		 date = "2022-03-27_08-12-04" 
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

		 $hex1= {36??2e??31??2e??37??36??30??30??2e??31??36??33??38??35??20??28??77??69??6e??37??5f??72??74??6d??2e??30??39??30??37??31??}
		 $hex2= {42??70??72??6f??63??65??73??73??2d??61??6c??6c??6f??63??61??74??69??6f??6e??73??6c??75??74??6d??65??63??68??61??6e??69??}
		 $hex3= {45??72??69??63??72??65??73??65??61??72??63??68??65??72??73??2c??4f??72??65??2d??65??6c??65??63??74??65??64??4e??55??70??}
		 $hex4= {45??78??74??65??6e??73??69??6f??6e??73??63??6f??6e??74??65??73??74??53??50??44??59??73??75??70??70??6f??72??74??52??33??}
		 $hex5= {4d??61??69??6e??54??55??73??65??6e??64??69??6e??67??68??30??66??69??72??73??74??74??68??61??74??75??73??65??73??0a??}
		 $hex6= {55??74??77??65??62??77??69??6c??6c??6e??6f??35??31??43??68??72??6f??6d??69??75??6d??29??2e??31??30??30??74??68??65??0a??}
		 $hex7= {5a??6e??70??65??72??69??6f??64??69??63??61??6c??6c??79??47??44??43??68??72??6f??6d??65??39??73??69??74??65??73??77??65??}
		 $hex8= {74??61??62??73??70??62??75??74??74??6f??6e??73??2e??74??68??75??6d??62??6e??61??69??6c??73??2e??67??74??68??65??6d??74??}
		 $hex9= {77??63??68??72??6f??6d??65??3a??66??6c??61??67??73??70??65??72??6d??61??6e??65??6e??74??36??6b??68??61??73??74??68??61??}
		 $hex10= {79??61??6d??61??68??61??6e??65??65??64??73??65??69??74??68??65??72??2e??31??31??33??36??38??6d??74??68??61??74??6a??61??}

	condition:
		11 of them
}