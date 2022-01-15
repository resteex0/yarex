
/*
   YARA Rule Set
   Author: resteex
   Identifier: W97M_Melissa_A 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W97M_Melissa_A {
	meta: 
		 description= "W97M_Melissa_A Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-54-23" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2010fa68a815f95ebe2f23dabfe9a996"
		 hash2= "3cdd16d0a848bdd592eb3b8cefebe882"
		 hash3= "4b68fdec8e89b3983ceb5190a2924003"
		 hash4= "7017cfee58da42d83f578a0bb0067798"
		 hash5= "bbcec7128791e6274238e391c6213471"

	strings:

	
 		 $s1= "1Normal.Melissa" fullword wide
		 $s2= "{572858EA-36DD-11D2-885F-004033E0078E}" fullword wide
		 $s3= "C:WINDOWSDesktopList0819.doc" fullword wide
		 $s4= "C:WINDOWSDesktoplist.doc" fullword wide
		 $s5= "C:WINDOWSDesktopP0.doc" fullword wide
		 $s6= "DocumentSummaryInformation" fullword wide
		 $s7= "#OLE Automation" fullword wide
		 $s8= "SummaryInformation" fullword wide
		 $a1= "{572858EA-36DD-11D2-885F-004033E0078E}" fullword ascii

		 $hex1= {2461313d20227b3537}
		 $hex2= {2473313d2022314e6f}
		 $hex3= {2473323d20227b3537}
		 $hex4= {2473333d2022433a57}
		 $hex5= {2473343d2022433a57}
		 $hex6= {2473353d2022433a57}
		 $hex7= {2473363d2022446f63}
		 $hex8= {2473373d2022234f4c}
		 $hex9= {2473383d202253756d}

	condition:
		1 of them
}
