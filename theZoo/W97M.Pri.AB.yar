
/*
   YARA Rule Set
   Author: resteex
   Identifier: W97M_Pri_AB 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W97M_Pri_AB {
	meta: 
		 description= "W97M_Pri_AB Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-54-24" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1146e8aa5c88b4e0fa967154d0e4b435"
		 hash2= "5dced08f340d380c7c2c49ece988caf6"
		 hash3= "f8a707e654520ab1b95ea6e23474747f"

	strings:

	
 		 $s1= "{11058097-9912-11D2-8861-004" fullword wide
		 $s2= "{11058097-9912-11D2-8861-004033E0078E}" fullword wide
		 $s3= "(1Normal.ThisDocument " fullword wide
		 $s4= "Application.Quit SaveChanges:=wdDoNotSaveChanges" fullword wide
		 $s5= "Ben Dover VicodinES" fullword wide
		 $s6= "DocumentSummaryInformation" fullword wide
		 $s7= "HKEY_CURRENT_USERSoftwareMicrosoftOffice9.0WordSecurity" fullword wide
		 $s8= "Sub ViewVBCode()" fullword wide
		 $s9= "SummaryInformation" fullword wide
		 $a1= "{11058097-9912-11D2-8861-004033E0078E}" fullword ascii
		 $a2= "Application.Quit SaveChanges:=wdDoNotSaveChanges" fullword ascii
		 $a3= "HKEY_CURRENT_USERSoftwareMicrosoftOffice9.0WordSecurity" fullword ascii

		 $hex1= {2461313d20227b3131}
		 $hex2= {2461323d2022417070}
		 $hex3= {2461333d2022484b45}
		 $hex4= {2473313d20227b3131}
		 $hex5= {2473323d20227b3131}
		 $hex6= {2473333d202228314e}
		 $hex7= {2473343d2022417070}
		 $hex8= {2473353d202242656e}
		 $hex9= {2473363d2022446f63}
		 $hex10= {2473373d2022484b45}
		 $hex11= {2473383d2022537562}
		 $hex12= {2473393d202253756d}

	condition:
		1 of them
}
