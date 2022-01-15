
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
		 date = "2022-01-14_22-52-05" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1146e8aa5c88b4e0fa967154d0e4b435"
		 hash2= "5dced08f340d380c7c2c49ece988caf6"
		 hash3= "f8a707e654520ab1b95ea6e23474747f"

	strings:

	
 		 $s1= "{11058097-9912-11D2-8861-004" fullword wide
		 $s2= "{11058097-9912-11D2-8861-004033E0078E}" fullword wide
		 $s3= "Application.Quit SaveChanges:=wdDoNotSaveChanges" fullword wide
		 $s4= "DocumentSummaryInformation" fullword wide
		 $s5= "HKEY_CURRENT_USERSoftwareMicrosoftOffice9.0WordSecurity" fullword wide
		 $a1= "HKEY_CURRENT_USERSoftwareMicrosoftOffice9.0WordSecurity" fullword ascii

		 $hex1= {2461313d2022484b45}
		 $hex2= {2473313d20227b3131}
		 $hex3= {2473323d20227b3131}
		 $hex4= {2473333d2022417070}
		 $hex5= {2473343d2022446f63}
		 $hex6= {2473353d2022484b45}

	condition:
		4 of them
}
