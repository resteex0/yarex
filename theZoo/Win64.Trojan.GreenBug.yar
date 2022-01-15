
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win64_Trojan_GreenBug 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win64_Trojan_GreenBug {
	meta: 
		 description= "Win64_Trojan_GreenBug Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-55-22" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "786e61331a1e84b7fe26c254de0280ad"

	strings:

	
 		 $s1= "american english" fullword wide
		 $s2= "american-english" fullword wide
		 $s3= "chinese-hongkong" fullword wide
		 $s4= "chinese-simplified" fullword wide
		 $s5= "chinese-singapore" fullword wide
		 $s6= "chinese-traditional" fullword wide
		 $s7= "english-american" fullword wide
		 $s8= "english-caribbean" fullword wide
		 $s9= "english-jamaica" fullword wide
		 $s10= "english-south africa" fullword wide
		 $s11= "french-canadian" fullword wide
		 $s12= "french-luxembourg" fullword wide
		 $s13= "german-austrian" fullword wide
		 $s14= "german-lichtenstein" fullword wide
		 $s15= "german-luxembourg" fullword wide
		 $s16= "MicrosoftWindows" fullword wide
		 $s17= "MicrosoftWindowsCRMFiles" fullword wide
		 $s18= "MicrosoftwindowsTmp98871" fullword wide
		 $s19= "MicrosoftWindowsTmp9932u1.bat" fullword wide
		 $s20= "MicrosoftWindowsTmpFiles" fullword wide
		 $s21= "MicrosoftWindowsTmpFiles" fullword wide
		 $s22= "MicrosoftWindowsTmpFiles" fullword wide
		 $s23= "norwegian-bokmal" fullword wide
		 $s24= "norwegian-nynorsk" fullword wide
		 $s25= "portuguese-brazilian" fullword wide
		 $s26= "spanish-argentina" fullword wide
		 $s27= "spanish-bolivia" fullword wide
		 $s28= "spanish-colombia" fullword wide
		 $s29= "spanish-costa rica" fullword wide
		 $s30= "spanish-dominican republic" fullword wide
		 $s31= "spanish-ecuador" fullword wide
		 $s32= "spanish-el salvador" fullword wide
		 $s33= "spanish-guatemala" fullword wide
		 $s34= "spanish-honduras" fullword wide
		 $s35= "spanish-mexican" fullword wide
		 $s36= "spanish-nicaragua" fullword wide
		 $s37= "spanish-paraguay" fullword wide
		 $s38= "spanish-puerto rico" fullword wide
		 $s39= "spanish-uruguay" fullword wide
		 $s40= "spanish-venezuela" fullword wide
		 $s41= "swedish-finland" fullword wide

		 $hex1= {247331303d2022656e}
		 $hex2= {247331313d20226672}
		 $hex3= {247331323d20226672}
		 $hex4= {247331333d20226765}
		 $hex5= {247331343d20226765}
		 $hex6= {247331353d20226765}
		 $hex7= {247331363d20224d69}
		 $hex8= {247331373d20224d69}
		 $hex9= {247331383d20224d69}
		 $hex10= {247331393d20224d69}
		 $hex11= {2473313d2022616d65}
		 $hex12= {247332303d20224d69}
		 $hex13= {247332313d20224d69}
		 $hex14= {247332323d20224d69}
		 $hex15= {247332333d20226e6f}
		 $hex16= {247332343d20226e6f}
		 $hex17= {247332353d2022706f}
		 $hex18= {247332363d20227370}
		 $hex19= {247332373d20227370}
		 $hex20= {247332383d20227370}
		 $hex21= {247332393d20227370}
		 $hex22= {2473323d2022616d65}
		 $hex23= {247333303d20227370}
		 $hex24= {247333313d20227370}
		 $hex25= {247333323d20227370}
		 $hex26= {247333333d20227370}
		 $hex27= {247333343d20227370}
		 $hex28= {247333353d20227370}
		 $hex29= {247333363d20227370}
		 $hex30= {247333373d20227370}
		 $hex31= {247333383d20227370}
		 $hex32= {247333393d20227370}
		 $hex33= {2473333d2022636869}
		 $hex34= {247334303d20227370}
		 $hex35= {247334313d20227377}
		 $hex36= {2473343d2022636869}
		 $hex37= {2473353d2022636869}
		 $hex38= {2473363d2022636869}
		 $hex39= {2473373d2022656e67}
		 $hex40= {2473383d2022656e67}
		 $hex41= {2473393d2022656e67}

	condition:
		5 of them
}
