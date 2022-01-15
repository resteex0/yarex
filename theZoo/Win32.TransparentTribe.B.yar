
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_TransparentTribe_B 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_TransparentTribe_B {
	meta: 
		 description= "Win32_TransparentTribe_B Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-55-11" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "15da10765b7becfcca3325a91d90db37"
		 hash2= "48476da4403243b342a166d8a6be7a3f"
		 hash3= "53cd72147b0ef6bf6e64d266bf3ccafe"
		 hash4= "6c3308cd8a060327d841626a677a0549"
		 hash5= "d7d6889bfa96724f7b3f951bc06e8c02"

	strings:

	
 		 $s1= "8BFFDB8BB9D}#2.0#0#C:Users" fullword wide
		 $s2= "american english" fullword wide
		 $s3= "american-english" fullword wide
		 $s4= "chinese-hongkong" fullword wide
		 $s5= "chinese-simplified" fullword wide
		 $s6= "chinese-singapore" fullword wide
		 $s7= "chinese-traditional" fullword wide
		 $s8= "com.imo.android.imoim" fullword wide
		 $s9= "DocumentSummaryInformation" fullword wide
		 $s10= "english-american" fullword wide
		 $s11= "english-caribbean" fullword wide
		 $s12= "english-jamaica" fullword wide
		 $s13= "english-south africa" fullword wide
		 $s14= "Explanatory Text" fullword wide
		 $s15= "french-canadian" fullword wide
		 $s16= "french-luxembourg" fullword wide
		 $s17= "german-austrian" fullword wide
		 $s18= "german-lichtenstein" fullword wide
		 $s19= "german-luxembourg" fullword wide
		 $s20= "norwegian-bokmal" fullword wide
		 $s21= "norwegian-nynorsk" fullword wide
		 $s22= "portuguese-brazilian" fullword wide
		 $s23= "spanish-argentina" fullword wide
		 $s24= "spanish-bolivia" fullword wide
		 $s25= "spanish-colombia" fullword wide
		 $s26= "spanish-costa rica" fullword wide
		 $s27= "spanish-dominican republic" fullword wide
		 $s28= "spanish-ecuador" fullword wide
		 $s29= "spanish-el salvador" fullword wide
		 $s30= "spanish-guatemala" fullword wide
		 $s31= "spanish-honduras" fullword wide
		 $s32= "spanish-mexican" fullword wide
		 $s33= "spanish-nicaragua" fullword wide
		 $s34= "spanish-paraguay" fullword wide
		 $s35= "spanish-puerto rico" fullword wide
		 $s36= "spanish-uruguay" fullword wide
		 $s37= "spanish-venezuela" fullword wide
		 $s38= "SummaryInformation" fullword wide
		 $s39= "swedish-finland" fullword wide
		 $s40= "TableStyleMedium9PivotStyleLight16" fullword wide
		 $s41= "_VBA_PROJECT_CUR" fullword wide

		 $hex1= {247331303d2022656e}
		 $hex2= {247331313d2022656e}
		 $hex3= {247331323d2022656e}
		 $hex4= {247331333d2022656e}
		 $hex5= {247331343d20224578}
		 $hex6= {247331353d20226672}
		 $hex7= {247331363d20226672}
		 $hex8= {247331373d20226765}
		 $hex9= {247331383d20226765}
		 $hex10= {247331393d20226765}
		 $hex11= {2473313d2022384246}
		 $hex12= {247332303d20226e6f}
		 $hex13= {247332313d20226e6f}
		 $hex14= {247332323d2022706f}
		 $hex15= {247332333d20227370}
		 $hex16= {247332343d20227370}
		 $hex17= {247332353d20227370}
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
		 $hex31= {247333383d20225375}
		 $hex32= {247333393d20227377}
		 $hex33= {2473333d2022616d65}
		 $hex34= {247334303d20225461}
		 $hex35= {247334313d20225f56}
		 $hex36= {2473343d2022636869}
		 $hex37= {2473353d2022636869}
		 $hex38= {2473363d2022636869}
		 $hex39= {2473373d2022636869}
		 $hex40= {2473383d2022636f6d}
		 $hex41= {2473393d2022446f63}

	condition:
		5 of them
}
