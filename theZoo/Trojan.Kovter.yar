
/*
   YARA Rule Set
   Author: resteex
   Identifier: Trojan_Kovter 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Trojan_Kovter {
	meta: 
		 description= "Trojan_Kovter Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-54-09" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "15af6227d39ca3f9d1dcd8566efb0057"

	strings:

	
 		 $s1= "{Additional Info}" fullword wide
		 $s2= "Additional &Metadata..." fullword wide
		 $s3= "&Change Settings..." fullword wide
		 $s4= "Color &Settings:" fullword wide
		 $s5= "Content Copying:" fullword wide
		 $s6= "Conversion Options" fullword wide
		 $s7= "Destination Folder:" fullword wide
		 $s8= "Document Assembly:" fullword wide
		 $s9= "Document Properties" fullword wide
		 $s10= "Document Security" fullword wide
		 $s11= "Documents Layout" fullword wide
		 $s12= "Encryption Method:" fullword wide
		 $s13= "Erase everything" fullword wide
		 $s14= "FileDescription" fullword wide
		 $s15= "LegalTrademarks" fullword wide
		 $s16= "msctls_updown32" fullword wide
		 $s17= "&Multiple Documents" fullword wide
		 $s18= "Opening Documents" fullword wide
		 $s19= "OriginalFilename" fullword wide
		 $s20= "Page background:" fullword wide
		 $s21= "Page Extraction:" fullword wide
		 $s22= "PDF-XChange Viewer" fullword wide
		 $s23= "Saving Documents" fullword wide
		 $s24= "Security &Method:" fullword wide
		 $s25= "Selected &Graphic" fullword wide
		 $s26= "&Selected Pages" fullword wide
		 $s27= "Show Details..." fullword wide
		 $s28= "&Single Document" fullword wide
		 $s29= "&Tabbed Documents" fullword wide
		 $s30= "Toggle StatusBar" fullword wide
		 $s31= "VS_VERSION_INFO" fullword wide

		 $hex1= {247331303d2022446f}
		 $hex2= {247331313d2022446f}
		 $hex3= {247331323d2022456e}
		 $hex4= {247331333d20224572}
		 $hex5= {247331343d20224669}
		 $hex6= {247331353d20224c65}
		 $hex7= {247331363d20226d73}
		 $hex8= {247331373d2022264d}
		 $hex9= {247331383d20224f70}
		 $hex10= {247331393d20224f72}
		 $hex11= {2473313d20227b4164}
		 $hex12= {247332303d20225061}
		 $hex13= {247332313d20225061}
		 $hex14= {247332323d20225044}
		 $hex15= {247332333d20225361}
		 $hex16= {247332343d20225365}
		 $hex17= {247332353d20225365}
		 $hex18= {247332363d20222653}
		 $hex19= {247332373d20225368}
		 $hex20= {247332383d20222653}
		 $hex21= {247332393d20222654}
		 $hex22= {2473323d2022416464}
		 $hex23= {247333303d2022546f}
		 $hex24= {247333313d20225653}
		 $hex25= {2473333d2022264368}
		 $hex26= {2473343d2022436f6c}
		 $hex27= {2473353d2022436f6e}
		 $hex28= {2473363d2022436f6e}
		 $hex29= {2473373d2022446573}
		 $hex30= {2473383d2022446f63}
		 $hex31= {2473393d2022446f63}

	condition:
		3 of them
}
