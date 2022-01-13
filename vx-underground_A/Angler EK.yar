
/*
   YARA Rule Set
   Author: resteex
   Identifier: Angler EK 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Angler_EK {
	meta: 
		 description= "Angler EK Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-12_19-48-57" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "061c086a4da72ecaf5475c862f178f9d"
		 hash2= "16ac6fc55ab027f64d50da928fea49ec"
		 hash3= "3be3cc195f6a806dd9d1d20b14a31c05"
		 hash4= "660fa2c94544ae8666f7c9fb2b203b9a"
		 hash5= "754b9bf394046bd6a944c50f57774963"
		 hash6= "8731d5f453049e2df7e781d43fdcf0cb"
		 hash7= "9addc79d6a9f532d210ba635699a8aa1"
		 hash8= "a4daa7bf178006b1e328286645f6d048"
		 hash9= "b3a3f2f880ffd8708390d7a65e96fdc7"
		 hash10= "c9a500e37e7861196e2f7645c0620fae"
		 hash11= "e186f5bc8dffe398f17f1f5995b403f5"
		 hash12= "e44f53083aa263f0ef4c8502f1402500"

	strings:

	
 		 $s1= "6.2.9200.16384 (win8_rtm.120725-1247)" fullword wide
		 $s2= "About4Quit the application; prompts to save documents" fullword wide
		 $s3= "Arranges icons in a grid." fullword wide
		 $s4= "Change the window position" fullword wide
		 $s5= "'Close print preview mode" fullword wide
		 $s6= "Close the active document" fullword wide
		 $s7= "Copy1Cut the selection and put it on the Clipboard" fullword wide
		 $s8= "Copyright (C) 2014 - Marc Ochsenmeier" fullword wide
		 $s9= "dbghelp.amd64,6.2.9200.1638" fullword wide
		 $s10= "/Display items by using small icons." fullword wide
		 $s11= "?Display program information, version number and copyright" fullword wide
		 $s12= "Displays items in a list." fullword wide
		 $s13= "Erase All3Copy the selection and put it on the Clipboard" fullword wide
		 $s14= "F3LMVL7k tKR5vR d1FH506 n7R" fullword wide
		 $s15= "iM0n W21J9pX1 X3D7obSb b8qi" fullword wide
		 $s16= "Insert Clipboard contents" fullword wide
		 $s17= "ListDDisplays detailed information about each item in the window." fullword wide
		 $s18= "Next Pane5Switch back to the previous window pane" fullword wide
		 $s19= "NVIDIA Windows Display Driver Installer" fullword wide
		 $s20= "Open an existing document" fullword wide
		 $s21= "Page Setup3Change the printer and printing options" fullword wide
		 $s22= "Please wait while Setup is loading..." fullword wide
		 $s23= "Print the active document" fullword wide
		 $s24= "q4C0e FYI1km CN596oF C82246v" fullword wide
		 $s25= "Reduce the window to an icon" fullword wide
		 $s26= "Repeat1Replace specific text with different text" fullword wide
		 $s27= "Replace%Select the entire document" fullword wide
		 $s28= "!Restore the window to normal size" fullword wide
		 $s29= "s36gO0m9 CHL0954o Lbhl8845" fullword wide
		 $s30= "Save0Save the active document with a new name" fullword wide
		 $s31= "Save As&Change the printing options" fullword wide
		 $s32= "'Show or hide the toolbar" fullword wide
		 $s33= "Small Icons/Display items by using large icons." fullword wide
		 $s34= "Sorts the icons alphabetically." fullword wide
		 $s35= "(Split the active window into panes" fullword wide
		 $s36= "(Switch to the next window pane" fullword wide
		 $s37= "Toggle ToolBar,Show or hide the status bar" fullword wide
		 $s38= "Undo&Redo the previously undone action" fullword wide
		 $s39= "Windows Executable Analysis - www.winitor.com" fullword wide
		 $s40= "Windows Executable Anomalies Indicator" fullword wide

		 $hex1= {247331303d20222f44}
		 $hex2= {247331313d20223f44}
		 $hex3= {247331323d20224469}
		 $hex4= {247331333d20224572}
		 $hex5= {247331343d20224633}
		 $hex6= {247331353d2022694d}
		 $hex7= {247331363d2022496e}
		 $hex8= {247331373d20224c69}
		 $hex9= {247331383d20224e65}
		 $hex10= {247331393d20224e56}
		 $hex11= {2473313d2022362e32}
		 $hex12= {247332303d20224f70}
		 $hex13= {247332313d20225061}
		 $hex14= {247332323d2022506c}
		 $hex15= {247332333d20225072}
		 $hex16= {247332343d20227134}
		 $hex17= {247332353d20225265}
		 $hex18= {247332363d20225265}
		 $hex19= {247332373d20225265}
		 $hex20= {247332383d20222152}
		 $hex21= {247332393d20227333}
		 $hex22= {2473323d202241626f}
		 $hex23= {247333303d20225361}
		 $hex24= {247333313d20225361}
		 $hex25= {247333323d20222753}
		 $hex26= {247333333d2022536d}
		 $hex27= {247333343d2022536f}
		 $hex28= {247333353d20222853}
		 $hex29= {247333363d20222853}
		 $hex30= {247333373d2022546f}
		 $hex31= {247333383d2022556e}
		 $hex32= {247333393d20225769}
		 $hex33= {2473333d2022417272}
		 $hex34= {247334303d20225769}
		 $hex35= {2473343d2022436861}
		 $hex36= {2473353d202227436c}
		 $hex37= {2473363d2022436c6f}
		 $hex38= {2473373d2022436f70}
		 $hex39= {2473383d2022436f70}
		 $hex40= {2473393d2022646267}

	condition:
		5 of them
}
