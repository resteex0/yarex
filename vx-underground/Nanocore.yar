
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Nanocore 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Nanocore {
	meta: 
		 description= "vx_underground2_Nanocore Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-11-48" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "15a6502124a4b7573c45d96f041b950f"
		 hash2= "6a0ca26944e0c0e44d2b37796c7eaf36"
		 hash3= "79f4447b49c5da0c064ba4ffec154b0d"
		 hash4= "c076cac87cfb3582c53f4a7244a893d3"
		 hash5= "c99a2c278e2c345bc20d4a5a1a91ad89"

	strings:

	
 		 $s1= "$this.AutoScaleDimensions" fullword wide
		 $s2= "8=8>8?8@8A8B8C8" fullword wide
		 $s3= "broadWayToolStripMenuItem" fullword wide
		 $s4= "colorBackgroundToolStripMenuItem" fullword wide
		 $s5= "colorSelectBackgroundToolStripMenuItem" fullword wide
		 $s6= "colorSelectTextToolStripMenuItem" fullword wide
		 $s7= "colorTextToolStripMenuItem" fullword wide
		 $s8= "colorTextToolStripMenuItem1" fullword wide
		 $s9= "deleteTabToolStripMenuItem" fullword wide
		 $s10= "findNextToolStripMenuItem" fullword wide
		 $s11= "Font_toolStripDropDownButton" fullword wide
		 $s12= "Font_toolStripDropDownButton.Image" fullword wide
		 $s13= "https://www.bing.com/search?q=" fullword wide
		 $s14= "https://www.google.com/search?q=" fullword wide
		 $s15= "languageToolStripMenuItem" fullword wide
		 $s16= "newWindowToolStripMenuItem" fullword wide
		 $s17= "pageSetupToolStripMenuItem" fullword wide
		 $s18= "PaintApp.Properties.Resources" fullword wide
		 $s19= "rectangleToolStripMenuItem" fullword wide
		 $s20= "renameTabToolStripMenuItem" fullword wide
		 $s21= "roundRectToolStripMenuItem" fullword wide
		 $s22= "searchWithBingToolStripMenuItem" fullword wide
		 $s23= "searchWithGoogleToolStripMenuItem" fullword wide
		 $s24= "selectAllToolStripMenuItem" fullword wide
		 $s25= "sendFeedbackToolStripMenuItem" fullword wide
		 $s26= "statusBarToolStripMenuItem" fullword wide
		 $s27= "Tetris.Properties.Resources" fullword wide
		 $s28= "timeDateToolStripMenuItem" fullword wide
		 $s29= "timesNewRomanToolStripMenuItem" fullword wide
		 $s30= "toolStripDropDownButton1.Image" fullword wide
		 $s31= "toolStripDropDownButton2.Image" fullword wide
		 $s32= "toolStripDropDownButton3.Image" fullword wide
		 $s33= "viewHelpToolStripMenuItem" fullword wide
		 $s34= "width10toolStripMenuItem3" fullword wide
		 $s35= "wordWrapToolStripMenuItem" fullword wide

		 $hex1= {247331303d20226669}
		 $hex2= {247331313d2022466f}
		 $hex3= {247331323d2022466f}
		 $hex4= {247331333d20226874}
		 $hex5= {247331343d20226874}
		 $hex6= {247331353d20226c61}
		 $hex7= {247331363d20226e65}
		 $hex8= {247331373d20227061}
		 $hex9= {247331383d20225061}
		 $hex10= {247331393d20227265}
		 $hex11= {2473313d2022247468}
		 $hex12= {247332303d20227265}
		 $hex13= {247332313d2022726f}
		 $hex14= {247332323d20227365}
		 $hex15= {247332333d20227365}
		 $hex16= {247332343d20227365}
		 $hex17= {247332353d20227365}
		 $hex18= {247332363d20227374}
		 $hex19= {247332373d20225465}
		 $hex20= {247332383d20227469}
		 $hex21= {247332393d20227469}
		 $hex22= {2473323d2022383d38}
		 $hex23= {247333303d2022746f}
		 $hex24= {247333313d2022746f}
		 $hex25= {247333323d2022746f}
		 $hex26= {247333333d20227669}
		 $hex27= {247333343d20227769}
		 $hex28= {247333353d2022776f}
		 $hex29= {2473333d202262726f}
		 $hex30= {2473343d2022636f6c}
		 $hex31= {2473353d2022636f6c}
		 $hex32= {2473363d2022636f6c}
		 $hex33= {2473373d2022636f6c}
		 $hex34= {2473383d2022636f6c}
		 $hex35= {2473393d202264656c}

	condition:
		23 of them
}
