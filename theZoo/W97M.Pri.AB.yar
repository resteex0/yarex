
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
		 date = "2022-01-10_19-31-25" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "1146e8aa5c88b4e0fa967154d0e4b435"
		 hash2= "5dced08f340d380c7c2c49ece988caf6"
		 hash3= "f8a707e654520ab1b95ea6e23474747f"

	strings:

	
 		 $s1= "$*Rffff*2=37b08151" fullword wide
		 $s2= "{11058097-9912-11D2-8861-004" fullword wide
		 $s3= "{11058097-9912-11D2-8861-004033E0078E}" fullword wide
		 $s4= "(1Normal.ThisDocument " fullword wide
		 $s5= "Application.Quit SaveChanges:=wdDoNotSaveChanges" fullword wide
		 $s6= "BA6VBE6.DLL#Visual Basic For Applications" fullword wide
		 $s7= "Ben Dover VicodinES" fullword wide
		 $s8= "C:WINDOWSDesktoppsd2.doc VicodinES)C:WINDOWSDesktopPoppy 2000psd2000.doc" fullword wide
		 $s9= "Default Paragraph Font" fullword wide
		 $s10= "DocumentSummaryInformation" fullword wide
		 $s11= "e 8.0 Object Library" fullword wide
		 $s12= "*G{00020430-0000-0000-C000-000000000046}#2.0#0#C:WINDOWSSYSTEMStdOle2.tlb#OLE Automation" fullword wide
		 $s13= "*G{000204EF-0000-0000-C000-000000000046}#4.0#9#C:PROGRAM FILESCOMMON FILESMICROSOFT SHAREDVBAV" fullword wide
		 $s14= "*G{00020905-0000-0000-C000-000000000046}#9.0#0#C:Program FilesMicrosoft OfficeOfficemsword9.olb" fullword wide
		 $s15= "*G{0002E157-0000-0000-C000-000000000046}#5.3#0#......Program FilesCommon FilesMicrosoft Shared" fullword wide
		 $s16= "*G{0D452EE1-E08F-101A-852E-02608C4D0BB4}#2.0#0#C:WINDOWSSYSTEMFM20.DLL#Microsoft Forms 2.0 Objec" fullword wide
		 $s17= "*G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.1#0#E:MICROSOFT OFFICEOFFICEMSO97.DLL#Microsoft Offic" fullword wide
		 $s18= "*G{F431D1C7-9C2E-11D2-B78D-00805F012932}#2.0#0#C:WINDOWSTEMPVBEMSForms.exd#Microsoft Forms 2.0 " fullword wide
		 $s19= "HKEY_CURRENT_USERSoftwareMicrosoftOffice9.0WordSecurity" fullword wide
		 $s20= "#Microsoft Word 9.0 Object Library" fullword wide
		 $s21= "Private Sub Document_Close()" fullword wide
		 $s22= "Private Sub Document_Open()" fullword wide
		 $s23= "Sub ViewVBCode()" fullword wide
		 $s24= "SummaryInformation" fullword wide
		 $s25= "Times New Roman" fullword wide
		 $s26= "tions Extensibility 5.3*#1b" fullword wide
		 $s27= "VBAVBA6vbe6ext.olb#Microsoft Visual Basic for Applica" fullword wide
		 $s28= "VBAVBA6vbe6ext.olb#Microsoft Visual Basic for Applications Extensibility 5.3*#25" fullword wide
		 $s29= "VBAVBA6vbe6ext.olb#Microsoft Visual Basic for Applications Extensibility 5.3*#2a" fullword wide
		 $s30= "VBAVBA6vbe6ext.olb#Microsoft Visual Basic for Applications Extensibility 5.3*#34" fullword wide
		 $a1= "------------------------------------------------" fullword ascii
		 $a2= "C:WINDOWSSYSTEMFM20.DLL" fullword ascii
		 $a3= "C:WINDOWSSYSTEMStdOle2.tlb" fullword ascii
		 $a4= "C:WINDOWSTEMPVBEMSForms.exd" fullword ascii
		 $a5= "Document=ThisDocument/&H00000000" fullword ascii
		 $a6= "&H00000001={3832D640-CF90-11CF-8E43-00A0C911005A};VBE;&H00000000" fullword ascii
		 $a7= "HKEY_CURRENT_USERSoftwareMicrosoftOffice9.0WordSecurity" fullword ascii

		 $hex1= {2461313d20222d2d2d}
		 $hex2= {2461323d2022433a57}
		 $hex3= {2461333d2022433a57}
		 $hex4= {2461343d2022433a57}
		 $hex5= {2461353d2022446f63}
		 $hex6= {2461363d2022264830}
		 $hex7= {2461373d2022484b45}
		 $hex8= {247331303d2022446f}
		 $hex9= {247331313d20226520}
		 $hex10= {247331323d20222a47}
		 $hex11= {247331333d20222a47}
		 $hex12= {247331343d20222a47}
		 $hex13= {247331353d20222a47}
		 $hex14= {247331363d20222a47}
		 $hex15= {247331373d20222a47}
		 $hex16= {247331383d20222a47}
		 $hex17= {247331393d2022484b}
		 $hex18= {2473313d2022242a52}
		 $hex19= {247332303d2022234d}
		 $hex20= {247332313d20225072}
		 $hex21= {247332323d20225072}
		 $hex22= {247332333d20225375}
		 $hex23= {247332343d20225375}
		 $hex24= {247332353d20225469}
		 $hex25= {247332363d20227469}
		 $hex26= {247332373d20225642}
		 $hex27= {247332383d20225642}
		 $hex28= {247332393d20225642}
		 $hex29= {2473323d20227b3131}
		 $hex30= {247333303d20225642}
		 $hex31= {2473333d20227b3131}
		 $hex32= {2473343d202228314e}
		 $hex33= {2473353d2022417070}
		 $hex34= {2473363d2022424136}
		 $hex35= {2473373d202242656e}
		 $hex36= {2473383d2022433a57}
		 $hex37= {2473393d2022446566}

	condition:
		4 of them
}
