
/*
   YARA Rule Set
   Author: resteex
   Identifier: W97M_Class_AU 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W97M_Class_AU {
	meta: 
		 description= "W97M_Class_AU Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-31-22" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "345e5ed6361e5f0f6ed521c3f2f3881c"
		 hash2= "58f3e1cb3d85ec986263cc61ea1cfec7"
		 hash3= "5c71303a31853917f08adc37a8ec32eb"
		 hash4= "6dc6f027f195e1c6e39971ea8d33d86f"

	strings:

	
 		 $s1= "(1Normal.ThisDocument" fullword wide
		 $s2= "BA332.DLL#Visual Basic For Applications" fullword wide
		 $s3= "|| C:WINDOWSDesktopVAMP_DEMO.doc" fullword wide
		 $s4= "||%C:WINDOWSDesktopVAMPVAMP_DEMO.doc" fullword wide
		 $s5= "Default Paragraph Font" fullword wide
		 $s6= "DocumentSummaryInformation" fullword wide
		 $s7= "D:sokdemoVAMP_DEMO.doc" fullword wide
		 $s8= "e 8.0 Object Library" fullword wide
		 $s9= "{F7EC565B-91B3-11D2-8861-004033E0078E}" fullword wide
		 $s10= "*G{00020430-0000-0000-C000-000000000046}#2.0#0#C:WINDOWSSYSTEMStdOle2.tlb#OLE Automation" fullword wide
		 $s11= "*G{000204EF-0000-0000-C000-000000000046}#3.0#9#C:PROGRAM FILESCOMMON FILESMICROSOFT SHAREDVBAV" fullword wide
		 $s12= "*G{00020905-0000-0000-C000-000000000046}#8.0#409#E:microsoft officeOfficeMSWORD8.OLB#Microsoft W" fullword wide
		 $s13= "*G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.0#0#E:MICROSOFT OFFICEOFFICEMSO97.DLL#Microsoft Offic" fullword wide
		 $s14= "*G{73A1DEC2-5DCE-11D2-885F-004033E0078E}#2.0#0#C:WINDOWSTEMPVBEMSForms.EXD#Microsoft Forms 2.0 " fullword wide
		 $s15= "*G{875CACC1-19AD-11D2-885F-A2A3578D9326}#2.0#0#C:WINDOWSSYSTEMMSForms.TWD#Microsoft Forms 2.0 Ob" fullword wide
		 $s16= "John Wilkens C:windowsdesktopVAMP_DEMO.doc" fullword wide
		 $s17= "ord 8.0 Object Library" fullword wide
		 $s18= "Project.ThisDocument.AutoOpen" fullword wide
		 $s19= "PROJECT.THISDOCUMENT.AUTOOPEN" fullword wide
		 $s20= "SummaryInformation" fullword wide
		 $s21= "Times New Roman" fullword wide
		 $s22= "VAMP Demo Virus" fullword wide
		 $a1= "'=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-='" fullword ascii
		 $a2= "------------------------------------------------" fullword ascii
		 $a3= "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-='" fullword ascii
		 $a4= "Document=ThisDocument/&H00000000" fullword ascii
		 $a5= "&H00000001={3832D640-CF90-11CF-8E43-00A0C911005A};VBE;&H00000000" fullword ascii

		 $hex1= {2461313d2022273d2d}
		 $hex2= {2461323d20222d2d2d}
		 $hex3= {2461333d20223d2d3d}
		 $hex4= {2461343d2022446f63}
		 $hex5= {2461353d2022264830}
		 $hex6= {247331303d20222a47}
		 $hex7= {247331313d20222a47}
		 $hex8= {247331323d20222a47}
		 $hex9= {247331333d20222a47}
		 $hex10= {247331343d20222a47}
		 $hex11= {247331353d20222a47}
		 $hex12= {247331363d20224a6f}
		 $hex13= {247331373d20226f72}
		 $hex14= {247331383d20225072}
		 $hex15= {247331393d20225052}
		 $hex16= {2473313d202228314e}
		 $hex17= {247332303d20225375}
		 $hex18= {247332313d20225469}
		 $hex19= {247332323d20225641}
		 $hex20= {2473323d2022424133}
		 $hex21= {2473333d20227c7c20}
		 $hex22= {2473343d20227c7c25}
		 $hex23= {2473353d2022446566}
		 $hex24= {2473363d2022446f63}
		 $hex25= {2473373d2022443a73}
		 $hex26= {2473383d2022652038}
		 $hex27= {2473393d20227b4637}

	condition:
		3 of them
}
