
/*
   YARA Rule Set
   Author: resteex
   Identifier: W97M_Pri_A 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W97M_Pri_A {
	meta: 
		 description= "W97M_Pri_A Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-31-24" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "20577952428b972fc5103d329b77f4b7"
		 hash2= "44d7ef71a0c02a415f6ddf11ea976de0"
		 hash3= "edbe88b73d582b38690570f032a3e249"

	strings:

	
 		 $s1= "(1Normal.ThisDocument" fullword wide
		 $s2= "BA332.DLL#Visual Basic For Applications" fullword wide
		 $s3= "{C2F40CF1-9808-11D2-8861-004033E0078E}" fullword wide
		 $s4= "Default Paragraph Font" fullword wide
		 $s5= "DocumentSummaryInformation" fullword wide
		 $s6= "e 8.0 Object Library" fullword wide
		 $s7= "*G{00020430-0000-0000-C000-000000000046}#2.0#0#C:WINDOWSSYSTEMStdOle2.tlb#OLE Automation" fullword wide
		 $s8= "*G{000204EF-0000-0000-C000-000000000046}#3.0#9#C:PROGRAM FILESCOMMON FILESMICROSOFT SHAREDVBAV" fullword wide
		 $s9= "*G{00020905-0000-0000-C000-000000000046}#8.0#409#E:microsoft officeOfficeMSWORD8.OLB#Microsoft W" fullword wide
		 $s10= "*G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.0#0#E:MICROSOFT OFFICEOFFICEMSO97.DLL#Microsoft Offic" fullword wide
		 $s11= "*G{73A1DEC2-5DCE-11D2-885F-004033E0078E}#2.0#0#C:WINDOWSTEMPVBEMSForms.EXD#Microsoft Forms 2.0 " fullword wide
		 $s12= "*G{875CACC1-19AD-11D2-885F-A2A3578D9326}#2.0#0#C:WINDOWSSYSTEMMSForms.TWD#Microsoft Forms 2.0 Ob" fullword wide
		 $s13= "ord 8.0 Object Library" fullword wide
		 $s14= "SummaryInformation" fullword wide
		 $s15= "Times New Roman" fullword wide
		 $a1= "------------------------------------------------" fullword ascii
		 $a2= "C:WINDOWSSYSTEMMSForms.TWD" fullword ascii
		 $a3= "C:WINDOWSSYSTEMStdOle2.tlb" fullword ascii
		 $a4= "C:WINDOWSTEMPVBEMSForms.EXD" fullword ascii
		 $a5= "Document=ThisDocument/&H00000000" fullword ascii
		 $a6= "&H00000001={3832D640-CF90-11CF-8E43-00A0C911005A};VBE;&H00000000" fullword ascii
		 $a7= "http://www.symantec.com/avcenter/download.html" fullword ascii

		 $hex1= {2461313d20222d2d2d}
		 $hex2= {2461323d2022433a57}
		 $hex3= {2461333d2022433a57}
		 $hex4= {2461343d2022433a57}
		 $hex5= {2461353d2022446f63}
		 $hex6= {2461363d2022264830}
		 $hex7= {2461373d2022687474}
		 $hex8= {247331303d20222a47}
		 $hex9= {247331313d20222a47}
		 $hex10= {247331323d20222a47}
		 $hex11= {247331333d20226f72}
		 $hex12= {247331343d20225375}
		 $hex13= {247331353d20225469}
		 $hex14= {2473313d202228314e}
		 $hex15= {2473323d2022424133}
		 $hex16= {2473333d20227b4332}
		 $hex17= {2473343d2022446566}
		 $hex18= {2473353d2022446f63}
		 $hex19= {2473363d2022652038}
		 $hex20= {2473373d20222a477b}
		 $hex21= {2473383d20222a477b}
		 $hex22= {2473393d20222a477b}

	condition:
		2 of them
}
