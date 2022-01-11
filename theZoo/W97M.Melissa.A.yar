
/*
   YARA Rule Set
   Author: resteex
   Identifier: W97M_Melissa_A 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W97M_Melissa_A {
	meta: 
		 description= "W97M_Melissa_A Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-31-23" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2010fa68a815f95ebe2f23dabfe9a996"
		 hash2= "3cdd16d0a848bdd592eb3b8cefebe882"
		 hash3= "4b68fdec8e89b3983ceb5190a2924003"
		 hash4= "7017cfee58da42d83f578a0bb0067798"
		 hash5= "bbcec7128791e6274238e391c6213471"

	strings:

	
 		 $s1= "1Normal.Melissa" fullword wide
		 $s2= "{572858EA-36DD-11D2-885F-004033E0078E}" fullword wide
		 $s3= "73 sites in this list" fullword wide
		 $s4= "Adult Website Passwords" fullword wide
		 $s5= "BA332.DLL#Visual Basic For Applications" fullword wide
		 $s6= "C:WINDOWSDesktopList0819.doc" fullword wide
		 $s7= "C:WINDOWSDesktoplist.doc" fullword wide
		 $s8= "C:WINDOWSDesktopP0.doc" fullword wide
		 $s9= "Default Paragraph Font" fullword wide
		 $s10= "DocumentSummaryInformation" fullword wide
		 $s11= "*G{00020430-0000-0000-C000-000000000046}#2.0#0#C:WINDOWSSYSTEMstdole2.tlb" fullword wide
		 $s12= "*G{000204EF-0000-0000-C000-000000000046}#3.0#9#C:PROGRAM FILESCOMMON FILESMICROSOFT SHAREDVBAV" fullword wide
		 $s13= "*G{00020905-0000-0000-C000-000000000046}#8.0#409#C:Program FilesMicrosoft OfficeOfficeMSWORD8.O" fullword wide
		 $s14= "*G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.0#0#C:PROGRAM FILESMICROSOFT OFFICEOFFICEMSO97.DLL#M" fullword wide
		 $s15= "*G{3D459962-E1B4-11D2-9EBA-004033E0078E}#2.0#0#C:WINDOWSSYSTEMMSForms.TWD#Microsoft Forms 2.0 Ob" fullword wide
		 $s16= "*G{3D459963-E1B4-11D2-9EBA-004033E0078E}#2.0#0#G:tempVBEMSForms.EXD#Microsoft Forms 2.0 Object L" fullword wide
		 $s17= "icrosoft Office 8.0 Object Library" fullword wide
		 $s18= "LB#Microsoft Word 8.0 Object Library" fullword wide
		 $s19= "#OLE Automation" fullword wide
		 $s20= "!Password List for August 19, 1998" fullword wide
		 $s21= "SummaryInformation" fullword wide
		 $s22= "Times New Roman" fullword wide
		 $a1= "------------------------------------------------" fullword ascii
		 $a2= "C:WINDOWSSYSTEMMSForms.TWD" fullword ascii
		 $a3= "C:WINDOWSSYSTEMstdole2.tlb" fullword ascii
		 $a4= "Document=Melissa/&H00000000" fullword ascii
		 $a5= "&H00000001={3832D640-CF90-11CF-8E43-00A0C911005A};VBE;&H00000000" fullword ascii
		 $a6= "HKEY_CURRENT_USERSoftwareMicrosoftOffice" fullword ascii
		 $a7= "HKEY_CURRENT_USERSoftwareMicrosoftOffice9.0WordSecurity" fullword ascii

		 $hex1= {2461313d20222d2d2d}
		 $hex2= {2461323d2022433a57}
		 $hex3= {2461333d2022433a57}
		 $hex4= {2461343d2022446f63}
		 $hex5= {2461353d2022264830}
		 $hex6= {2461363d2022484b45}
		 $hex7= {2461373d2022484b45}
		 $hex8= {247331303d2022446f}
		 $hex9= {247331313d20222a47}
		 $hex10= {247331323d20222a47}
		 $hex11= {247331333d20222a47}
		 $hex12= {247331343d20222a47}
		 $hex13= {247331353d20222a47}
		 $hex14= {247331363d20222a47}
		 $hex15= {247331373d20226963}
		 $hex16= {247331383d20224c42}
		 $hex17= {247331393d2022234f}
		 $hex18= {2473313d2022314e6f}
		 $hex19= {247332303d20222150}
		 $hex20= {247332313d20225375}
		 $hex21= {247332323d20225469}
		 $hex22= {2473323d20227b3537}
		 $hex23= {2473333d2022373320}
		 $hex24= {2473343d2022416475}
		 $hex25= {2473353d2022424133}
		 $hex26= {2473363d2022433a57}
		 $hex27= {2473373d2022433a57}
		 $hex28= {2473383d2022433a57}
		 $hex29= {2473393d2022446566}

	condition:
		3 of them
}
