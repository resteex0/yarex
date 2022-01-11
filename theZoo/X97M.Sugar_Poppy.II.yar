
/*
   YARA Rule Set
   Author: resteex
   Identifier: X97M_Sugar_Poppy_II 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_X97M_Sugar_Poppy_II {
	meta: 
		 description= "X97M_Sugar_Poppy_II Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-35-46" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "5620fa07c51c3cf57d7b78016f81fa68"
		 hash2= "90b5684d749d3b23b6bac6e592a4c30a"

	strings:

	
 		 $s1= "{97D0B946-8ABD-11D2-B33C-0000F64898E0}" fullword wide
		 $s2= "BA332.dll#Visual Basic For Applications" fullword wide
		 $s3= "DocumentSummaryInformation" fullword wide
		 $s4= "EL8.OLB#Microsoft Excel 8.0 Object Library" fullword wide
		 $s5= "*G{00020430-0000-0000-C000-000000000046}#2.0#0#C:WINNTSystem32StdOle2.tlb#OLE Automation" fullword wide
		 $s6= "*G{000204EF-0000-0000-C000-000000000046}#3.0#9#C:Program FilesCommon FilesMicrosoft SharedVBAV" fullword wide
		 $s7= "*G{00020813-0000-0000-C000-000000000046}#1.2#0#C:Program FilesMicrosoft OfficeOfficeEXC" fullword wide
		 $s8= "*G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.0#0#C:Program FilesMicrosoft OfficeOFFICEMSO97.DLL#M" fullword wide
		 $s9= "*G{73A1DEC2-5DCE-11D2-885F-004033E0078E}#2.0#0#C:WINDOWSTEMPVBEMSForms.EXD#Microsoft Forms 2.0 " fullword wide
		 $s10= "*G{875CACC1-19AD-11D2-885F-A2A3578D9326}#2.0#0#C:WINDOWSSYSTEMMSForms.TWD#Microsoft Forms 2.0 Ob" fullword wide
		 $s11= "icrosoft Office 8.0 Object Library" fullword wide
		 $s12= "N0{00020819-0000-0000-C000-000000000046}" fullword wide
		 $s13= "N0{00020820-0000-0000-C000-000000000046}" fullword wide
		 $s14= "SummaryInformation" fullword wide
		 $s15= "_VBA_PROJECT_CUR" fullword wide
		 $a1= "------------------------------------------------" fullword ascii
		 $a2= "--------------------------------------------------------------------------------" fullword ascii
		 $a3= "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-'" fullword ascii
		 $a4= "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-''" fullword ascii
		 $a5= "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-'" fullword ascii
		 $a6= "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" fullword ascii
		 $a7= "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-'BP" fullword ascii
		 $a8= "C:WINDOWSSYSTEMMSForms.TWD" fullword ascii
		 $a9= "C:WINDOWSTEMPVBEMSForms.EXD" fullword ascii
		 $a10= "C:WINNTSystem32StdOle2.tlb" fullword ascii
		 $a11= "Document=Sheet1/&H00000000" fullword ascii
		 $a12= "Document=Sheet2/&H00000000" fullword ascii
		 $a13= "Document=Sheet3/&H00000000" fullword ascii
		 $a14= "Document=ThisWorkbook/&H00000000" fullword ascii
		 $a15= "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-'ec" fullword ascii
		 $a16= "&H00000001={3832D640-CF90-11CF-8E43-00A0C911005A};VBE;&H00000000" fullword ascii
		 $a17= "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-'kb" fullword ascii
		 $a18= "Normal.ThisDocument.AutoExec " fullword ascii
		 $a19= "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-'va" fullword ascii
		 $a20= "Workbook_WindowDeactivate" fullword ascii
		 $a21= "Workbook_WindowDeactivatehs" fullword ascii

		 $hex1= {246131303d2022433a}
		 $hex2= {246131313d2022446f}
		 $hex3= {246131323d2022446f}
		 $hex4= {246131333d2022446f}
		 $hex5= {246131343d2022446f}
		 $hex6= {246131353d20222d3d}
		 $hex7= {246131363d20222648}
		 $hex8= {246131373d20222d3d}
		 $hex9= {246131383d20224e6f}
		 $hex10= {246131393d20222d3d}
		 $hex11= {2461313d20222d2d2d}
		 $hex12= {246132303d2022576f}
		 $hex13= {246132313d2022576f}
		 $hex14= {2461323d20222d2d2d}
		 $hex15= {2461333d20222d3d2d}
		 $hex16= {2461343d20222d3d2d}
		 $hex17= {2461353d20223d2d3d}
		 $hex18= {2461363d20223d2d3d}
		 $hex19= {2461373d20222d3d2d}
		 $hex20= {2461383d2022433a57}
		 $hex21= {2461393d2022433a57}
		 $hex22= {247331303d20222a47}
		 $hex23= {247331313d20226963}
		 $hex24= {247331323d20224e30}
		 $hex25= {247331333d20224e30}
		 $hex26= {247331343d20225375}
		 $hex27= {247331353d20225f56}
		 $hex28= {2473313d20227b3937}
		 $hex29= {2473323d2022424133}
		 $hex30= {2473333d2022446f63}
		 $hex31= {2473343d2022454c38}
		 $hex32= {2473353d20222a477b}
		 $hex33= {2473363d20222a477b}
		 $hex34= {2473373d20222a477b}
		 $hex35= {2473383d20222a477b}
		 $hex36= {2473393d20222a477b}

	condition:
		4 of them
}
