
/*
   YARA Rule Set
   Author: resteex
   Identifier: X97M_Sugar_A 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_X97M_Sugar_A {
	meta: 
		 description= "X97M_Sugar_A Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-35-45" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "051f2f03d0ad1f8931d3ebaef24850d6"
		 hash2= "4635b30179f9cf8fbf2e1e3f4bf1490b"
		 hash3= "c441cafdba84b56b63004272caa037a4"
		 hash4= "d374c8da41b5008b28483133a31c0738"
		 hash5= "fed7b61bd85e989dbfa6b8238a1f4550"

	strings:

	
 		 $s1= "-000000000046}#1.2#0#C:Program FilesMicrosoft OfficeOfficeEXCEL8.OLB#Microsoft Excel 8.0 Object " fullword wide
		 $s2= "{97D0B946-8ABD-11D2-B33C-0000F64898E0}" fullword wide
		 $s3= "BA332.dll#Visual Basic For Applications" fullword wide
		 $s4= "DocumentSummaryInformation" fullword wide
		 $s5= "*G{00020430-0000-0000-C000-000000000046}#2.0#0#C:WINNTSystem32StdOle2.tlb#OLE Automation" fullword wide
		 $s6= "*G{000204EF-0000-0000-C000-000000000046}#3.0#9#C:Program FilesCommon FilesMicrosoft SharedVBAV" fullword wide
		 $s7= "*G{00020813-0000-0000-C000-000000000046}#1.2#0#C:Program FilesMicrosoft OfficeOfficeEXCEL8.OLB#" fullword wide
		 $s8= "*G{033636B8-700C-11D2-B324-0000F64898E0}#2.0#0#C:TEMPVBEMSForms.EXD#Microsoft Forms 2.0 Object L" fullword wide
		 $s9= "*G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.0#0#C:Program FilesMicrosoft OfficeOFFICEMSO97.DLL#M" fullword wide
		 $s10= "*G{AB597880-6F50-11D2-B321-0000F64898E0}#2.0#0#C:WINNTSystem32MSForms.TWD#Microsoft Forms 2.0 Ob" fullword wide
		 $s11= "icrosoft Office 8.0 Object Library" fullword wide
		 $s12= "Microsoft Excel 8.0 Object Library" fullword wide
		 $s13= "N0{00020819-0000-0000-C000-000000000046}" fullword wide
		 $s14= "N0{00020820-0000-0000-C000-000000000046}" fullword wide
		 $s15= "SummaryInformation" fullword wide
		 $s16= "_VBA_PROJECT_CUR" fullword wide
		 $a1= "'=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-'" fullword ascii
		 $a2= "------------------------------------------------" fullword ascii
		 $a3= "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-'" fullword ascii
		 $a4= "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" fullword ascii
		 $a5= "Document=Sheet1/&H00000000" fullword ascii
		 $a6= "Document=Sheet2/&H00000000" fullword ascii
		 $a7= "Document=Sheet3/&H00000000" fullword ascii
		 $a8= "Document=ThisWorkbook/&H00000000" fullword ascii
		 $a9= "&H00000001={3832D640-CF90-11CF-8E43-00A0C911005A};VBE;&H00000000" fullword ascii
		 $a10= "Workbook_WindowDeactivatehs" fullword ascii

		 $hex1= {246131303d2022576f}
		 $hex2= {2461313d2022273d2d}
		 $hex3= {2461323d20222d2d2d}
		 $hex4= {2461333d20223d2d3d}
		 $hex5= {2461343d20223d2d3d}
		 $hex6= {2461353d2022446f63}
		 $hex7= {2461363d2022446f63}
		 $hex8= {2461373d2022446f63}
		 $hex9= {2461383d2022446f63}
		 $hex10= {2461393d2022264830}
		 $hex11= {247331303d20222a47}
		 $hex12= {247331313d20226963}
		 $hex13= {247331323d20224d69}
		 $hex14= {247331333d20224e30}
		 $hex15= {247331343d20224e30}
		 $hex16= {247331353d20225375}
		 $hex17= {247331363d20225f56}
		 $hex18= {2473313d20222d3030}
		 $hex19= {2473323d20227b3937}
		 $hex20= {2473333d2022424133}
		 $hex21= {2473343d2022446f63}
		 $hex22= {2473353d20222a477b}
		 $hex23= {2473363d20222a477b}
		 $hex24= {2473373d20222a477b}
		 $hex25= {2473383d20222a477b}
		 $hex26= {2473393d20222a477b}

	condition:
		3 of them
}
