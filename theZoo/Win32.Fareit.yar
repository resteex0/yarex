
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Fareit 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Fareit {
	meta: 
		 description= "Win32_Fareit Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-38-52" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "15540d149889539308135fa12bedbcbf"
		 hash2= "1d34d800aa3320dc17a5786f8eec16ee"
		 hash3= "301210d5557d9ba34f401d3ef7a7276f"
		 hash4= "60c01a897dd8d60d3fea002ed3a4b764"
		 hash5= "67e4f5301851646b10a95f65a0b3bacb"
		 hash6= "8953398de47344e9c2727565af8d6f31"
		 hash7= "d883dc7acc192019f220409ee2cadd64"
		 hash8= "df5a394ad60512767d375647dbb82994"
		 hash9= "f1e546fe9d51dc96eb766ec61269edfb"
		 hash10= "f77db63cbed98391027f2525c14e161f"

	strings:

	
 		 $s1= "&Destination folder" fullword wide
		 $s2= "Extraction progress" fullword wide
		 $s3= "FileDescription" fullword wide
		 $s4= "Installation progress" fullword wide
		 $s5= "jmsctls_progress32" fullword wide
		 $s6= "LegalTrademarks" fullword wide
		 $s7= "msctls_progress32" fullword wide
		 $s8= "OriginalFilename" fullword wide
		 $s9= "ProgramFilesDir" fullword wide
		 $s10= "RarHtmlClassName" fullword wide
		 $s11= "RemoveDrive.exe" fullword wide
		 $s12= "REPLACEFILEDLG RENAMEDLG" fullword wide
		 $s13= "Sateira Software" fullword wide
		 $s14= "SeRestorePrivilege" fullword wide
		 $s15= "SeSecurityPrivilege" fullword wide
		 $s16= "SoftwareMicrosoftWindowsCurrentVersion" fullword wide
		 $s17= "SoftwareWinRAR SFX" fullword wide
		 $s18= "__tmp_rar_sfx_access_check_%u" fullword wide
		 $s19= "VS_VERSION_INFO" fullword wide
		 $s20= "winrarsfxmappingfile.tmp" fullword wide
		 $a1= "SoftwareMicrosoftWindowsCurrentVersion" fullword ascii

		 $hex1= {2461313d2022536f66}
		 $hex2= {247331303d20225261}
		 $hex3= {247331313d20225265}
		 $hex4= {247331323d20225245}
		 $hex5= {247331333d20225361}
		 $hex6= {247331343d20225365}
		 $hex7= {247331353d20225365}
		 $hex8= {247331363d2022536f}
		 $hex9= {247331373d2022536f}
		 $hex10= {247331383d20225f5f}
		 $hex11= {247331393d20225653}
		 $hex12= {2473313d2022264465}
		 $hex13= {247332303d20227769}
		 $hex14= {2473323d2022457874}
		 $hex15= {2473333d202246696c}
		 $hex16= {2473343d2022496e73}
		 $hex17= {2473353d20226a6d73}
		 $hex18= {2473363d20224c6567}
		 $hex19= {2473373d20226d7363}
		 $hex20= {2473383d20224f7269}
		 $hex21= {2473393d202250726f}

	condition:
		7 of them
}
