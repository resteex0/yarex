
/*
   YARA Rule Set
   Author: resteex
   Identifier: PlugX 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_PlugX {
	meta: 
		 description= "PlugX Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-37-42" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "3bc9e9b78ac6dee1a44436859849bbbf"
		 hash2= "3c74a85c2cf883bd9d4b9f8b9746030f"
		 hash3= "5f9f8ac1f749b0637eca6ef15910bf21"
		 hash4= "6b97b3cd2fcfb4b74985143230441463"
		 hash5= "901fa02ffd43de5b2d7c8c6b8c2f6a43"
		 hash6= "97c11e7d6b1926cd4be13804b36239ac"
		 hash7= "c116cd083284cc599c024c3479ca9b70"
		 hash8= "fc88beeb7425aefa5e8936e06849f484"

	strings:

	
 		 $s1= "DocumentSummaryInformation" fullword wide
		 $s2= "FileDescription" fullword wide
		 $s3= "GlobalDelSelf(%8.8X)" fullword wide
		 $s4= "LegalTrademarks" fullword wide
		 $s5= "OriginalFilename" fullword wide
		 $s6= "%sSidebar.dll.doc" fullword wide
		 $s7= "SummaryInformation" fullword wide
		 $s8= "TENCENT SideBar" fullword wide
		 $s9= "VS_VERSION_INFO" fullword wide

		 $hex1= {2473313d2022446f63}
		 $hex2= {2473323d202246696c}
		 $hex3= {2473333d2022476c6f}
		 $hex4= {2473343d20224c6567}
		 $hex5= {2473353d20224f7269}
		 $hex6= {2473363d2022257353}
		 $hex7= {2473373d202253756d}
		 $hex8= {2473383d202254454e}
		 $hex9= {2473393d202256535f}

	condition:
		3 of them
}
