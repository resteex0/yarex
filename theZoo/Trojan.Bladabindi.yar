
/*
   YARA Rule Set
   Author: resteex
   Identifier: Trojan_Bladabindi 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Trojan_Bladabindi {
	meta: 
		 description= "Trojan_Bladabindi Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-30-37" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "5a559b6d223c79f3736dc52794636cfd"

	strings:

	
 		 $s1= "Assembly Version" fullword wide
		 $s2= "FileDescription" fullword wide
		 $s3= "OriginalFilename" fullword wide
		 $s4= "VS_VERSION_INFO" fullword wide
		 $a1= "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
		 $a2= "CompilationRelaxationsAttribute" fullword ascii
		 $a3= "Microsoft.VisualBasic.ApplicationServices" fullword ascii
		 $a4= "Microsoft.VisualBasic.CompilerServices" fullword ascii
		 $a5= "Microsoft.VisualBasic.Devices" fullword ascii
		 $a6= "MyGroupCollectionAttribute" fullword ascii
		 $a7= "RuntimeCompatibilityAttribute" fullword ascii
		 $a8= "System.ComponentModel.Design" fullword ascii
		 $a9= "System.Runtime.CompilerServices" fullword ascii
		 $a10= "System.Runtime.InteropServices" fullword ascii

		 $hex1= {246131303d20225379}
		 $hex2= {2461313d2022345379}
		 $hex3= {2461323d2022436f6d}
		 $hex4= {2461333d20224d6963}
		 $hex5= {2461343d20224d6963}
		 $hex6= {2461353d20224d6963}
		 $hex7= {2461363d20224d7947}
		 $hex8= {2461373d202252756e}
		 $hex9= {2461383d2022537973}
		 $hex10= {2461393d2022537973}
		 $hex11= {2473313d2022417373}
		 $hex12= {2473323d202246696c}
		 $hex13= {2473333d20224f7269}
		 $hex14= {2473343d202256535f}

	condition:
		1 of them
}
