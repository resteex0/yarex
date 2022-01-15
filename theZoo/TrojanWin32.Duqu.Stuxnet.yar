
/*
   YARA Rule Set
   Author: resteex
   Identifier: TrojanWin32_Duqu_Stuxnet 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_TrojanWin32_Duqu_Stuxnet {
	meta: 
		 description= "TrojanWin32_Duqu_Stuxnet Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-38-23" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "c9a31ea148232b201fe7cb7db5c75f5e"

	strings:

	
 		 $s1= "DosDevicesGpdDev" fullword wide
		 $s2= "FileDescription" fullword wide
		 $s3= "InternalCopyright" fullword wide
		 $s4= "OriginalFilename" fullword wide
		 $s5= "VS_VERSION_INFO" fullword wide
		 $s6= "ZwQuerySystemInformation" fullword wide

		 $hex1= {2473313d2022446f73}
		 $hex2= {2473323d202246696c}
		 $hex3= {2473333d2022496e74}
		 $hex4= {2473343d20224f7269}
		 $hex5= {2473353d202256535f}
		 $hex6= {2473363d20225a7751}

	condition:
		2 of them
}
