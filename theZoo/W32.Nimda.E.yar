
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_W32_Nimda_E 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_W32_Nimda_E {
	meta: 
		 description= "theZoo_W32_Nimda_E Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-36-08" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "130d2fe8174481170b3d78627c6b5e13"

	strings:

	
 		 $a1= "SoftwareMicrosoftWindowsCurrentVersionExplorerShell Folders" fullword ascii
		 $a2= "SYSTEMCurrentControlSetServiceslanmanserverSharesSecurity" fullword ascii
		 $a3= "SYSTEMCurrentControlSetServicesTcpipParametersInterfaces" fullword ascii
		 $a4= "SYSTEMCurrentControlSetServicesTcpipParametersInterfaces" fullword ascii

		 $hex1= {2461313d2022536f66}
		 $hex2= {2461323d2022535953}
		 $hex3= {2461333d2022535953}
		 $hex4= {2461343d2022535953}

	condition:
		2 of them
}
