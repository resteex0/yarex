
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_DPRK_HiddenCobra_exe 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_DPRK_HiddenCobra_exe {
	meta: 
		 description= "APT_Sample_DPRK_HiddenCobra_exe Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_03-22-34" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "143cb4f16dcfc16a02812718acd32c8f"

	strings:

	
 		 $s1= "[Accept Thread]" fullword wide
		 $s2= "ProcessorNameString" fullword wide
		 $s3= "[SaveBotCmdFile]:%s" fullword wide

		 $hex1= {50??72??6f??63??65??73??73??6f??72??4e??61??6d??65??53??74??72??69??6e??67??0a??}
		 $hex2= {5b??41??63??63??65??70??74??20??54??68??72??65??61??64??5d??0a??}
		 $hex3= {5b??53??61??76??65??42??6f??74??43??6d??64??46??69??6c??65??5d??3a??25??73??0a??}

	condition:
		3 of them
}
