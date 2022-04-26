
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_Ransomeware_DharmaRansomware_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_Ransomeware_DharmaRansomware_bin {
	meta: 
		 description= "APT_Sample_Ransomeware_DharmaRansomware_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_03-25-09" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "9f3ea1850f9d879de8a36dc778dfffba"

	strings:

	
 		 $s1= "Assembly Version" fullword wide
		 $s2= "Control PanelDesktop" fullword wide
		 $s3= "FileDescription" fullword wide
		 $s4= "LegalTrademarks" fullword wide
		 $s5= "LKNMOMPMVUWUXU[ZZ^]_]cbdbjikili" fullword wide
		 $s6= "OriginalFilename" fullword wide
		 $s7= "VS_VERSION_INFO" fullword wide

		 $hex1= {41??73??73??65??6d??62??6c??79??20??56??65??72??73??69??6f??6e??0a??}
		 $hex2= {43??6f??6e??74??72??6f??6c??20??50??61??6e??65??6c??44??65??73??6b??74??6f??70??0a??}
		 $hex3= {46??69??6c??65??44??65??73??63??72??69??70??74??69??6f??6e??0a??}
		 $hex4= {4c??4b??4e??4d??4f??4d??50??4d??56??55??57??55??58??55??5b??5a??5a??5e??5d??5f??5d??63??62??64??62??6a??69??6b??69??6c??}
		 $hex5= {4c??65??67??61??6c??54??72??61??64??65??6d??61??72??6b??73??0a??}
		 $hex6= {4f??72??69??67??69??6e??61??6c??46??69??6c??65??6e??61??6d??65??0a??}
		 $hex7= {56??53??5f??56??45??52??53??49??4f??4e??5f??49??4e??46??4f??0a??}

	condition:
		7 of them
}
