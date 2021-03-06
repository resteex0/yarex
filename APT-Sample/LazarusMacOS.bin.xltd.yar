
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_Lazarus_LazarusMacOS_bin_xltd 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_Lazarus_LazarusMacOS_bin_xltd {
	meta: 
		 description= "APT_Sample_Lazarus_LazarusMacOS_bin_xltd Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_03-23-08" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "4f6b0be2dbd49871ff32e8388b011d90"

	strings:

	
 		 $s1= "CelasTradePro.pk" fullword wide
		 $s2= "CelasTradePro.pkg" fullword wide
		 $s3= "com.apple.cs.CodeDirectory" fullword wide
		 $s4= "com.apple.cs.CodeRequirements" fullword wide
		 $s5= "com.apple.cs.CodeRequirements-1" fullword wide
		 $s6= "com.apple.cs.CodeSignature" fullword wide
		 $s7= "com.apple.lastuseddate#PS" fullword wide
		 $s8= ".journal_info_block" fullword wide

		 $hex1= {2e??6a??6f??75??72??6e??61??6c??5f??69??6e??66??6f??5f??62??6c??6f??63??6b??0a??}
		 $hex2= {43??65??6c??61??73??54??72??61??64??65??50??72??6f??2e??70??6b??0a??}
		 $hex3= {43??65??6c??61??73??54??72??61??64??65??50??72??6f??2e??70??6b??67??0a??}
		 $hex4= {63??6f??6d??2e??61??70??70??6c??65??2e??63??73??2e??43??6f??64??65??44??69??72??65??63??74??6f??72??79??0a??}
		 $hex5= {63??6f??6d??2e??61??70??70??6c??65??2e??63??73??2e??43??6f??64??65??52??65??71??75??69??72??65??6d??65??6e??74??73??0a??}
		 $hex6= {63??6f??6d??2e??61??70??70??6c??65??2e??63??73??2e??43??6f??64??65??52??65??71??75??69??72??65??6d??65??6e??74??73??2d??}
		 $hex7= {63??6f??6d??2e??61??70??70??6c??65??2e??63??73??2e??43??6f??64??65??53??69??67??6e??61??74??75??72??65??0a??}
		 $hex8= {63??6f??6d??2e??61??70??70??6c??65??2e??6c??61??73??74??75??73??65??64??64??61??74??65??23??50??53??0a??}

	condition:
		8 of them
}
