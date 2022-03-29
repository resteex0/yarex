
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_HiddenCobraJoanap_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_HiddenCobraJoanap_bin {
	meta: 
		 description= "APT_Sample_HiddenCobraJoanap_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-29_06-37-50" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "e3d03829cbec1a8cca56c6ae730ba9a8"

	strings:

	
 		 $s1= "VarFileInfoTranslation" fullword wide

		 $hex1= {56??61??72??46??69??6c??65??49??6e??66??6f??54??72??61??6e??73??6c??61??74??69??6f??6e??0a??}

	condition:
		1 of them
}
