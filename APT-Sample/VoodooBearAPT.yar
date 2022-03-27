
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_VoodooBearAPT 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_VoodooBearAPT {
	meta: 
		 description= "APT_Sample_VoodooBearAPT Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-27_08-16-27" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0fd6c923edc283fb034f12557bd7719d"

	strings:

	
 		 $s1= "Content-Type: application/x-www-form-urlencoded" fullword wide

		 $hex1= {43??6f??6e??74??65??6e??74??2d??54??79??70??65??3a??20??61??70??70??6c??69??63??61??74??69??6f??6e??2f??78??2d??77??77??}

	condition:
		1 of them
}
