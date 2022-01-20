
/*
   YARA Rule Set
   Author: resteex
   Identifier: OSX_Backdoor_iWorm 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_OSX_Backdoor_iWorm {
	meta: 
		 description= "OSX_Backdoor_iWorm Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-42-40" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "126e7840a978ae90dfa731a66afbe9be"

	strings:

	
 		 $a1= "/System/Library/Frameworks/Carbon.framework/Versions/A/Carbon" fullword ascii

		 $hex1= {2461313d20222f5379}

	condition:
		0 of them
}
