
/*
   YARA Rule Set
   Author: resteex
   Identifier: EquationGroup_Fanny 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_EquationGroup_Fanny {
	meta: 
		 description= "EquationGroup_Fanny Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-42-23" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0a209ac0de4ac033f31d6ba9191a8f7a"

	strings:

	
 		 $a1= "SoftwareMicrosoftWindows NTCurrentVersionWinlogon" fullword ascii

		 $hex1= {2461313d2022536f66}

	condition:
		0 of them
}
