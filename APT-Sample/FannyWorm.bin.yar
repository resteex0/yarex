
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_EquationGroup_FannyWorm_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_EquationGroup_FannyWorm_bin {
	meta: 
		 description= "APT_Sample_EquationGroup_FannyWorm_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_03-21-41" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0a209ac0de4ac033f31d6ba9191a8f7a"

	strings:

	
 		 $s1= "CcnFormSyncExFBC" fullword wide
		 $s2= "system32win32k.sys" fullword wide

		 $hex1= {43??63??6e??46??6f??72??6d??53??79??6e??63??45??78??46??42??43??0a??}
		 $hex2= {73??79??73??74??65??6d??33??32??77??69??6e??33??32??6b??2e??73??79??73??0a??}

	condition:
		2 of them
}
