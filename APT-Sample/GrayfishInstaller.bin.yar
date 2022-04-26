
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_EquationGroup_GrayfishInstaller_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_EquationGroup_GrayfishInstaller_bin {
	meta: 
		 description= "APT_Sample_EquationGroup_GrayfishInstaller_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_03-21-39" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "9b1ca66aab784dc5f1dfe635d8f8a904"

	strings:

	
 		 $s1= "BsDADm$}u))ms''D@h*]iN[''" fullword wide
		 $s2= "cnFormSyncExFBC" fullword wide
		 $s3= "FileDescription" fullword wide
		 $s4= "Microsoft Corporation" fullword wide
		 $s5= "OriginalFilename" fullword wide
		 $s6= "S]*Fc2XY+hhcGEz*]h" fullword wide
		 $s7= "tB''CRS%)CD''D@h*]iN[''" fullword wide
		 $s8= "tB''CRS%)CD''D@h*]iN[''%2EK]2h''" fullword wide
		 $s9= "VS_VERSION_INFO" fullword wide

		 $hex1= {42??73??44??41??44??6d??24??7d??75??29??29??6d??73??27??27??44??40??68??2a??5d??69??4e??5b??27??27??0a??}
		 $hex2= {46??69??6c??65??44??65??73??63??72??69??70??74??69??6f??6e??0a??}
		 $hex3= {4d??69??63??72??6f??73??6f??66??74??20??43??6f??72??70??6f??72??61??74??69??6f??6e??0a??}
		 $hex4= {4f??72??69??67??69??6e??61??6c??46??69??6c??65??6e??61??6d??65??0a??}
		 $hex5= {53??5d??2a??46??63??32??58??59??2b??68??68??63??47??45??7a??2a??5d??68??0a??}
		 $hex6= {56??53??5f??56??45??52??53??49??4f??4e??5f??49??4e??46??4f??0a??}
		 $hex7= {63??6e??46??6f??72??6d??53??79??6e??63??45??78??46??42??43??0a??}
		 $hex8= {74??42??27??27??43??52??53??25??29??43??44??27??27??44??40??68??2a??5d??69??4e??5b??27??27??0a??}
		 $hex9= {74??42??27??27??43??52??53??25??29??43??44??27??27??44??40??68??2a??5d??69??4e??5b??27??27??25??32??45??4b??5d??32??68??}

	condition:
		10 of them
}
