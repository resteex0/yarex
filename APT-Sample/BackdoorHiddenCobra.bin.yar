
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_DPRK_BackdoorHiddenCobra_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_DPRK_BackdoorHiddenCobra_bin {
	meta: 
		 description= "APT_Sample_DPRK_BackdoorHiddenCobra_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_03-22-35" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "eb9db98914207815d763e2e5cfbe96b9"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "Microsoft Corporation" fullword wide
		 $s3= "VarFileInfoTranslation" fullword wide
		 $s4= "VS_VERSION_INFO" fullword wide

		 $hex1= {46??69??6c??65??44??65??73??63??72??69??70??74??69??6f??6e??0a??}
		 $hex2= {4d??69??63??72??6f??73??6f??66??74??20??43??6f??72??70??6f??72??61??74??69??6f??6e??0a??}
		 $hex3= {56??53??5f??56??45??52??53??49??4f??4e??5f??49??4e??46??4f??0a??}
		 $hex4= {56??61??72??46??69??6c??65??49??6e??66??6f??54??72??61??6e??73??6c??61??74??69??6f??6e??0a??}

	condition:
		4 of them
}
