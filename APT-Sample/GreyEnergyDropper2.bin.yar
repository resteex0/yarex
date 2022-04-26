
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_GreyEnergyAPT_GreyEnergyDropper2_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_GreyEnergyAPT_GreyEnergyDropper2_bin {
	meta: 
		 description= "APT_Sample_GreyEnergyAPT_GreyEnergyDropper2_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_03-24-40" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "446d226cedf08866dbe528868cba2007"

	strings:

	
 		 $s1= "CDataSocket::CDataSocket" fullword wide
		 $s2= "CheckUserSession" fullword wide
		 $s3= "CleanupInstance" fullword wide
		 $s4= "FileDescription" fullword wide
		 $s5= "Gateway Configuration" fullword wide
		 $s6= "Listener Initialize" fullword wide
		 $s7= "OnClose OnReceive" fullword wide
		 $s8= "OriginalFilename" fullword wide
		 $s9= "ThinPrint TPVCGateway" fullword wide
		 $s10= "TPVCGateway Dialog" fullword wide
		 $s11= "TPVCGateway.exe" fullword wide
		 $s12= "TPVCGateway Service" fullword wide
		 $s13= "VS_VERSION_INFO" fullword wide

		 $hex1= {43??44??61??74??61??53??6f??63??6b??65??74??3a??3a??43??44??61??74??61??53??6f??63??6b??65??74??0a??}
		 $hex2= {43??68??65??63??6b??55??73??65??72??53??65??73??73??69??6f??6e??0a??}
		 $hex3= {43??6c??65??61??6e??75??70??49??6e??73??74??61??6e??63??65??0a??}
		 $hex4= {46??69??6c??65??44??65??73??63??72??69??70??74??69??6f??6e??0a??}
		 $hex5= {47??61??74??65??77??61??79??20??43??6f??6e??66??69??67??75??72??61??74??69??6f??6e??0a??}
		 $hex6= {4c??69??73??74??65??6e??65??72??20??49??6e??69??74??69??61??6c??69??7a??65??0a??}
		 $hex7= {4f??6e??43??6c??6f??73??65??20??4f??6e??52??65??63??65??69??76??65??0a??}
		 $hex8= {4f??72??69??67??69??6e??61??6c??46??69??6c??65??6e??61??6d??65??0a??}
		 $hex9= {54??50??56??43??47??61??74??65??77??61??79??20??44??69??61??6c??6f??67??0a??}
		 $hex10= {54??50??56??43??47??61??74??65??77??61??79??20??53??65??72??76??69??63??65??0a??}
		 $hex11= {54??50??56??43??47??61??74??65??77??61??79??2e??65??78??65??0a??}
		 $hex12= {54??68??69??6e??50??72??69??6e??74??20??54??50??56??43??47??61??74??65??77??61??79??0a??}
		 $hex13= {56??53??5f??56??45??52??53??49??4f??4e??5f??49??4e??46??4f??0a??}

	condition:
		14 of them
}
