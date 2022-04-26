
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_DustSquad 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_DustSquad {
	meta: 
		 description= "APT_Sample_DustSquad Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_02-21-13" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1610cddb80d1be5d711feb46610f8a77"
		 hash2= "979eff03faeaeea5310df53ee1a2fc8e"
		 hash3= "ea241313acb27429d04a4e4a790d2703"

	strings:

	
 		 $s1= "%1:.2d:%2:.2d:%3:.2d" fullword wide
		 $s2= "148.251.185.168" fullword wide
		 $s3= "255.255.255.255" fullword wide
		 $s4= ".7z=application/x-7z-compressed" fullword wide
		 $s5= ".aab=application/x-authorware-bin" fullword wide
		 $s6= ".aam=application/x-authorware-map" fullword wide
		 $s7= ".a=application/x-archive" fullword wide
		 $s8= ".aas=application/x-authorware-seg" fullword wide
		 $s9= ".abw=application/x-abiword" fullword wide
		 $s10= "Accept-Encoding" fullword wide
		 $s11= "Accept-Language" fullword wide
		 $s12= "Access violation" fullword wide
		 $s13= ".ace=application/x-ace-compressed" fullword wide
		 $s14= "AcquireCredentialsHandleW" fullword wide
		 $s15= "Adobe-Standard-Encoding" fullword wide
		 $s16= "Adobe-Symbol-Encoding" fullword wide
		 $s17= ".ai=application/postscript" fullword wide
		 $s18= ".aif=audio/x-aiff" fullword wide
		 $s19= ".aifc=audio/x-aiff" fullword wide
		 $s20= ".aiff=audio/x-aiff" fullword wide

		 $hex1= {25??31??3a??2e??32??64??3a??25??32??3a??2e??32??64??3a??25??33??3a??2e??32??64??0a??}
		 $hex2= {2e??37??7a??3d??61??70??70??6c??69??63??61??74??69??6f??6e??2f??78??2d??37??7a??2d??63??6f??6d??70??72??65??73??73??65??}
		 $hex3= {2e??61??3d??61??70??70??6c??69??63??61??74??69??6f??6e??2f??78??2d??61??72??63??68??69??76??65??0a??}
		 $hex4= {2e??61??61??62??3d??61??70??70??6c??69??63??61??74??69??6f??6e??2f??78??2d??61??75??74??68??6f??72??77??61??72??65??2d??}
		 $hex5= {2e??61??61??6d??3d??61??70??70??6c??69??63??61??74??69??6f??6e??2f??78??2d??61??75??74??68??6f??72??77??61??72??65??2d??}
		 $hex6= {2e??61??61??73??3d??61??70??70??6c??69??63??61??74??69??6f??6e??2f??78??2d??61??75??74??68??6f??72??77??61??72??65??2d??}
		 $hex7= {2e??61??62??77??3d??61??70??70??6c??69??63??61??74??69??6f??6e??2f??78??2d??61??62??69??77??6f??72??64??0a??}
		 $hex8= {2e??61??63??65??3d??61??70??70??6c??69??63??61??74??69??6f??6e??2f??78??2d??61??63??65??2d??63??6f??6d??70??72??65??73??}
		 $hex9= {2e??61??69??3d??61??70??70??6c??69??63??61??74??69??6f??6e??2f??70??6f??73??74??73??63??72??69??70??74??0a??}
		 $hex10= {2e??61??69??66??3d??61??75??64??69??6f??2f??78??2d??61??69??66??66??0a??}
		 $hex11= {2e??61??69??66??63??3d??61??75??64??69??6f??2f??78??2d??61??69??66??66??0a??}
		 $hex12= {2e??61??69??66??66??3d??61??75??64??69??6f??2f??78??2d??61??69??66??66??0a??}
		 $hex13= {31??34??38??2e??32??35??31??2e??31??38??35??2e??31??36??38??0a??}
		 $hex14= {32??35??35??2e??32??35??35??2e??32??35??35??2e??32??35??35??0a??}
		 $hex15= {41??63??63??65??70??74??2d??45??6e??63??6f??64??69??6e??67??0a??}
		 $hex16= {41??63??63??65??70??74??2d??4c??61??6e??67??75??61??67??65??0a??}
		 $hex17= {41??63??63??65??73??73??20??76??69??6f??6c??61??74??69??6f??6e??0a??}
		 $hex18= {41??63??71??75??69??72??65??43??72??65??64??65??6e??74??69??61??6c??73??48??61??6e??64??6c??65??57??0a??}
		 $hex19= {41??64??6f??62??65??2d??53??74??61??6e??64??61??72??64??2d??45??6e??63??6f??64??69??6e??67??0a??}
		 $hex20= {41??64??6f??62??65??2d??53??79??6d??62??6f??6c??2d??45??6e??63??6f??64??69??6e??67??0a??}

	condition:
		22 of them
}
