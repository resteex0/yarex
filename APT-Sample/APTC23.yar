
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_APTC23 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_APTC23 {
	meta: 
		 description= "APT_Sample_APTC23 Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_02-20-45" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "6eff53e85a9ce9f1d99c812270093581"
		 hash2= "b0bdeb5faf774e2a5c4365cb3efe0903"
		 hash3= "e121531a15f2eaa34dce89f3fec70cfd"

	strings:

	
 		 $s1= "%1:.2d:%2:.2d:%3:.2d" fullword wide
		 $s2= "Accept-Encoding" fullword wide
		 $s3= "Accept-Language" fullword wide
		 $s4= "Access violation" fullword wide
		 $s5= "application/andrew-inset" fullword wide
		 $s6= "application/applixware" fullword wide
		 $s7= "application/atomcat+xml" fullword wide
		 $s8= "application/atomsvc+xml" fullword wide
		 $s9= "application/atom+xml" fullword wide
		 $s10= "application/ccxml+xml" fullword wide
		 $s11= "application/cdmi-capability" fullword wide
		 $s12= "application/cdmi-container" fullword wide
		 $s13= "application/cdmi-domain" fullword wide
		 $s14= "application/cdmi-object" fullword wide
		 $s15= "application/cdmi-queue" fullword wide
		 $s16= "application/cu-seeme" fullword wide
		 $s17= "application/davmount+xml" fullword wide
		 $s18= "application/docbook+xml" fullword wide
		 $s19= "application/dssc+der" fullword wide
		 $s20= "application/dssc+xml" fullword wide

		 $hex1= {25??31??3a??2e??32??64??3a??25??32??3a??2e??32??64??3a??25??33??3a??2e??32??64??0a??}
		 $hex2= {41??63??63??65??70??74??2d??45??6e??63??6f??64??69??6e??67??0a??}
		 $hex3= {41??63??63??65??70??74??2d??4c??61??6e??67??75??61??67??65??0a??}
		 $hex4= {41??63??63??65??73??73??20??76??69??6f??6c??61??74??69??6f??6e??0a??}
		 $hex5= {61??70??70??6c??69??63??61??74??69??6f??6e??2f??61??6e??64??72??65??77??2d??69??6e??73??65??74??0a??}
		 $hex6= {61??70??70??6c??69??63??61??74??69??6f??6e??2f??61??70??70??6c??69??78??77??61??72??65??0a??}
		 $hex7= {61??70??70??6c??69??63??61??74??69??6f??6e??2f??61??74??6f??6d??2b??78??6d??6c??0a??}
		 $hex8= {61??70??70??6c??69??63??61??74??69??6f??6e??2f??61??74??6f??6d??63??61??74??2b??78??6d??6c??0a??}
		 $hex9= {61??70??70??6c??69??63??61??74??69??6f??6e??2f??61??74??6f??6d??73??76??63??2b??78??6d??6c??0a??}
		 $hex10= {61??70??70??6c??69??63??61??74??69??6f??6e??2f??63??63??78??6d??6c??2b??78??6d??6c??0a??}
		 $hex11= {61??70??70??6c??69??63??61??74??69??6f??6e??2f??63??64??6d??69??2d??63??61??70??61??62??69??6c??69??74??79??0a??}
		 $hex12= {61??70??70??6c??69??63??61??74??69??6f??6e??2f??63??64??6d??69??2d??63??6f??6e??74??61??69??6e??65??72??0a??}
		 $hex13= {61??70??70??6c??69??63??61??74??69??6f??6e??2f??63??64??6d??69??2d??64??6f??6d??61??69??6e??0a??}
		 $hex14= {61??70??70??6c??69??63??61??74??69??6f??6e??2f??63??64??6d??69??2d??6f??62??6a??65??63??74??0a??}
		 $hex15= {61??70??70??6c??69??63??61??74??69??6f??6e??2f??63??64??6d??69??2d??71??75??65??75??65??0a??}
		 $hex16= {61??70??70??6c??69??63??61??74??69??6f??6e??2f??63??75??2d??73??65??65??6d??65??0a??}
		 $hex17= {61??70??70??6c??69??63??61??74??69??6f??6e??2f??64??61??76??6d??6f??75??6e??74??2b??78??6d??6c??0a??}
		 $hex18= {61??70??70??6c??69??63??61??74??69??6f??6e??2f??64??6f??63??62??6f??6f??6b??2b??78??6d??6c??0a??}
		 $hex19= {61??70??70??6c??69??63??61??74??69??6f??6e??2f??64??73??73??63??2b??64??65??72??0a??}
		 $hex20= {61??70??70??6c??69??63??61??74??69??6f??6e??2f??64??73??73??63??2b??78??6d??6c??0a??}

	condition:
		22 of them
}
