
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_Dridex_dridexLoader_bin_exe_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_Dridex_dridexLoader_bin_exe_bin {
	meta: 
		 description= "APT_Sample_Dridex_dridexLoader_bin_exe_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_03-20-34" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "c26203af4b3e9c81a9e634178b603601"

	strings:

	
 		 $s1= "3jandcontrolledbdonkey4" fullword wide
		 $s2= "bildevelopersdBelfast,ll" fullword wide
		 $s3= "ExtensionscontestSPDYsupportR3g" fullword wide
		 $s4= "FileDescription" fullword wide
		 $s5= "localExplorerRjQPepper" fullword wide
		 $s6= "MainTUsendingh0firstthatuses" fullword wide
		 $s7= "OriginalFilename" fullword wide
		 $s8= "tabspbuttons.thumbnails.gthemtheeH" fullword wide
		 $s9= "UaSraisedJanuarymThe" fullword wide
		 $s10= "Utwebwillno51Chromium).100the" fullword wide
		 $s11= "VS_VERSION_INFO" fullword wide
		 $s12= "wchrome:flagspermanent6khasthatbLO" fullword wide
		 $s13= "z2insteadttopluginbutto" fullword wide
		 $s14= "ZnperiodicallyGDChrome9sitesweach" fullword wide

		 $hex1= {33??6a??61??6e??64??63??6f??6e??74??72??6f??6c??6c??65??64??62??64??6f??6e??6b??65??79??34??0a??}
		 $hex2= {45??78??74??65??6e??73??69??6f??6e??73??63??6f??6e??74??65??73??74??53??50??44??59??73??75??70??70??6f??72??74??52??33??}
		 $hex3= {46??69??6c??65??44??65??73??63??72??69??70??74??69??6f??6e??0a??}
		 $hex4= {4d??61??69??6e??54??55??73??65??6e??64??69??6e??67??68??30??66??69??72??73??74??74??68??61??74??75??73??65??73??0a??}
		 $hex5= {4f??72??69??67??69??6e??61??6c??46??69??6c??65??6e??61??6d??65??0a??}
		 $hex6= {55??61??53??72??61??69??73??65??64??4a??61??6e??75??61??72??79??6d??54??68??65??0a??}
		 $hex7= {55??74??77??65??62??77??69??6c??6c??6e??6f??35??31??43??68??72??6f??6d??69??75??6d??29??2e??31??30??30??74??68??65??0a??}
		 $hex8= {56??53??5f??56??45??52??53??49??4f??4e??5f??49??4e??46??4f??0a??}
		 $hex9= {5a??6e??70??65??72??69??6f??64??69??63??61??6c??6c??79??47??44??43??68??72??6f??6d??65??39??73??69??74??65??73??77??65??}
		 $hex10= {62??69??6c??64??65??76??65??6c??6f??70??65??72??73??64??42??65??6c??66??61??73??74??2c??6c??6c??0a??}
		 $hex11= {6c??6f??63??61??6c??45??78??70??6c??6f??72??65??72??52??6a??51??50??65??70??70??65??72??0a??}
		 $hex12= {74??61??62??73??70??62??75??74??74??6f??6e??73??2e??74??68??75??6d??62??6e??61??69??6c??73??2e??67??74??68??65??6d??74??}
		 $hex13= {77??63??68??72??6f??6d??65??3a??66??6c??61??67??73??70??65??72??6d??61??6e??65??6e??74??36??6b??68??61??73??74??68??61??}
		 $hex14= {7a??32??69??6e??73??74??65??61??64??74??74??6f??70??6c??75??67??69??6e??62??75??74??74??6f??0a??}

	condition:
		15 of them
}
