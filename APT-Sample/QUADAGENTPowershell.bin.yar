
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_APT34_QUADAGENTPowershell_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_APT34_QUADAGENTPowershell_bin {
	meta: 
		 description= "APT_Sample_APT34_QUADAGENTPowershell_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_03-21-23" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "485041067b8e37d3b172f5c0e700bff1"

	strings:

	
 		 $s1= "(1Normal.ThisDocument " fullword wide
		 $s2= "C:UsersDevDesktop3.dot" fullword wide
		 $s3= "DocumentSummaryInformation" fullword wide
		 $s4= "Scripting.FileSystemObject" fullword wide
		 $s5= "shell.application" fullword wide
		 $s6= "SummaryInformation" fullword wide

		 $hex1= {28??31??4e??6f??72??6d??61??6c??2e??54??68??69??73??44??6f??63??75??6d??65??6e??74??0a??}
		 $hex2= {43??3a??55??73??65??72??73??44??65??76??44??65??73??6b??74??6f??70??33??2e??64??6f??74??0a??}
		 $hex3= {44??6f??63??75??6d??65??6e??74??53??75??6d??6d??61??72??79??49??6e??66??6f??72??6d??61??74??69??6f??6e??0a??}
		 $hex4= {53??63??72??69??70??74??69??6e??67??2e??46??69??6c??65??53??79??73??74??65??6d??4f??62??6a??65??63??74??0a??}
		 $hex5= {53??75??6d??6d??61??72??79??49??6e??66??6f??72??6d??61??74??69??6f??6e??0a??}
		 $hex6= {73??68??65??6c??6c??2e??61??70??70??6c??69??63??61??74??69??6f??6e??0a??}

	condition:
		6 of them
}
