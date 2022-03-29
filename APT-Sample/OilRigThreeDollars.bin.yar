
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_OilRigThreeDollars_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_OilRigThreeDollars_bin {
	meta: 
		 description= "APT_Sample_OilRigThreeDollars_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-29_06-37-58" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "02306d629ca4092551081c4ebcbbd9b4"

	strings:

	
 		 $s1= "(1Normal.ThisDocument " fullword wide
		 $s2= "DocumentSummaryInformation" fullword wide
		 $s3= "Librariesservicereset.exe" fullword wide
		 $s4= "Scripting.FileSystemObject" fullword wide
		 $s5= "SummaryInformation" fullword wide

		 $hex1= {28??31??4e??6f??72??6d??61??6c??2e??54??68??69??73??44??6f??63??75??6d??65??6e??74??0a??}
		 $hex2= {44??6f??63??75??6d??65??6e??74??53??75??6d??6d??61??72??79??49??6e??66??6f??72??6d??61??74??69??6f??6e??0a??}
		 $hex3= {4c??69??62??72??61??72??69??65??73??73??65??72??76??69??63??65??72??65??73??65??74??2e??65??78??65??0a??}
		 $hex4= {53??63??72??69??70??74??69??6e??67??2e??46??69??6c??65??53??79??73??74??65??6d??4f??62??6a??65??63??74??0a??}
		 $hex5= {53??75??6d??6d??61??72??79??49??6e??66??6f??72??6d??61??74??69??6f??6e??0a??}

	condition:
		5 of them
}
