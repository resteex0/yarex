
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_APT34 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_APT34 {
	meta: 
		 description= "APT_Sample_APT34 Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-27_09-55-25" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "02306d629ca4092551081c4ebcbbd9b4"
		 hash2= "10d12a4363a4ca5cb369edd4d6df108e"
		 hash3= "485041067b8e37d3b172f5c0e700bff1"
		 hash4= "486bdf835a453c6ffb5f56647e697871"

	strings:

	
 		 $s1= "AdobeAcrobatLicenseVerify.ps1" fullword wide
		 $s2= "AdobeAcrobatLicenseVerify.vbs" fullword wide
		 $s3= "C:programdataOffice365DCOMCheck.ps1" fullword wide
		 $s4= "C:UsersDevDesktop3.dot" fullword wide
		 $s5= "C:UsersJ-Win-7-32-VmDesktoperror.jpg" fullword wide
		 $s6= "DocumentSummaryInformation" fullword wide
		 $s7= "e//x//e//.//l//l//e//h//s//r//e//w//o//p" fullword wide
		 $s8= "Librariesservicereset.exe" fullword wide
		 $s9= "Project.ThisDocument.AutoOpen" fullword wide
		 $s10= "Scripting.FileSystemObject" fullword wide

		 $hex1= {41??64??6f??62??65??41??63??72??6f??62??61??74??4c??69??63??65??6e??73??65??56??65??72??69??66??79??2e??70??73??31??0a??}
		 $hex2= {41??64??6f??62??65??41??63??72??6f??62??61??74??4c??69??63??65??6e??73??65??56??65??72??69??66??79??2e??76??62??73??0a??}
		 $hex3= {43??3a??55??73??65??72??73??44??65??76??44??65??73??6b??74??6f??70??33??2e??64??6f??74??0a??}
		 $hex4= {43??3a??55??73??65??72??73??4a??2d??57??69??6e??2d??37??2d??33??32??2d??56??6d??44??65??73??6b??74??6f??70??65??72??72??}
		 $hex5= {43??3a??70??72??6f??67??72??61??6d??64??61??74??61??4f??66??66??69??63??65??33??36??35??44??43??4f??4d??43??68??65??63??}
		 $hex6= {44??6f??63??75??6d??65??6e??74??53??75??6d??6d??61??72??79??49??6e??66??6f??72??6d??61??74??69??6f??6e??0a??}
		 $hex7= {4c??69??62??72??61??72??69??65??73??73??65??72??76??69??63??65??72??65??73??65??74??2e??65??78??65??0a??}
		 $hex8= {50??72??6f??6a??65??63??74??2e??54??68??69??73??44??6f??63??75??6d??65??6e??74??2e??41??75??74??6f??4f??70??65??6e??0a??}
		 $hex9= {53??63??72??69??70??74??69??6e??67??2e??46??69??6c??65??53??79??73??74??65??6d??4f??62??6a??65??63??74??0a??}
		 $hex10= {65??2f??2f??78??2f??2f??65??2f??2f??2e??2f??2f??6c??2f??2f??6c??2f??2f??65??2f??2f??68??2f??2f??73??2f??2f??72??2f??2f??}

	condition:
		11 of them
}
