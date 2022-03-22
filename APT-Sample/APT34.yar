
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
		 date = "2022-03-22_12-18-03" 
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

		 $hex1= {41646f62654163726f}
		 $hex2= {433a55736572734465}
		 $hex3= {433a55736572734a2d}
		 $hex4= {433a70726f6772616d}
		 $hex5= {446f63756d656e7453}
		 $hex6= {4c6962726172696573}
		 $hex7= {50726f6a6563742e54}
		 $hex8= {536372697074696e67}
		 $hex9= {652f2f782f2f652f2f}

	condition:
		1 of them
}
