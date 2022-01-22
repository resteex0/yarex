
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
		 date = "2022-01-22_17-55-06" 
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

		 $hex1= {247331303d20225363}
		 $hex2= {2473313d202241646f}
		 $hex3= {2473323d202241646f}
		 $hex4= {2473333d2022433a70}
		 $hex5= {2473343d2022433a55}
		 $hex6= {2473353d2022433a55}
		 $hex7= {2473363d2022446f63}
		 $hex8= {2473373d2022652f2f}
		 $hex9= {2473383d20224c6962}
		 $hex10= {2473393d202250726f}

	condition:
		6 of them
}
