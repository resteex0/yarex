
/*
   YARA Rule Set
   Author: resteex
   Identifier: W32_Klez_H 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W32_Klez_H {
	meta: 
		 description= "W32_Klez_H Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-44-04" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "07c19da3a33f9ec6a97f3837aef6fde0"
		 hash2= "4ae9a4a8b8ce22c7b52c2eaec75ca536"
		 hash3= "60c271a141c1cbd29489e1a2925b639f"
		 hash4= "b023af582bfe56ae0c32401599b7d082"
		 hash5= "bbb1522b1db750efbcf7813e9153d424"

	strings:

	
 		 $s1= "http://www.bitdefender.com" fullword wide
		 $s2= "Win32.Klez.A@mm, Win32.Klez.B@mm," fullword wide
		 $s3= "Win32.Klez.C@mm, Win32.Klez.D@mm," fullword wide
		 $a1= "4http://crl.verisign.com/Class3SoftwarePublishers.crl0" fullword ascii
		 $a2= "4https://www.verisign.com/repository/verisignlogo.gif0" fullword ascii
		 $a3= "HKEY_LOCAL_MACHINESoftwareMicrosoftWindowsCurrentVersionRun" fullword ascii
		 $a4= "HKEY_LOCAL_MACHINESystemCurrentControlSetServices" fullword ascii
		 $a5= "http://www.microsoft.com/technet/security/bulletin/MS01-020.asp" fullword ascii
		 $a6= "SoftwareMicrosoftWindowsCurrentVersionPoliciesComdlg32" fullword ascii
		 $a7= "SoftwareMicrosoftWindowsCurrentVersionPoliciesExplorer" fullword ascii
		 $a8= "SoftwareMicrosoftWindowsCurrentVersionPoliciesNetwork" fullword ascii

		 $hex1= {2461313d2022346874}
		 $hex2= {2461323d2022346874}
		 $hex3= {2461333d2022484b45}
		 $hex4= {2461343d2022484b45}
		 $hex5= {2461353d2022687474}
		 $hex6= {2461363d2022536f66}
		 $hex7= {2461373d2022536f66}
		 $hex8= {2461383d2022536f66}
		 $hex9= {2473313d2022687474}
		 $hex10= {2473323d202257696e}
		 $hex11= {2473333d202257696e}

	condition:
		7 of them
}
