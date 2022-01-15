
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Mamba 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Mamba {
	meta: 
		 description= "Ransomware_Mamba Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_19-53-53" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "409d80bb94645fbc4a1fa61c07806883"

	strings:

	
 		 $s1= "ArcNamemulti(0)disk(0)rdisk(0)partition(1)" fullword wide
		 $s2= "http://diskcryptor.net/index.php/DiskCryptor" fullword wide
		 $s3= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s4= "SoftwareMicrosoftWindowsCurrentVersionRunOnce" fullword wide
		 $s5= "SOFTWAREMicrosoftWindowsCurrentVersionUninstall" fullword wide
		 $s6= "SYSTEMCurrentControlSetControlCrashControl" fullword wide
		 $s7= "SYSTEMCurrentControlSetServicesdcryptconfig" fullword wide
		 $s8= "SYSTEMCurrentControlSetServicesdcryptInstances" fullword wide
		 $a1= "SOFTWAREMicrosoftWindowsCurrentVersionUninstall" fullword ascii
		 $a2= "SYSTEMCurrentControlSetServicesdcryptInstances" fullword ascii

		 $hex1= {2461313d2022534f46}
		 $hex2= {2461323d2022535953}
		 $hex3= {2473313d2022417263}
		 $hex4= {2473323d2022687474}
		 $hex5= {2473333d2022536f66}
		 $hex6= {2473343d2022536f66}
		 $hex7= {2473353d2022534f46}
		 $hex8= {2473363d2022535953}
		 $hex9= {2473373d2022535953}
		 $hex10= {2473383d2022535953}

	condition:
		1 of them
}
