
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
		 date = "2022-01-14_22-51-20" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "409d80bb94645fbc4a1fa61c07806883"

	strings:

	
 		 $s1= "ArcNamemulti(0)disk(0)rdisk(0)partition(1)" fullword wide
		 $s2= "http://diskcryptor.net/forum" fullword wide
		 $s3= "http://diskcryptor.net/index.php/DiskCryptor" fullword wide
		 $s4= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s5= "SoftwareMicrosoftWindowsCurrentVersionRunOnce" fullword wide
		 $s6= "SOFTWAREMicrosoftWindowsCurrentVersionUninstall" fullword wide
		 $s7= "spanish-dominican republic" fullword wide
		 $s8= "SYSTEMCurrentControlSetControlCrashControl" fullword wide
		 $s9= "SYSTEMCurrentControlSetServicesdcryptconfig" fullword wide
		 $s10= "SYSTEMCurrentControlSetServicesdcryptInstances" fullword wide
		 $a1= "SOFTWAREMicrosoftWindowsCurrentVersionUninstall" fullword ascii
		 $a2= "SYSTEMCurrentControlSetServicesdcryptInstances" fullword ascii

		 $hex1= {2461313d2022534f46}
		 $hex2= {2461323d2022535953}
		 $hex3= {247331303d20225359}
		 $hex4= {2473313d2022417263}
		 $hex5= {2473323d2022687474}
		 $hex6= {2473333d2022687474}
		 $hex7= {2473343d2022536f66}
		 $hex8= {2473353d2022536f66}
		 $hex9= {2473363d2022534f46}
		 $hex10= {2473373d2022737061}
		 $hex11= {2473383d2022535953}
		 $hex12= {2473393d2022535953}

	condition:
		8 of them
}
