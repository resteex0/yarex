
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Ransomware_Mamba 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Ransomware_Mamba {
	meta: 
		 description= "theZoo_Ransomware_Mamba Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-35-16" 
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

		 $hex1= {247331303d20225359}
		 $hex2= {2473313d2022417263}
		 $hex3= {2473323d2022687474}
		 $hex4= {2473333d2022687474}
		 $hex5= {2473343d2022536f66}
		 $hex6= {2473353d2022536f66}
		 $hex7= {2473363d2022534f46}
		 $hex8= {2473373d2022737061}
		 $hex9= {2473383d2022535953}
		 $hex10= {2473393d2022535953}

	condition:
		6 of them
}
