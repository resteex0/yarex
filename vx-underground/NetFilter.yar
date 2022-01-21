
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_NetFilter 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_NetFilter {
	meta: 
		 description= "vx_underground2_NetFilter Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-12-01" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "c664fc54853d9b50d7e33bad5bd7070e"
		 hash2= "ccea678c13f13a8d6438a314e26cdc2a"

	strings:

	
 		 $s1= "%04d-%02d-%02d %02d:%02d:%02d" fullword wide
		 $s2= "/%04d-%02d-%02d %02d:%02d:%02d" fullword wide
		 $s3= "DefaultConnectionSettings" fullword wide
		 $s4= "D:P(A;;GA;;;SY)(A;;GA;;;BA)" fullword wide
		 $s5= "EnableLegacyAutoProxyFeatures" fullword wide
		 $s6= "SoftwareMicrosoftWindowsCurrentVersionInternet Settings" fullword wide
		 $a1= "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x" fullword ascii
		 $a2= "C:UsersomensourcereposnetfilterdrvReleasenetfilterdrv.pdb" fullword ascii
		 $a3= ">http://www.microsoft.com/pki/certs/MicRooCerAut_2010-06-23.crt0" fullword ascii
		 $a4= ">http://www.microsoft.com/pki/certs/MicTimStaPCA_2010-07-01.crt0" fullword ascii

		 $hex1= {2461313d2022253032}
		 $hex2= {2461323d2022433a55}
		 $hex3= {2461333d20223e6874}
		 $hex4= {2461343d20223e6874}
		 $hex5= {2473313d2022253034}
		 $hex6= {2473323d20222f2530}
		 $hex7= {2473333d2022446566}
		 $hex8= {2473343d2022443a50}
		 $hex9= {2473353d2022456e61}
		 $hex10= {2473363d2022536f66}

	condition:
		6 of them
}
