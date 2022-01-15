
/*
   YARA Rule Set
   Author: resteex
   Identifier: Clownic_Ransomware 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Clownic_Ransomware {
	meta: 
		 description= "Clownic_Ransomware Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-01-26" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "711486a19e8b011528dee34a5d25776e"

	strings:

	
 		 $s1= "Rasomware2._0.Properties.Resources" fullword wide
		 $s2= "SoftwareMicrosoftWindowsCurrentVersionPoliciesSystem" fullword wide
		 $s3= "SOFTWAREMicrosoftWindows NTCurrentVersionWinlogon" fullword wide
		 $a1= "SoftwareMicrosoftWindowsCurrentVersionPoliciesSystem" fullword ascii
		 $a2= "SOFTWAREMicrosoftWindows NTCurrentVersionWinlogon" fullword ascii

		 $hex1= {2461313d2022536f66}
		 $hex2= {2461323d2022534f46}
		 $hex3= {2473313d2022526173}
		 $hex4= {2473323d2022536f66}
		 $hex5= {2473333d2022534f46}

	condition:
		3 of them
}
