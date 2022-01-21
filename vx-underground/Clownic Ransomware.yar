
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Clownic_Ransomware 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Clownic_Ransomware {
	meta: 
		 description= "vx_underground2_Clownic_Ransomware Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-53-54" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "711486a19e8b011528dee34a5d25776e"

	strings:

	
 		 $s1= "Rasomware2._0.Properties.Resources" fullword wide
		 $s2= "SoftwareMicrosoftWindowsCurrentVersionPoliciesSystem" fullword wide
		 $s3= "SOFTWAREMicrosoftWindows NTCurrentVersionWinlogon" fullword wide

		 $hex1= {2473313d2022526173}
		 $hex2= {2473323d2022536f66}
		 $hex3= {2473333d2022534f46}

	condition:
		2 of them
}
