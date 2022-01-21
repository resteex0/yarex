
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Ransomware_Jigsaw 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Ransomware_Jigsaw {
	meta: 
		 description= "theZoo_Ransomware_Jigsaw Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-35-15" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2773e3dc59472296cb0024ba7715a64e"

	strings:

	
 		 $s1= "12Xspzstah37626slkwKhsKSHA" fullword wide
		 $s2= "costura.newtonsoft.json.dll.zip" fullword wide
		 $s3= "dataGridViewEncryptedFiles" fullword wide
		 $s4= "http://btc.blockr.io/api/v1/" fullword wide
		 $s5= "Main.Properties.Resources" fullword wide
		 $s6= "SOFTWAREMicrosoftWindowsCurrentVersionRun" fullword wide
		 $a1= "System.String>.Current" fullword ascii

		 $hex1= {2461313d2022537973}
		 $hex2= {2473313d2022313258}
		 $hex3= {2473323d2022636f73}
		 $hex4= {2473333d2022646174}
		 $hex5= {2473343d2022687474}
		 $hex6= {2473353d20224d6169}
		 $hex7= {2473363d2022534f46}

	condition:
		4 of them
}
