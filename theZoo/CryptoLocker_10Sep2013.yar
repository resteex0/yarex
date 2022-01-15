
/*
   YARA Rule Set
   Author: resteex
   Identifier: CryptoLocker_10Sep2013 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_CryptoLocker_10Sep2013 {
	meta: 
		 description= "CryptoLocker_10Sep2013 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-37-21" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "04fb36199787f2e3e2135611a38321eb"

	strings:

	
 		 $s1= "184.164.136.134" fullword wide
		 $s2= "Connection: Close" fullword wide
		 $s3= "Files decryption" fullword wide
		 $s4= "msctls_progress32" fullword wide
		 $s5= "SoftwareCryptoLocker" fullword wide
		 $s6= "SoftwareCryptoLockerFiles" fullword wide
		 $s7= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $a1= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword ascii

		 $hex1= {2461313d2022536f66}
		 $hex2= {2473313d2022313834}
		 $hex3= {2473323d2022436f6e}
		 $hex4= {2473333d202246696c}
		 $hex5= {2473343d20226d7363}
		 $hex6= {2473353d2022536f66}
		 $hex7= {2473363d2022536f66}
		 $hex8= {2473373d2022536f66}

	condition:
		2 of them
}
