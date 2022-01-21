
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_CryptoLocker_10Sep2013 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_CryptoLocker_10Sep2013 {
	meta: 
		 description= "theZoo_CryptoLocker_10Sep2013 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-34-51" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "04fb36199787f2e3e2135611a38321eb"

	strings:

	
 		 $s1= "SoftwareCryptoLockerFiles" fullword wide
		 $s2= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide

		 $hex1= {2473313d2022536f66}
		 $hex2= {2473323d2022536f66}

	condition:
		1 of them
}
