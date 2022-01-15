
/*
   YARA Rule Set
   Author: resteex
   Identifier: CryptoLocker_20Nov2013 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_CryptoLocker_20Nov2013 {
	meta: 
		 description= "CryptoLocker_20Nov2013 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-53-13" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "7f9c454a2e016e533e181d53eba113bc"

	strings:

	
 		 $s1= "accDefaultAction" fullword wide
		 $s2= "accDoDefaultAction" fullword wide
		 $s3= "accKeyboardShortcut" fullword wide
		 $s4= "Bronto Software" fullword wide
		 $s5= "FileDescription" fullword wide
		 $s6= "OriginalFilename" fullword wide
		 $s7= "temperatureSid.exe" fullword wide
		 $s8= "VS_VERSION_INFO" fullword wide

		 $hex1= {2473313d2022616363}
		 $hex2= {2473323d2022616363}
		 $hex3= {2473333d2022616363}
		 $hex4= {2473343d202242726f}
		 $hex5= {2473353d202246696c}
		 $hex6= {2473363d20224f7269}
		 $hex7= {2473373d202274656d}
		 $hex8= {2473383d202256535f}

	condition:
		1 of them
}
