
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_W32_Klez_E 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_W32_Klez_E {
	meta: 
		 description= "theZoo_W32_Klez_E Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-36-05" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "07c19da3a33f9ec6a97f3837aef6fde0"
		 hash2= "0af5aa9768abf8f19a6b3fa767660058"
		 hash3= "a99afd20a2a91ac3f1c17e0fb96c7832"
		 hash4= "b023af582bfe56ae0c32401599b7d082"
		 hash5= "b232ff116d2659a47f06389c5b4c73c1"
		 hash6= "bbb1522b1db750efbcf7813e9153d424"

	strings:

	
 		 $s1= "http://www.bitdefender.com" fullword wide
		 $s2= "Win32.Klez.A@mm, Win32.Klez.B@mm," fullword wide
		 $s3= "Win32.Klez.C@mm, Win32.Klez.D@mm," fullword wide
		 $a1= "HKEY_LOCAL_MACHINESoftwareMicrosoftWindowsCurrentVersionRun" fullword ascii
		 $a2= "http://www.microsoft.com/technet/security/bulletin/MS01-020.asp" fullword ascii

		 $hex1= {2461313d2022484b45}
		 $hex2= {2461323d2022687474}
		 $hex3= {2473313d2022687474}
		 $hex4= {2473323d202257696e}
		 $hex5= {2473333d202257696e}

	condition:
		3 of them
}
