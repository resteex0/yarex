
/*
   YARA Rule Set
   Author: resteex
   Identifier: W32_Klez_E 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W32_Klez_E {
	meta: 
		 description= "W32_Klez_E Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-54-20" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "07c19da3a33f9ec6a97f3837aef6fde0"
		 hash2= "0af5aa9768abf8f19a6b3fa767660058"
		 hash3= "a99afd20a2a91ac3f1c17e0fb96c7832"
		 hash4= "b023af582bfe56ae0c32401599b7d082"
		 hash5= "b232ff116d2659a47f06389c5b4c73c1"
		 hash6= "bbb1522b1db750efbcf7813e9153d424"

	strings:

	
 		 $s1= "accDefaultAction" fullword wide
		 $s2= "accKeyboardShortcut" fullword wide
		 $s3= "Anti Win32.Klez" fullword wide
		 $s4= "FileDescription" fullword wide
		 $s5= "http://www.bitdefender.com" fullword wide
		 $s6= "Invalid filename." fullword wide
		 $s7= "LegalTrademarks" fullword wide
		 $s8= "OriginalFilename" fullword wide
		 $s9= "Symantec Corporation" fullword wide
		 $s10= "VS_VERSION_INFO" fullword wide
		 $s11= "Win32.Klez.A@mm, Win32.Klez.B@mm," fullword wide
		 $s12= "Win32.Klez.C@mm, Win32.Klez.D@mm," fullword wide
		 $s13= "www.bitdefender.com" fullword wide
		 $s14= "YaccDoDefaultAction" fullword wide

		 $hex1= {247331303d20225653}
		 $hex2= {247331313d20225769}
		 $hex3= {247331323d20225769}
		 $hex4= {247331333d20227777}
		 $hex5= {247331343d20225961}
		 $hex6= {2473313d2022616363}
		 $hex7= {2473323d2022616363}
		 $hex8= {2473333d2022416e74}
		 $hex9= {2473343d202246696c}
		 $hex10= {2473353d2022687474}
		 $hex11= {2473363d2022496e76}
		 $hex12= {2473373d20224c6567}
		 $hex13= {2473383d20224f7269}
		 $hex14= {2473393d202253796d}

	condition:
		1 of them
}
