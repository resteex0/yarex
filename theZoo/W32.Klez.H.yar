
/*
   YARA Rule Set
   Author: resteex
   Identifier: W32_Klez_H 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W32_Klez_H {
	meta: 
		 description= "W32_Klez_H Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-54-20" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "07c19da3a33f9ec6a97f3837aef6fde0"
		 hash2= "4ae9a4a8b8ce22c7b52c2eaec75ca536"
		 hash3= "60c271a141c1cbd29489e1a2925b639f"
		 hash4= "b023af582bfe56ae0c32401599b7d082"
		 hash5= "bbb1522b1db750efbcf7813e9153d424"

	strings:

	
 		 $s1= "accDefaultAction" fullword wide
		 $s2= "accKeyboardShortcut" fullword wide
		 $s3= "Anti Win32.Klez" fullword wide
		 $s4= "FileDescription" fullword wide
		 $s5= "http://www.bitdefender.com" fullword wide
		 $s6= "Invalid filename." fullword wide
		 $s7= "LegalTrademarks" fullword wide
		 $s8= "Microsoft Corporation" fullword wide
		 $s9= "OriginalFilename" fullword wide
		 $s10= "Symantec Corporation" fullword wide
		 $s11= "VS_VERSION_INFO" fullword wide
		 $s12= "Win32.Klez.A@mm, Win32.Klez.B@mm," fullword wide
		 $s13= "Win32.Klez.C@mm, Win32.Klez.D@mm," fullword wide
		 $s14= "www.bitdefender.com" fullword wide
		 $s15= "YaccDoDefaultAction" fullword wide

		 $hex1= {247331303d20225379}
		 $hex2= {247331313d20225653}
		 $hex3= {247331323d20225769}
		 $hex4= {247331333d20225769}
		 $hex5= {247331343d20227777}
		 $hex6= {247331353d20225961}
		 $hex7= {2473313d2022616363}
		 $hex8= {2473323d2022616363}
		 $hex9= {2473333d2022416e74}
		 $hex10= {2473343d202246696c}
		 $hex11= {2473353d2022687474}
		 $hex12= {2473363d2022496e76}
		 $hex13= {2473373d20224c6567}
		 $hex14= {2473383d20224d6963}
		 $hex15= {2473393d20224f7269}

	condition:
		1 of them
}
