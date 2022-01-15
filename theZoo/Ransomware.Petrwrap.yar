
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Petrwrap 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Petrwrap {
	meta: 
		 description= "Ransomware_Petrwrap Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-37-48" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0487382a4daf8eb9660f1c67e30f8b25"
		 hash2= "51c028cd5f3afe9bf179d81def8d7a8e"
		 hash3= "65d9d04ea080e04e9d0aebf55aecd5d0"
		 hash4= "71b6a493388e7d0b40c83ce903bc6b04"
		 hash5= "b2303c3eb127d1ce6906d21d9d2d07a5"
		 hash6= "d2ec63b63e88ece47fbaab1ca22da1ef"

	strings:

	
 		 $s1= "{71461f04-2faa-4bb9-a0dd-28a79101b599}" fullword wide
		 $s2= "{8175e2c1-d077-43b3-8e9b-6232d4603826}" fullword wide
		 $s3= "Assembly Version" fullword wide
		 $s4= "FileDescription" fullword wide
		 $s5= "LegalTrademarks" fullword wide
		 $s6= "OriginalFilename" fullword wide
		 $s7= ", PublicKeyToken=" fullword wide
		 $s8= "PublicKeyToken=" fullword wide
		 $s9= "SeDebugPrivilege" fullword wide
		 $s10= "SeShutdownPrivilege" fullword wide
		 $s11= ",Sysinternals Utilitie" fullword wide
		 $s12= "VS_VERSION_INFO" fullword wide
		 $s13= "wowsmith123456@posteo.net." fullword wide
		 $s14= "\\%wsadmin$%ws" fullword wide
		 $a1= "{71461f04-2faa-4bb9-a0dd-28a79101b599}" fullword ascii
		 $a2= "{8175e2c1-d077-43b3-8e9b-6232d4603826}" fullword ascii

		 $hex1= {2461313d20227b3731}
		 $hex2= {2461323d20227b3831}
		 $hex3= {247331303d20225365}
		 $hex4= {247331313d20222c53}
		 $hex5= {247331323d20225653}
		 $hex6= {247331333d2022776f}
		 $hex7= {247331343d20222577}
		 $hex8= {2473313d20227b3731}
		 $hex9= {2473323d20227b3831}
		 $hex10= {2473333d2022417373}
		 $hex11= {2473343d202246696c}
		 $hex12= {2473353d20224c6567}
		 $hex13= {2473363d20224f7269}
		 $hex14= {2473373d20222c2050}
		 $hex15= {2473383d2022507562}
		 $hex16= {2473393d2022536544}

	condition:
		5 of them
}
