
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Elirks 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Elirks {
	meta: 
		 description= "vx_underground2_Elirks Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-55-40" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0e4fa549aecac0c1d2c3983c5f35304e"
		 hash2= "195e7bbbb17e3c250292a016f3ade0a3"
		 hash3= "ba5b141c47851c36f082581975f6155f"
		 hash4= "e7b53922a81f9a4b76364c093f4bafe2"
		 hash5= "f8fd37b6b8bf80c282440886dbfe32db"

	strings:

	
 		 $s1= "Content-Type: application/x-www-form-urlencoded" fullword wide
		 $s2= "/logging.php?action=login" fullword wide
		 $s3= "SeRemoteShutdownPrivilege" fullword wide
		 $s4= "SOFTWAREMicrosoftWindowsCurrentVersionApp Paths" fullword wide
		 $s5= "SoftwareMicrosoftWindowsCurrentVersionInternet Settings" fullword wide
		 $s6= "/upload.php?action=reply&tid=%u" fullword wide
		 $a1= "=>?01234567()*+,|&'$!##$!&'XYZ[]^_PQRSTUVWHIJKLMNN@ACCD" fullword ascii
		 $a2= ";>?85j?49:;ff`?!-.)(.*'t!& #&tqP^YY][XWYS[[]QWW@OLCEOFGIGJCLM" fullword ascii
		 $a3= "8=>=9:=84605b2?7(((+.)&)%'#$$!% Z__]]ZZYUQRST]UWKLLMEJLHDFGEEC" fullword ascii
		 $a4= "/Filter[/FlateDecode]/Length 144/Type/EmbeddedFile>>stream" fullword ascii
		 $a5= "/Filter[/FlateDecode]/Length 176/Type/EmbeddedFile>>stream" fullword ascii
		 $a6= "/Filter[/FlateDecode]/Length 4064/Type/EmbeddedFile>>stream" fullword ascii
		 $a7= "/Filter[/FlateDecode]/Length 416/Type/EmbeddedFile>>stream" fullword ascii
		 $a8= "/Filter[/FlateDecode]/Length 656/Type/EmbeddedFile>>stream" fullword ascii
		 $a9= "/Filter[/FlateDecode]/Length 848/Type/EmbeddedFile>>stream" fullword ascii
		 $a10= "o:661334fe>.)++,y&&&!##$t..^Y[[]VVWQSSTWV^OIKKLNHFGACCDANN" fullword ascii

		 $hex1= {246131303d20226f3a}
		 $hex2= {2461313d20223d3e3f}
		 $hex3= {2461323d20223b3e3f}
		 $hex4= {2461333d2022383d3e}
		 $hex5= {2461343d20222f4669}
		 $hex6= {2461353d20222f4669}
		 $hex7= {2461363d20222f4669}
		 $hex8= {2461373d20222f4669}
		 $hex9= {2461383d20222f4669}
		 $hex10= {2461393d20222f4669}
		 $hex11= {2473313d2022436f6e}
		 $hex12= {2473323d20222f6c6f}
		 $hex13= {2473333d2022536552}
		 $hex14= {2473343d2022534f46}
		 $hex15= {2473353d2022536f66}
		 $hex16= {2473363d20222f7570}

	condition:
		10 of them
}
