
/*
   YARA Rule Set
   Author: resteex
   Identifier: Elirks 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Elirks {
	meta: 
		 description= "Elirks Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-03-32" 
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
		 $a1= "SOFTWAREMicrosoftWindowsCurrentVersionApp Paths" fullword ascii
		 $a2= "SoftwareMicrosoftWindowsCurrentVersionInternet Settings" fullword ascii

		 $hex1= {2461313d2022534f46}
		 $hex2= {2461323d2022536f66}
		 $hex3= {2473313d2022436f6e}
		 $hex4= {2473323d20222f6c6f}
		 $hex5= {2473333d2022536552}
		 $hex6= {2473343d2022534f46}
		 $hex7= {2473353d2022536f66}
		 $hex8= {2473363d20222f7570}

	condition:
		5 of them
}
