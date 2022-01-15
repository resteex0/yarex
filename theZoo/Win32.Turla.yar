
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Turla 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Turla {
	meta: 
		 description= "Win32_Turla Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-39-23" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2b47ad7df9902aaa19474723064ee76f"
		 hash2= "3c1a8991e96f4c56ae3e90fb6f0ae679"
		 hash3= "5f8f3cf46719afa7eb5f761cdd18b63d"
		 hash4= "aac56baff4be3db02378f11b9844dcb5"
		 hash5= "b46c792c8e051bc5c9d4cecab96e4c30"
		 hash6= "f57c84e22e9e6eaa6cbd9730d7c652dc"

	strings:

	
 		 $s1= "{a1d3d2d3-af20-4317-903f-78271c44b294}" fullword wide
		 $s2= "apisetschema.dll" fullword wide
		 $s3= "REGISTRYMACHINESoftwareMicrosoftWindows NTCurrentVersion" fullword wide
		 $s4= "SeShutdownPrivilege" fullword wide
		 $s5= "tapisetschema.dll" fullword wide
		 $a1= "{a1d3d2d3-af20-4317-903f-78271c44b294}" fullword ascii
		 $a2= "REGISTRYMACHINESoftwareMicrosoftWindows NTCurrentVersion" fullword ascii

		 $hex1= {2461313d20227b6131}
		 $hex2= {2461323d2022524547}
		 $hex3= {2473313d20227b6131}
		 $hex4= {2473323d2022617069}
		 $hex5= {2473333d2022524547}
		 $hex6= {2473343d2022536553}
		 $hex7= {2473353d2022746170}

	condition:
		2 of them
}
