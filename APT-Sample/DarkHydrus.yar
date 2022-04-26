
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_DarkHydrus 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_DarkHydrus {
	meta: 
		 description= "APT_Sample_DarkHydrus Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_02-20-54" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1a57c63942d049b222f9b0179f5216fd"
		 hash2= "21e9451af7c59a4a136f4046d036352a"
		 hash3= "4e77d769514d476d598f17e31f165cc4"
		 hash4= "953a753dd4944c9a2b9876b090bf7c00"
		 hash5= "ab9cf050fb3f4fadf3eb080e09995cda"
		 hash6= "bd764192e951b5afd56870d2084bccfd"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "VS_VERSION_INFO" fullword wide

		 $hex1= {46??69??6c??65??44??65??73??63??72??69??70??74??69??6f??6e??0a??}
		 $hex2= {56??53??5f??56??45??52??53??49??4f??4e??5f??49??4e??46??4f??0a??}

	condition:
		2 of them
}
