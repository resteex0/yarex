
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_BerserkBear_Downloader_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_BerserkBear_Downloader_bin {
	meta: 
		 description= "APT_Sample_BerserkBear_Downloader_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-29_06-39-33" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "f7c5d117c91bd22fa17d2d5444ff7ab7"

	strings:

	
 		 $s1= "CEGIKMOQSUWY[]_a" fullword wide

		 $hex1= {43??45??47??49??4b??4d??4f??51??53??55??57??59??5b??5d??5f??61??0a??}

	condition:
		1 of them
}
