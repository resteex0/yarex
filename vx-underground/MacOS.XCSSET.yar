
/*
   YARA Rule Set
   Author: resteex
   Identifier: MacOS_XCSSET 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_MacOS_XCSSET {
	meta: 
		 description= "MacOS_XCSSET Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-14-47" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2f7d8e7c6be2ffecd4b6a48c3d4f73df"
		 hash2= "3b0257a1a7e8b7e66840888db18be1cd"
		 hash3= "48d5f141c857e6779c7c4a01b3bf32fb"
		 hash4= "e5299d8d7159103a3741157c5160edd4"

	strings:

	
 		 $s1= "$0/CoreFrameworks/com.scp" fullword wide
		 $s2= "L' https://adobestats.com/agent/log.ph" fullword wide

		 $hex1= {2473313d202224302f}
		 $hex2= {2473323d20224c2720}

	condition:
		1 of them
}
