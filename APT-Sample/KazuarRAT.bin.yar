
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_KazuarRAT_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_KazuarRAT_bin {
	meta: 
		 description= "APT_Sample_KazuarRAT_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-29_06-37-20" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "edfd33d319af1cce7baa1b15b52940e7"

	strings:

	
 		 $s1= "C:6gCzH5r1.exe" fullword wide

		 $hex1= {43??3a??36??67??43??7a??48??35??72??31??2e??65??78??65??0a??}

	condition:
		1 of them
}
