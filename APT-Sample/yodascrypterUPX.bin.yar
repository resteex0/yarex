
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_yodascrypterUPX_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_yodascrypterUPX_bin {
	meta: 
		 description= "APT_Sample_yodascrypterUPX_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-29_06-36-36" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "744cd119a11d72765f0688498c75ea66"

	strings:

	
 		 $s1= "EFGHIJKLMNOPQRST" fullword wide

		 $hex1= {45??46??47??48??49??4a??4b??4c??4d??4e??4f??50??51??52??53??54??0a??}

	condition:
		1 of them
}
