
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Pushdo 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Pushdo {
	meta: 
		 description= "vx_underground2_Pushdo Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-13-50" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "40165ee6b1d69c58d3c0d2f4701230fa"
		 hash2= "6e54267c787fc017a2b2cc5dc5273a0a"
		 hash3= "7b7584d86efa2df42fe504213a3d1d2c"
		 hash4= "891823de9b05e17def459e04fb574f94"
		 hash5= "b988944f831c478f5a6d71f9e06fbc22"
		 hash6= "be284327e1c97be35d9439383878e29d"
		 hash7= "de3b206a8066db48e9d7b0a42d50c5cd"
		 hash8= "e93799591429756b7a5ad6e44197c020"
		 hash9= "f088b291af1a3710f99c33fa37f68602"

	strings:

	
 		 $s1= "2http://www.facebook.com/" fullword wide
		 $s2= "abe2869f-9b47-4cd9-a358-c22904dba7f7" fullword wide
		 $a1= "SOFTWAREClassesTypeLib{9EA55529-E122-4757-BC79-E4825F80732C}" fullword ascii
		 $a2= "SOFTWAREClassesTypeLib{CB1F2C0F-8094-4AAC-BCF5-41A64E27F777}" fullword ascii
		 $a3= "SoftwareMicrosoftWindowsCurrentVersionExplorerShell Folders" fullword ascii

		 $hex1= {2461313d2022534f46}
		 $hex2= {2461323d2022534f46}
		 $hex3= {2461333d2022536f66}
		 $hex4= {2473313d2022326874}
		 $hex5= {2473323d2022616265}

	condition:
		3 of them
}
