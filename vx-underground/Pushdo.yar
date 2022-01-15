
/*
   YARA Rule Set
   Author: resteex
   Identifier: Pushdo 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Pushdo {
	meta: 
		 description= "Pushdo Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-17-03" 
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

		 $hex1= {2473313d2022326874}
		 $hex2= {2473323d2022616265}

	condition:
		1 of them
}
