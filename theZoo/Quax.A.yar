
/*
   YARA Rule Set
   Author: resteex
   Identifier: Quax_A 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Quax_A {
	meta: 
		 description= "Quax_A Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-42-49" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "50a572e94c69b0644576519b182f67dd"
		 hash2= "ba02f4502d6ca67ea5033aebce28a36d"

	strings:

	
 		 $a1= "-=->-?-@-A-B-C-D-E-F-G-H-I-J-K-L-M-N-O-P-Q-" fullword ascii

		 $hex1= {2461313d20222d3d2d}

	condition:
		0 of them
}
