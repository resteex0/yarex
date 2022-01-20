
/*
   YARA Rule Set
   Author: resteex
   Identifier: VBS_NoMercy_B 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_VBS_NoMercy_B {
	meta: 
		 description= "VBS_NoMercy_B Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-43-56" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "54d7a0c80595ec07cfe9c9da6cceec26"
		 hash2= "9db9456adf7d62035de23ab3133aaa65"

	strings:

	
 		 $a1= "iQA/AwUBNvWQwvrs3+cY486eEQJk7ACfQe2+EYIIyQrGrv/y53f4DE3KChgAoK4Y" fullword ascii

		 $hex1= {2461313d2022695141}

	condition:
		0 of them
}
