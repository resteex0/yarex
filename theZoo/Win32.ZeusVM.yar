
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_ZeusVM 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_ZeusVM {
	meta: 
		 description= "Win32_ZeusVM Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-45-17" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "34875dcb19479c5df2b059cc967b76e7"
		 hash2= "8a0c95be8a40ae5419f7d97bb3e91b2b"

	strings:

	
 		 $s1= "Rihanna-Millionen-verschwendet" fullword wide

		 $hex1= {2473313d2022526968}

	condition:
		0 of them
}
