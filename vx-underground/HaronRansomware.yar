
/*
   YARA Rule Set
   Author: resteex
   Identifier: HaronRansomware 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_HaronRansomware {
	meta: 
		 description= "HaronRansomware Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-07-25" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "dedad693898bba0e4964e6c9a749d380"

	strings:

	
 		 $s1= "! $#&%('/.0.21435363A@GFHFIFJFKFLFMFONPNQNRNSN!" fullword wide
		 $s2= "{e5c43f0f-0868-4f29-a2f6-76c871139ec3}" fullword wide

		 $hex1= {2473313d2022212024}
		 $hex2= {2473323d20227b6535}

	condition:
		1 of them
}
