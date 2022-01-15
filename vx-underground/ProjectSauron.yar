
/*
   YARA Rule Set
   Author: resteex
   Identifier: ProjectSauron 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_ProjectSauron {
	meta: 
		 description= "ProjectSauron Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-17-02" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "01ac1cd4064b44cdfa24bf4eb40290e7"
		 hash2= "1d9d7d05ab7c68bdc257afb1c086fb88"
		 hash3= "2a8785bf45f4f03c10cd929bb0685c2d"
		 hash4= "6ca97b89af29d7eff94a3a60fa7efe0a"
		 hash5= "6cd8311d11dc973e970237e10ed04ad7"
		 hash6= "7261230a43a40bb29227a169c2c8e1be"
		 hash7= "7b8a3bf6fd266593db96eddaa3fae6f9"
		 hash8= "9f81f59bc58452127884ce513865ed20"
		 hash9= "b98227f8116133dc8060f2ada986631c"
		 hash10= "cf6c049bd7cd9e04cc365b73f3f6098e"
		 hash11= "edb9e045b8dc7bb0b549bdf28e55f3b5"

	strings:

	
 		 $s1= "6.1.7600.16385 (win7_rtm.090713-1255)" fullword wide
		 $s2= "6.1.7601.22137 (win7sp1_ldr.121018-0535)" fullword wide

		 $hex1= {2473313d2022362e31}
		 $hex2= {2473323d2022362e31}

	condition:
		1 of them
}
