
/*
   YARA Rule Set
   Author: resteex
   Identifier: Bedep 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Bedep {
	meta: 
		 description= "Bedep Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-01-02" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2faf2044e18837d23aa325cb21f17c4b"
		 hash2= "46df78cf0eea2915422d84928dbc2462"
		 hash3= "854646bdcf4da69c975dd627f5635037"

	strings:

	
 		 $s1= "5.2.3790.0 (srv03_rtm.030324-2048)" fullword wide
		 $s2= "6.0.3790.1830 (srv03_sp1_rtm.050324-1447)" fullword wide
		 $s3= "DEFGHIJKLMNOPQRSTUVWXYZ[]^_`" fullword wide
		 $s4= "UV.-;.,>,(),+,,.,@ABC,()G+,,,]+" fullword wide

		 $hex1= {2473313d2022352e32}
		 $hex2= {2473323d2022362e30}
		 $hex3= {2473333d2022444546}
		 $hex4= {2473343d202255562e}

	condition:
		2 of them
}
