
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_DecafRansomware 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_DecafRansomware {
	meta: 
		 description= "vx_underground2_DecafRansomware Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-54-49" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "298b9c281bab03460621171d76476850"
		 hash2= "46a1325bb01e37e0ee2d2ba37db257f2"

	strings:

	
 		 $a1= "B/xuTOuDjmUSNiGyijWBVfYk7sVXl/lQ8taXr36xPWhMIG0EqRVrFV+cavS7Z4va" fullword ascii
		 $a2= ">http://www.microsoft.com/pki/certs/MicRooCerAut_2010-06-23.crt0" fullword ascii
		 $a3= ">http://www.microsoft.com/pki/certs/MicTimStaPCA_2010-07-01.crt0" fullword ascii

		 $hex1= {2461313d2022422f78}
		 $hex2= {2461323d20223e6874}
		 $hex3= {2461333d20223e6874}

	condition:
		2 of them
}
