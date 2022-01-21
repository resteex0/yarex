
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_NitlovePOS 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_NitlovePOS {
	meta: 
		 description= "vx_underground2_NitlovePOS Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-12-04" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "3309274e139157762b5708998d00cee0"
		 hash2= "4d877072fd81b5b18c2c585f5a58a56e"
		 hash3= "600e5df303765ff73dccff1c3e37c03a"
		 hash4= "6545d2528460884b24bf6d53b721bf9e"
		 hash5= "6cdd93dcb1c54a4e2b036d2e13b51216"
		 hash6= "9c6398de0101e6b3811cf35de6fc7b79"
		 hash7= "9e208e9d516f27fd95e8d165bd7911e8"
		 hash8= "abc69e0d444536e41016754cfee3ff90"
		 hash9= "ac8358ce51bbc7f7515e656316e23f8d"
		 hash10= "b3962f61a4819593233aa5893421c4d1"
		 hash11= "c8b0769eb21bb103b8fbda8ddaea2806"
		 hash12= "e339fce54e2ff6e9bd3a5c9fe6a214ea"
		 hash13= "e6531d4c246ecf82a2fd959003d76cca"

	strings:

	
 		 $s1= "5.1.2600.0 (xpclient.010817-1148)" fullword wide
		 $s2= "5.3.2600.2180 (xpsp_sp2_rtm.040803-2158)" fullword wide

		 $hex1= {2473313d2022352e31}
		 $hex2= {2473323d2022352e33}

	condition:
		1 of them
}
