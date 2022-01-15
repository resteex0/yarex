
/*
   YARA Rule Set
   Author: resteex
   Identifier: FritzFrog 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_FritzFrog {
	meta: 
		 description= "FritzFrog Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-04-39" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0263de27fd997a4904ee4a92f91ac733"
		 hash2= "100bff2f4ee4d88b005bb016daa04fe6"
		 hash3= "3a371a09bfcba3d545465339f1e1d481"
		 hash4= "3fe7b88a9ba6c5acee4faae760642b78"
		 hash5= "4842d5cc29c97aa611fba5ca07b060a5"
		 hash6= "682ac123d740321e6ba04d82e8cc4ed8"
		 hash7= "76fe4fdd628218f630ba50f91ceba852"
		 hash8= "799c965e0a5a132ec2263d5fea0b0e1c"
		 hash9= "819b0fdb2b9c8a440b734a7b72522f12"
		 hash10= "8f0cb7af15afe40ed85f35e1b40b8f38"
		 hash11= "97cfb3c26a12e13792f7d1741309d767"
		 hash12= "aa55272ad8db954381a8eab889f087cf"
		 hash13= "ae747bc7fff9bc23f06635ef60ea0e8d"
		 hash14= "b2e0eede7b18253dccd0d44ebb5db85a"
		 hash15= "c947363b50231882723bd6b07bc291ca"
		 hash16= "d4e533f9c11b5cc9e755d94c1315553a"

	strings:

	
 		 $s1= "!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13" fullword wide
		 $a1= "!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13" fullword ascii

		 $hex1= {2461313d2022212325}
		 $hex2= {2473313d2022212325}

	condition:
		1 of them
}
