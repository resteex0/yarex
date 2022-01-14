
/*
   YARA Rule Set
   Author: resteex
   Identifier: Darkside 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Darkside {
	meta: 
		 description= "Darkside Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_00-46-01" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "04fde4340cc79cd9e61340d4c1e8ddfb"
		 hash2= "0e178c4808213ce50c2540468ce409d3"
		 hash3= "0ed51a595631e9b4d60896ab5573332f"
		 hash4= "130220f4457b9795094a21482d5f104b"
		 hash5= "1a700f845849e573ab3148daef1a3b0b"
		 hash6= "1c33dc87c6fdb80725d732a5323341f9"
		 hash7= "222792d2e75782516d653d5cccfcf33b"
		 hash8= "29bcd459f5ddeeefad26fc098304e786"
		 hash9= "3fd9b0117a0e79191859630148dcdc6d"
		 hash10= "47a4420ad26f60bb6bba5645326fa963"
		 hash11= "4c99af42d102c863bbae84db9f133a82"
		 hash12= "4d419dc50e3e4824c096f298e0fa885a"
		 hash13= "5ff75d33080bb97a8e6b54875c221777"
		 hash14= "66ddb290df3d510a6001365c3a694de2"
		 hash15= "68ada5f6aa8e3c3969061e905ceb204c"
		 hash16= "69ec3d1368adbe75f3766fc88bc64afc"
		 hash17= "6a7fdab1c7f6c5a5482749be5c4bf1a4"
		 hash18= "84c1567969b86089cc33dccf41562bcd"
		 hash19= "885fc8fb590b899c1db7b42fe83dddc3"
		 hash20= "91e2807955c5004f13006ff795cb803c"
		 hash21= "9d418ecc0f3bf45029263b0944236884"
		 hash22= "9e779da82d86bcd4cc43ab29f929f73f"
		 hash23= "a3d964aaf642d626474f02ba3ae4f49b"
		 hash24= "b0fd45162c2219e14bdccab76f33946e"
		 hash25= "b278d7ec3681df16a541cf9e34d3b70a"
		 hash26= "b9d04060842f71d1a8f3444316dc1843"
		 hash27= "c2764be55336f83a59aa0f63a0b36732"
		 hash28= "c4f1a1b73e4af0fbb63af8ee89a5a7fe"
		 hash29= "c81dae5c67fb72a2c2f24b178aea50b7"
		 hash30= "c830512579b0e08f40bc1791fc10c582"
		 hash31= "cfcfb68901ffe513e9f0d76b17d02f96"
		 hash32= "d6634959e4f9b42dfc02b270324fa6d9"
		 hash33= "e44450150e8683a0addd5c686cd4d202"
		 hash34= "f75ba194742c978239da2892061ba1b4"
		 hash35= "f87a2e1c3d148a67eaeb696b1ab69133"
		 hash36= "f913d43ba0a9f921b1376b26cd30fa34"
		 hash37= "f9fc1a1a95d5723c140c2a8effc93722"

	strings:

	
 		 $s1= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s2= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s3= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s4= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s5= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s6= "Bapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s7= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s8= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide

		 $hex1= {2473313d2022617069}
		 $hex2= {2473323d2022617069}
		 $hex3= {2473333d2022617069}
		 $hex4= {2473343d2022617069}
		 $hex5= {2473353d2022617069}
		 $hex6= {2473363d2022426170}
		 $hex7= {2473373d2022657874}
		 $hex8= {2473383d2022657874}

	condition:
		1 of them
}
