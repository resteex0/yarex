
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_VolatileCedar_Explosion 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_VolatileCedar_Explosion {
	meta: 
		 description= "theZoo_VolatileCedar_Explosion Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-36-01" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "034e4c62965f8d5dd5d5a2ce34a53ba9"
		 hash2= "08c988d6cebdd55f3b123f2d9d5507a6"
		 hash3= "184320a057e455555e3be22e67663722"
		 hash4= "1d4b0fc476b7d20f1ef590bcaa78dc5d"
		 hash5= "1dcac3178a1b85d5179ce75eace04d10"
		 hash6= "22872f40f5aad3354bbf641fe90f2fd6"
		 hash7= "29eca6286a01c0b684f7d5f0bfe0c0e6"
		 hash8= "2b9106e8df3aa98c3654a4e0733d83e7"
		 hash9= "306d243745ba53d09353b3b722d471b8"
		 hash10= "3f35c97e9e87472030b84ae1bc932ffc"
		 hash11= "44b5a3af895f31e22f6bc4eb66bd3eb7"
		 hash12= "4f8b989bc424a39649805b5b93318295"
		 hash13= "5b505d0286378efcca4df38ed4a26c90"
		 hash14= "5ca3ac2949022e5c77335f7e228db1d8"
		 hash15= "5d437eb2a22ec8f37139788f2087d45d"
		 hash16= "61b11b9e6baae4f764722a808119ed0c"
		 hash17= "66e2adf710261e925db588b5fac98ad8"
		 hash18= "6f11a67803e1299a22c77c8e24072b82"
		 hash19= "7031426fb851e93965a72902842b7c2c"
		 hash20= "740c47c663f5205365ae9fb08adfb127"
		 hash21= "7cd87c4976f1b34a0b060a23faddbd19"
		 hash22= "7dbc46559efafe8ec8446b836129598c"
		 hash23= "826b772c81f41505f96fc18e666b1acd"
		 hash24= "981234d969a4c5e6edea50df009efedd"
		 hash25= "9a5a99def615966ea05e3067057d6b37"
		 hash26= "ab3d0c748ced69557f78b7071879e50a"
		 hash27= "c19e91a91a2fa55e869c42a70da9a506"
		 hash28= "c7ac6193245b76cc8cebc2835ee13532"
		 hash29= "c898aed0ab4173cc3ac7d4849d06e7fa"
		 hash30= "c9a4317f1002fefcc7a250c3d76d4b01"
		 hash31= "d2074d6273f41c34e8ba370aa9af46ad"
		 hash32= "e6f874b7629b11a2f5ed3cc2c123f8b6"
		 hash33= "ea53e618432ca0c823fafc06dc60b726"
		 hash34= "eb7042ad32f41c0e577b5b504c7558ea"
		 hash35= "edaca6fb1896a120237b2ce13f6bc3e6"

	strings:

	
 		 $s1= "6.00.2900.2180 (xpsp_sp2_rtm.040803-2158)" fullword wide
		 $s2= "6.1.7600.16385 (win7_rtm.090713-1255)" fullword wide
		 $s3= "EL$_RasDefaultCredentials#0" fullword wide
		 $a1= "Application DataMicrosoftNetworkConnectionspbkrasphone.pbk" fullword ascii
		 $a2= "DLD-NTI:300:DLD-NTI)DLD-IP:49@50@55@46@48@46@48@46@49@:DLD-IP" fullword ascii
		 $a3= "HKEY_CURRENT_USERSOFTWAREMicrosoftWindowsCurrentVersionRun" fullword ascii

		 $hex1= {2461313d2022417070}
		 $hex2= {2461323d2022444c44}
		 $hex3= {2461333d2022484b45}
		 $hex4= {2473313d2022362e30}
		 $hex5= {2473323d2022362e31}
		 $hex6= {2473333d2022454c24}

	condition:
		4 of them
}
