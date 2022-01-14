
/*
   YARA Rule Set
   Author: resteex
   Identifier: FighterPOS 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_FighterPOS {
	meta: 
		 description= "FighterPOS Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_01-09-28" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "03e2598ed6749480879524dc50968ce5"
		 hash2= "0476145bab17d348caad05233a21c59c"
		 hash3= "0ca6d769dbce182f84a82835fe44fc5f"
		 hash4= "2917f38b4b310d0d26599af11bd9ca2f"
		 hash5= "29d5b1ffdd4701cad0edeb8773ad6574"
		 hash6= "31c19f04e4a5cd4c1b9cf530349f3f39"
		 hash7= "3590e9305fc0c4a8d7085bd33675d035"
		 hash8= "3e6e1e03fed32ba9d27d46c3981666a8"
		 hash9= "591304b96923aa03979477885f238ad1"
		 hash10= "5c855ee2247b039f01892818021d4003"
		 hash11= "5e58d7ffa3c946a0fb730d82afebc8f9"
		 hash12= "5f2c71138cabb2591558368888a4b0cc"
		 hash13= "677f66594ee0cf2cbf4d7bc87435cbef"
		 hash14= "6cb50f7f2fe6f69ee8613d531e816089"
		 hash15= "78b610809b8d76504845f7c6acbf5872"
		 hash16= "7b9a36f3d28fdcf6cf142a9b2aa0f1d8"
		 hash17= "83f4c831576d2668d61148cbeeaead3b"
		 hash18= "86796f798d87ceaf81779f6d9f0ce9d3"
		 hash19= "9284a3db47bb237dbf39803b9af33ce6"
		 hash20= "9fd89e62451545c7c03ed9bb995885af"
		 hash21= "a3382a248a89277e1f2aea3c4c081581"
		 hash22= "a455a05fad2434843cdfb0afa8c03b82"
		 hash23= "a522a3fbab74e6436121c4da9c65644f"
		 hash24= "ab329da23704672235f8201bb735a512"
		 hash25= "b9cfa4698972c89a2b47369873558cc5"
		 hash26= "ba953dc12994580f1135c1c4ca0aafec"
		 hash27= "c31095e453b165a561fd30f98c384df0"
		 hash28= "c40c0726196ab1d6afab94cf09f2fc7c"
		 hash29= "c4245850a3e45cd63d3510856fe5b34e"
		 hash30= "c8eccca5edd2d030aa64869a2decd445"
		 hash31= "d13e1b8632f391d94c5e4138d5f26371"
		 hash32= "d1d96fa9349126e11bce189f5bc206d1"
		 hash33= "d8b6f7d0d071177825bde72b5467baf8"
		 hash34= "e29d9560b6fcc14290f411eed9f4ff4f"
		 hash35= "e794171d0ebbe14f3e0aaf70c68c4e86"
		 hash36= "e9ef65b60183a7d3a8cdc1151e67d9f6"
		 hash37= "f04a3b785783140186befdccf57c4e3c"
		 hash38= "f11bf1952276c823b173d5aaca5f3c3e"
		 hash39= "f351b06f5681509e723e67f679e4b627"
		 hash40= "f4f7686c4f1e8f1fd76363a269ed9fda"
		 hash41= "ff3ce3c400a57b15684468995406684d"

	strings:

	
 		 $s1= "28C4C820-401A-101B-A3C9-08002B2F49FB" fullword wide
		 $s2= "35408482665400332571209654820175389" fullword wide
		 $s3= "500C56495341454C454354524F4E9F120744454249544F20870101" fullword wide
		 $s4= "Content-Type: application/x-www-form-urlencoded" fullword wide
		 $s5= "F5F2018564153434F4E43454C4F532F4A4F414F20522044452046489F1F18" fullword wide
		 $s6= "F5F20194D415249414E4120444120434F5354412053414E544F532020" fullword wide
		 $s7= "HARDWAREDESCRIPTIONSystemCentralProcessor0" fullword wide
		 $s8= "http://schemas.microsoft.com/cdo/configuration/" fullword wide
		 $s9= "modSocketPlus.DestroyWinsockMessageWindow" fullword wide
		 $s10= "sCDE57A55-8B86-11D0-b3C6-00A0C90AEA82" fullword wide
		 $s11= "SOFTWAREMicrosoftWindowsCurrentVersionPoliciesSystem" fullword wide
		 $s12= "SOFTWAREMicrosoftWindows NTCurrentVersion" fullword wide
		 $s13= "szObject$szReferencedColumn$szReferencedObject" fullword wide
		 $a1= "500C56495341454C454354524F4E9F120744454249544F20870101" fullword ascii
		 $a2= "F5F2018564153434F4E43454C4F532F4A4F414F20522044452046489F1F18" fullword ascii
		 $a3= "F5F20194D415249414E4120444120434F5354412053414E544F532020" fullword ascii
		 $a4= "SOFTWAREMicrosoftWindowsCurrentVersionPoliciesSystem" fullword ascii

		 $hex1= {2461313d2022353030}
		 $hex2= {2461323d2022463546}
		 $hex3= {2461333d2022463546}
		 $hex4= {2461343d2022534f46}
		 $hex5= {247331303d20227343}
		 $hex6= {247331313d2022534f}
		 $hex7= {247331323d2022534f}
		 $hex8= {247331333d2022737a}
		 $hex9= {2473313d2022323843}
		 $hex10= {2473323d2022333534}
		 $hex11= {2473333d2022353030}
		 $hex12= {2473343d2022436f6e}
		 $hex13= {2473353d2022463546}
		 $hex14= {2473363d2022463546}
		 $hex15= {2473373d2022484152}
		 $hex16= {2473383d2022687474}
		 $hex17= {2473393d20226d6f64}

	condition:
		2 of them
}
