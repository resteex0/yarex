
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_MacOS_Tarmac 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_MacOS_Tarmac {
	meta: 
		 description= "vx_underground2_MacOS_Tarmac Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-10-23" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "00e75857e031a58369e50b7d14e546bb"
		 hash2= "07eb8a3741ae66901e8ac2b667b02b47"
		 hash3= "0c192b6f9e9b3dba3cf2f33469ed3d8b"
		 hash4= "0f46b4f093eae0f16d8d64475b7a59b3"
		 hash5= "17177efe5927eda022ee4077e4dd5497"
		 hash6= "1ba18e42120ea0f0ae887cb886a16eda"
		 hash7= "1d067b14f71a4ab94dbb01e4753b0b15"
		 hash8= "1de632823425fa538ba3bb3254f8134b"
		 hash9= "1df5ce34b22d3fb3f83a31acc8c77f7f"
		 hash10= "1e96d0d0b94d9d4ece9285df1cce320a"
		 hash11= "20f576fb79711e8be38bf82c1561be45"
		 hash12= "210d915495f18c6bb6063453abee5627"
		 hash13= "22e8ea5d7f4e36cb0bff5cf1f98d50bc"
		 hash14= "22ee6478df8a77d46424f9625e8a14e2"
		 hash15= "2bc4d8c881b2238dfc95479c5fcf208f"
		 hash16= "2d1b014998bd05f5768e4ecd7bcdd7c8"
		 hash17= "31f200bbc1eb6d30a14f766e51011b55"
		 hash18= "3357563e905c574e558d55757f014c99"
		 hash19= "3765ecc9f3bb3411c0c61ceefdc904e5"
		 hash20= "3b44a6b6f6222327f5163fe8cd3b775d"
		 hash21= "42e537a018288d9675eb4b53c0fe83de"
		 hash22= "539d5cda4f5743ef9bb56705bf36964e"
		 hash23= "553b682627200a8082721f04cb977c90"
		 hash24= "597e564df56a75fc838cccea84bba18d"
		 hash25= "67f967607c45499b4eba50642b619d89"
		 hash26= "745c25079b1f32f310af56e1f336ed19"
		 hash27= "7a0bf6ad93ebb5b35932c2481d094400"
		 hash28= "8c128f63d375674ebf332ba70765b32e"
		 hash29= "8e9da7a0f68bb7d512ad14a734fb81c6"
		 hash30= "95af7872e15b0cbcaa9830ed102cb74e"
		 hash31= "a572cd7e74d19e509168cc3a75f9b230"
		 hash32= "aa8e5654bab3c9a23543a3ed6adeb5c2"
		 hash33= "b1f95c2900ed662aec76d1c2ddbd98e6"
		 hash34= "b3fed0423f74b231ea40c2507f696e0e"
		 hash35= "b4782d9af7c4d5c7928d0b5ab5e3b42e"
		 hash36= "b4b00457396f39ef62e913abbed8ffd9"
		 hash37= "b4fc86a797e89b1c45b79810c5f31319"
		 hash38= "bb0d19146efea82d136b181a4ef6784e"
		 hash39= "bea00943b291fc85ee29c67ae8bb9c8c"
		 hash40= "d0ec9e6a7f56845430ea8f698a119895"
		 hash41= "d5a69e7dabae7e34e9be50ea66e1d5ec"
		 hash42= "d74c4d631da8f56f2efdb0d05f4a8f91"
		 hash43= "d7ecb39181351b818617e9cb94bdcb70"
		 hash44= "d7fb51d4c75c08768e8c525edbfdc694"
		 hash45= "da7e495d307723cc6c3c466966d84f5d"
		 hash46= "defe65537370d096b184073747909aa8"
		 hash47= "dfd6361578dacffbeb55e1d0eb28aa82"
		 hash48= "e46066c89e66dde11e9fce3a2b79e0f6"
		 hash49= "e4e76307b6f88f4a8637c6fcc4c11ed9"
		 hash50= "f24db38bc7852005a76f490572c89a3c"
		 hash51= "f389da00a43cd1a49f92e74ca351e309"
		 hash52= "f4f69bd6955a20409f95c348f45cfd91"

	strings:

	
 		 $a1= "Player_136.app/Contents/_CodeSignature/CodeRequirements-1UT " fullword ascii
		 $a2= "Player_205.app/Contents/_CodeSignature/CodeRequirements-1UT " fullword ascii
		 $a3= "Player_240.app/Contents/_CodeSignature/CodeRequirements-1UT " fullword ascii
		 $a4= "Player_337.app/Contents/_CodeSignature/CodeRequirements-1UT " fullword ascii
		 $a5= "Player_373.app/Contents/_CodeSignature/CodeRequirements-1UT " fullword ascii
		 $a6= "Player_462.app/Contents/_CodeSignature/CodeRequirements-1UT " fullword ascii
		 $a7= "Player_517.app/Contents/_CodeSignature/CodeRequirements-1UT " fullword ascii
		 $a8= "Player_553.app/Contents/_CodeSignature/CodeRequirements-1UT " fullword ascii
		 $a9= "Player_576.app/Contents/_CodeSignature/CodeRequirements-1UT " fullword ascii
		 $a10= "Player_607.app/Contents/_CodeSignature/CodeRequirements-1UT " fullword ascii
		 $a11= "Player_694.app/Contents/_CodeSignature/CodeRequirements-1UT " fullword ascii
		 $a12= "Player_703.app/Contents/_CodeSignature/CodeRequirements-1UT " fullword ascii
		 $a13= "Player_719.app/Contents/_CodeSignature/CodeRequirements-1UT " fullword ascii
		 $a14= "Player_719.app/Contents/MacOS/t.02jr4zgKQpwYiXIHvggcIImFvyUT" fullword ascii
		 $a15= "Player_719.app/Contents/MacOS/t.02jr4zgKQpwYiXIHvggcIImFvyUT " fullword ascii
		 $a16= "Player_719.app/Contents/MacOS/t.02jr4zgKQpwYiXIHvggcIImFvyUX" fullword ascii
		 $a17= "Player_778.app/Contents/_CodeSignature/CodeRequirements-1UT " fullword ascii
		 $a18= "Player_793.app/Contents/_CodeSignature/CodeRequirements-1UT " fullword ascii
		 $a19= "Player_799.app/Contents/_CodeSignature/CodeRequirements-1UT " fullword ascii
		 $a20= "Player_858.app/Contents/_CodeSignature/CodeRequirements-1UT " fullword ascii
		 $a21= "Player_917.app/Contents/_CodeSignature/CodeRequirements-1UT " fullword ascii
		 $a22= "Player_942.app/Contents/_CodeSignature/CodeRequirements-1UT " fullword ascii
		 $a23= "Player_955.app/Contents/_CodeSignature/CodeRequirements-1UT " fullword ascii
		 $a24= "Player_967.app/Contents/_CodeSignature/CodeRequirements-1UT " fullword ascii

		 $hex1= {246131303d2022506c}
		 $hex2= {246131313d2022506c}
		 $hex3= {246131323d2022506c}
		 $hex4= {246131333d2022506c}
		 $hex5= {246131343d2022506c}
		 $hex6= {246131353d2022506c}
		 $hex7= {246131363d2022506c}
		 $hex8= {246131373d2022506c}
		 $hex9= {246131383d2022506c}
		 $hex10= {246131393d2022506c}
		 $hex11= {2461313d2022506c61}
		 $hex12= {246132303d2022506c}
		 $hex13= {246132313d2022506c}
		 $hex14= {246132323d2022506c}
		 $hex15= {246132333d2022506c}
		 $hex16= {246132343d2022506c}
		 $hex17= {2461323d2022506c61}
		 $hex18= {2461333d2022506c61}
		 $hex19= {2461343d2022506c61}
		 $hex20= {2461353d2022506c61}
		 $hex21= {2461363d2022506c61}
		 $hex22= {2461373d2022506c61}
		 $hex23= {2461383d2022506c61}
		 $hex24= {2461393d2022506c61}

	condition:
		16 of them
}
