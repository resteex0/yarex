
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Virlock 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Virlock {
	meta: 
		 description= "vx_underground2_Virlock Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-17-50" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "009580224a928379b801eff9062b3fd5"
		 hash2= "00a14cec7de23fe480857b99f29f9eea"
		 hash3= "00a7dc0a25d07488331722da85373c7d"
		 hash4= "00a8973e803b594632ea269cb8dc881b"
		 hash5= "00c29d85fbcaada7fb9b9cf7b4d247b9"
		 hash6= "00e38784d429edc4e7f4f5a003c312c9"
		 hash7= "00f087f1ae956275df66ded4c789544b"
		 hash8= "013d780e39cd307e57e55275b81ed84b"
		 hash9= "018b27c6938df10bc564a9d98c8c06ea"
		 hash10= "01a943efb0064a36dba153bb03acd621"
		 hash11= "01f45c7e9af544658502abe2e8c1415f"
		 hash12= "0236520442abd53455f35a5a6428d08d"
		 hash13= "0257cb0341bd070eaba1fb444db2be39"
		 hash14= "04d371bdaad1482c1615e46cc7ea124b"
		 hash15= "05ea68ff14deba72d9147fc1b478f2aa"
		 hash16= "06544e7f43e92f905d730fd458316174"
		 hash17= "067129765e2ff7af090bf3c156619a84"
		 hash18= "0699fafdcf04b4e00447f8f6216fc10a"
		 hash19= "069d09cdb72b5c8bbc66d7599b0493db"
		 hash20= "06b89406e4cd1cdc29c6ead937a16c65"
		 hash21= "06d96026e54fa6aec04f3bf865f6d141"
		 hash22= "071e06bf339eec25611356c21e1a8a7b"
		 hash23= "07355a3f7a2871f9f626850dc67308d8"
		 hash24= "0738b3c43350ef777d3ff7a5afe44548"
		 hash25= "080d919b88d1ab0df3167aeebe06137f"
		 hash26= "25729d41ac679ebff7a23e734195d718"
		 hash27= "26ad97f24c774aa5f87bd4f49a0c1763"
		 hash28= "344e1e2658fcbe58b04cf00003ffbf75"
		 hash29= "45dafc56073bbaca1a7563bdfe4c09af"
		 hash30= "4e85aeeefd6487dfa1a295e3c6733a55"
		 hash31= "55272c79c0cd6f901a0b9cbf6349aa02"
		 hash32= "5b3b9b5b70744e2a5b2e9bb04bab570e"
		 hash33= "5b651da15429a8d65660690bae6d9fae"
		 hash34= "5c7d1533466f2e0137bced5725f9b18e"
		 hash35= "608237f1d24c9fa4906bed67e98635bf"
		 hash36= "700a992ea73f07810c7508b129279239"
		 hash37= "7c62a41eb68b72d1d47589f6bb32f9d9"
		 hash38= "86de194b511005baf2f280cc141f6248"
		 hash39= "92a359ad527a3a153166f6bd05254b16"
		 hash40= "97d4e4f0279f872b4f5600b650be6270"
		 hash41= "afeea6cf68bb9b333ff3f21ce1b85d1d"
		 hash42= "bf864ab71b16c96a93c9e3174de5044e"
		 hash43= "bf90d6017e3da354cf5cf9f982b220e2"
		 hash44= "c04afc914bfbb6ac6c2e76a39f44e082"
		 hash45= "c45aa4fe6ad3766739946334b912fae1"
		 hash46= "c47a3c4e244cff0287dce0177af59fb9"
		 hash47= "c4afceb42f27af70a164e5cabe8ec900"
		 hash48= "c4c904761b29da4ca611ff11a9caa6fd"
		 hash49= "c612c0238e2990d37d95828f5ca619cf"
		 hash50= "c6eb0a2fc104ac7ce92bf780b1ef451d"
		 hash51= "c73badbb8f85acab6526196d5d28ee01"
		 hash52= "c777acae58dbc60beefbcbfac7c1475b"
		 hash53= "c8c3c0fe1fecb27551ca386470632687"
		 hash54= "d1a9b7fb122a33bb013a90152a84b338"
		 hash55= "d1fcc6c96f09ef6eb37d59d207bf90d2"
		 hash56= "d21f14567757039a3352975cbec7b922"
		 hash57= "d22216da83938ac6c8b9b16b7ba2240d"
		 hash58= "d22369d6f6376be8f2e69901cfa3d715"
		 hash59= "d278ceb9dfc4e0971076fa07b32874db"
		 hash60= "d2bb472b743813a6a88d92ab62ae99b2"
		 hash61= "d30fa6012105d72db2a7ff00ec103fa8"
		 hash62= "d31088d97d256c25593d5856140ef475"
		 hash63= "d351e112d2319db402c2a2b50f7d68e7"
		 hash64= "d3b172020985ea1058a707786f729d71"
		 hash65= "d3ecf70c7d10ec4a5092fbd0d25b3f89"
		 hash66= "e286224831e418bc9725b6b2870cac66"
		 hash67= "e39f34ab47af0d9734d47afedee5db51"

	strings:

	
 		 $a1= "-KSf+KSf+KSf+KSf+KSf+KSf+KSf+KSf+KSf+KSf+KSf+KSf+KSf+KSf+KVf+" fullword ascii
		 $a2= "O.=DL.=DL.=DL.=DL.=DL.=DL.=DL.=DL.=DL.=DL.=DL.=DL.=DL.=DL.=DL." fullword ascii
		 $a3= "vb.Aeb.Aeb.Aeb.Aeb.Aeb.Aeb.Aeb.Aeb.Aeb.Aeb.Aeb.Aeb.Aeb.Aeb.Aeb " fullword ascii
		 $a4= "V'SsR'SsR'SsR'SsR'SsR'SsR'SsR'SsR'SsR'SsR'SsR'SsR'SsR'SsR'SsR" fullword ascii
		 $a5= "wrGvvvwr[vvvwr_vvvwrSvvvwrWvvvwrkvvvwrovvvwrcvvvwrgvvvwr{vvvwr" fullword ascii
		 $a6= "zFw^zFw^zFw^zFw^zFw^zFw^zFw^zFw^zFw^zFw^zFw^zFw^zFw^zFw^zFw^zF" fullword ascii
		 $a7= "ZMTdW@TdW@TdW@TdW@TdW@TdW@TdW@TdW@TdW@TdW@TdW@TdW@TdW@TdW@TdW@" fullword ascii

		 $hex1= {2461313d20222d4b53}
		 $hex2= {2461323d20224f2e3d}
		 $hex3= {2461333d202276622e}
		 $hex4= {2461343d2022562753}
		 $hex5= {2461353d2022777247}
		 $hex6= {2461363d20227a4677}
		 $hex7= {2461373d20225a4d54}

	condition:
		4 of them
}
