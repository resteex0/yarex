
/*
   YARA Rule Set
   Author: resteex
   Identifier: Android_Xavier 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Android_Xavier {
	meta: 
		 description= "Android_Xavier Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-12_23-54-00" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0056b98db48192ad6b8d02a5c40e17a8"
		 hash2= "0168efe68282cba4272487deffad36ed"
		 hash3= "022a8a7a6fb97551ec15d085362af81e"
		 hash4= "03dcb41624843f5fc745df48b35a3e87"
		 hash5= "045dbcc1adf85e41052a9a6a0102f1f2"
		 hash6= "06d61baa85a45e71d64fa7c6b4e41222"
		 hash7= "07024a7ec2787f3d71696b0bdb9c99ca"
		 hash8= "07310e944e04048339112ea5198e5fac"
		 hash9= "07b82733026e8f8442b6768490981843"
		 hash10= "089c70e1471067ea38e3aff23fa94ecc"
		 hash11= "0982b9a5a3bbac61a605de03db7e8585"
		 hash12= "0bb1168cbe2cc2410cb90c3cf898f6e6"
		 hash13= "0c81847fb69ecaa05715d6a261371b69"
		 hash14= "0c85ede07d25d2ee0b0cfc1544c72d66"
		 hash15= "0e05c03bc30dd173c700a8eae3e3eed1"
		 hash16= "0e8ca291ad96567261885a88dff03d2b"
		 hash17= "0ef21db5524cbd71efb1056cd3657b4c"
		 hash18= "0fcfe4104741f0999ab2fa16b0d88615"
		 hash19= "12168b5c97ca7977f0a0fd998b71a269"
		 hash20= "12587427409a62d9a47bd56e3f0cb52d"
		 hash21= "157e68566fb9640cded9b9af1156d9ac"
		 hash22= "161c50eb4ea6b040d458a2775554ccca"
		 hash23= "174394da063b2668c6f16cbe82ebdf3a"
		 hash24= "17ec16b65c92a9285011cbec35f41f72"
		 hash25= "18156f53e02eae5ccf62831f364f6d27"
		 hash26= "19158ec7a9c9ceb1102810a704bcd09f"
		 hash27= "1b7387492780acbb5e69bd6c316270e5"
		 hash28= "1bf6ad3cc71c7599d35bd178748e77dc"
		 hash29= "1cc53edba68f13f4a3f56f785d4e77d4"
		 hash30= "1cedee8823737fc07761b22426d3591a"
		 hash31= "2199a31f724ee5b5153e00f12fd3826e"
		 hash32= "21bb441f5b79482790b3bdaaff4a790a"
		 hash33= "22c36935e5c627efad239bf78a4ade09"
		 hash34= "22fdeb4b41d9aa75f8f442fa76c5f3f9"
		 hash35= "256728bca655314c5a503ad70e2fce0f"
		 hash36= "2582ff3727a84a04992233edcaede8a9"
		 hash37= "26a6e08e07145d27cf59e2fa0bc38f59"
		 hash38= "273e4c67ae8e95fac5ef59bf7bc70ff5"
		 hash39= "28293a1a3891f8ee6d06e6e2d0dd8131"
		 hash40= "28606a24030f73ac7be72ca7930b19d8"
		 hash41= "2a5830e4c5a96b3b7bf3a8a721090cfa"
		 hash42= "2b368b1a886aa0b26208e2de199e0fcb"
		 hash43= "2ba9bfb62f6080da4759aae20c2b8ccb"
		 hash44= "2c4ac207f16b0de23d5c204d56ad73f8"
		 hash45= "2ca07f364626231d1a244c9aacdd8f95"
		 hash46= "2d78f59afac77a4f2aa98f2b68a956b5"
		 hash47= "2da2576ef62b5431b3c110a0f9bc0275"
		 hash48= "2e2ddb0962a6b553747de531b95f5a6f"
		 hash49= "2e309aab19e51dd6f57cf203e0b178ed"
		 hash50= "3113b00b9674ebaff48857a7066b13c7"
		 hash51= "3136b62eae745a1203042f32189f53e4"
		 hash52= "318b78d0e551f7954b46f93b8c2fc14e"
		 hash53= "31b1f23dccacd526ed601fb71c98ba6c"
		 hash54= "329e2abd1da4a69c7c21fb41531f463c"
		 hash55= "333f821c619731e9135ddab6b559d40f"
		 hash56= "337cc6824e468d94ac2522e6ea7472c7"
		 hash57= "34a8907e9cc6d1977c72294f1ebd63e0"
		 hash58= "36ee3f3341bd274015fb6b05d6600c8f"
		 hash59= "37e3f2801465e230c3273f4f89176e05"
		 hash60= "37e655bd78d1f6e41a0b183858bd38d7"
		 hash61= "39a0129a511dd50fd6ce3ffbcfc1bb2e"
		 hash62= "3ae6d870f4ac6e01873783c4c6b0d192"
		 hash63= "3b4a843dee9cdfb15f1e2ab99b3ee1b6"
		 hash64= "3c6ce3516414d694eaac6c10a7332798"
		 hash65= "3d89f2f34e6246874c0e8a5035be6e62"
		 hash66= "3dfc2fef8c47e2a6b17c1bb3f2a94b24"
		 hash67= "3e637367ddea13369afe919b757ebeaf"
		 hash68= "413ec1e0475d923dfd0979a9781b074c"
		 hash69= "41c133483977115763aea034bdf0e7bd"
		 hash70= "42e8dfe8d75ae32d258566de18762820"
		 hash71= "43660ce55b6aee50b51a5f2b7d9875b3"
		 hash72= "439e54f11f224f7869b456c7762adde3"
		 hash73= "43dbaed29bacbd8003b867d874eb9f13"
		 hash74= "4456f41a3c491871ec89f5e8c2c012ad"
		 hash75= "46a539b81f249eb1b3dd25cc4c4c0477"
		 hash76= "483f7180a875bffb07f03a2ae6531952"
		 hash77= "4872291d37c8595836885db0754c5f73"
		 hash78= "497fef03def0f0dc7df186f00e565511"
		 hash79= "4bcdc77f11d490aaa9a3d242c2b22c88"
		 hash80= "4d1cfc08be83763aecdf4994cac202dc"
		 hash81= "4d3515970509b90f614321adbad35d39"
		 hash82= "4d4abaa4b4c55f8049bbc9a1288cbfca"
		 hash83= "4e8d748a3eff690e77632a9e780a988f"
		 hash84= "4f38afad085f0134d02f0704f2d383e4"
		 hash85= "507cf0fc962503241b681bc9ec6754ed"
		 hash86= "509dba9dce0037aa43efe8bc5b2cade4"
		 hash87= "512ded7e25a9b0b4c3928119bad1b3ad"
		 hash88= "513e29e0728a05792426fc3949793a7e"
		 hash89= "5228e8672aec8d180361f966d53831ed"
		 hash90= "539cf1bbafdd0269a3a28b24be8b3615"
		 hash91= "5472e457db443ad47e6e26fccc9c865e"
		 hash92= "55aa1f274aad2e5a8239954caefcba83"
		 hash93= "5814839c33429a70ea444a3b42754d1b"
		 hash94= "586c60d25a690ab02c05899ac4796411"
		 hash95= "590b7d914f5440b6a868d2e7ed82f62b"
		 hash96= "597f4047002e18a01f01deb4549e8a9a"
		 hash97= "5a66ab313763ce6b01419292665643be"
		 hash98= "5a8a3d0c78ed0c711417300983556079"
		 hash99= "5aeeda06cbc4fb897dac08f17163184e"
		 hash100= "5d8f6c6fd45a3ced9363276e8dfbdc5b"
		 hash101= "60c12bea6a38bc4b06bd4de6dca24418"
		 hash102= "614070f4ec9af6734a4b2c96a9b99990"
		 hash103= "62a9a4e05f9f095e0c8bebb461498256"
		 hash104= "62d9eb83a8a8e2f3094d465db511ae64"
		 hash105= "63f1357dd3e0d2eded23cd2e0780ff1a"
		 hash106= "641041732be3f14a1251982c940d3b36"
		 hash107= "650e406aa432c18790ffce301e76c2d1"
		 hash108= "6602ab2c684329ff5c614cddb7baf641"
		 hash109= "683691139d8419ca88b2e06e6e043862"
		 hash110= "69e9ce5ec555fb00fb0dd7e0e655aa06"
		 hash111= "6a45667923670c84257822c6d1781e4e"
		 hash112= "6a9c4eeebfb66482345547265fbed6b3"
		 hash113= "6ae80109361c422a2860302002424d5c"
		 hash114= "6b3b7055549e07a475ac4ed2c87943f0"
		 hash115= "6b70b960731442ed5c4ef58f77fc6171"
		 hash116= "6bf276353d7e627bd80ec219eec05b7d"
		 hash117= "6c44036c7f9a54148323f5235af2cc1c"
		 hash118= "6c8690e3377e4288ca372b5bbb76e507"
		 hash119= "6ce71ab5c3ed6789f8aac80d1c676e03"
		 hash120= "6dcd49004dcef1b20d5e3118e6c8ebed"
		 hash121= "6e14e5c8764c7669339d1ca183f68745"
		 hash122= "6ed0dd1f372ea946fb15f29948c1ee7f"
		 hash123= "6f1d04d795e8ef3da868d954e65faf78"
		 hash124= "6fe112d11f9b0069b33a3c9bd98403ab"
		 hash125= "6ff8586bcf82b028594d15d8ddec2704"
		 hash126= "71ce2c93828c04f97ea5ffbca839d6e0"
		 hash127= "7478fb310feae2256e042dbc7d4670af"
		 hash128= "7646228c59cdb61a9912c8f430f25128"
		 hash129= "764a66a7df54e4b02b5ba3200b4e7f57"
		 hash130= "7740fd44e6f71f2679662200332dc0f2"
		 hash131= "785561973d6f0c39e4bd2849893755c1"
		 hash132= "797ea362210165c3d50a42b895688dae"
		 hash133= "798788316c9c01a37a6d4e558b925aed"
		 hash134= "7a76192af82bfe7f2385d08263b7f7ce"
		 hash135= "7bf8efc126f887eb4ff087ca449ff27d"
		 hash136= "7dcf9616fbdf109f7800523a40cd9398"
		 hash137= "806349aa982cf4cd3dcba32f2208022c"
		 hash138= "80f923fe5ec3d79e4e44fcf711b6126d"
		 hash139= "825c3159cb36271eec23af04842fa522"
		 hash140= "82ecf66a7b0d1d10e366dad510af7860"
		 hash141= "832acc692dcfcdd17b28203f458c6f99"
		 hash142= "83b58a0e9e03429cfe50cb4c0d26ac1a"
		 hash143= "87e391451be61cb479e5a4a9e1b5732f"
		 hash144= "8838cb01731486a0c18392b896dacc5f"
		 hash145= "886f5b269378aef355a91db33c31d4f2"
		 hash146= "89ffc18beb860eabe8c79deabefd5e8e"
		 hash147= "8a72124709dd0cd555f01effcbb42078"
		 hash148= "901f0c89f5f4e0523653de38a7fdf97b"
		 hash149= "90beb7806a09d0792c9aaba9c3ca82fc"
		 hash150= "90f63ca77b69773e003c8c2c6002d291"
		 hash151= "911624c70093c5a1b5d5f86dfff511d6"
		 hash152= "926275010f2f376012cc2841f21dd54d"
		 hash153= "937c60553d99f021ffad7a51a68788f1"
		 hash154= "94ebdd0b19bb059743710d6f26bf24ae"
		 hash155= "95f79db9b6acbbca688fa2138dd33fe7"
		 hash156= "97daf1df51a2869b2c14bbc756164046"
		 hash157= "983e15e32563dc0634a69091837efeb9"
		 hash158= "9885997ba646f6d093a2bd6d8e0ad916"
		 hash159= "98dc726daf824d96c5a71b4cad08136d"
		 hash160= "9943b397f033ea0e4e9c113f064fe392"
		 hash161= "99e2b23e9469967390c28913806f3076"
		 hash162= "9a9660ac13a2b335f50d5e601585e90d"
		 hash163= "9ade90b417ee16e8251eaaeb52bd8406"
		 hash164= "9b8a64ddc5fed751524113f628dcb19b"
		 hash165= "9baa6c4bd5d46740f2131d2d14c8c460"
		 hash166= "9db5ac5f4cee7f357732fa04b6160d9e"
		 hash167= "9e31fb55ae8c66aed1d4d5692f27faad"
		 hash168= "9e96867a0a5bce0092e8c3a4dec997a9"
		 hash169= "a45e29a4643cbcf47dd2e55b49d4d5b8"
		 hash170= "a5e3a864d6af4bf7ac47407f743ca9df"
		 hash171= "a7eb45c7d9e9178de7e7ea699845cd00"
		 hash172= "a8ca4a9b7c03fdb33101c55de4b22a4c"
		 hash173= "aa614fa9eb855ad6e5068c88093e44ca"
		 hash174= "aad53c1a57f218da2ea473a791e164c3"
		 hash175= "abc49f756fbeeec206486a4fffc7f4aa"
		 hash176= "acfe9f7647cf2249b2aeb5714f95a2e6"
		 hash177= "ad3e147c3498d6cdf6e68454af109949"
		 hash178= "afd0254113329f32fa24e8940d648615"
		 hash179= "b1db154540bc86223da5af593c66ec70"
		 hash180= "b296fd71bf0badbcfa91c4510fd93e4b"
		 hash181= "b32c60f1df82e9fd01b6425d2968849c"
		 hash182= "b5824e2643f1d0df4d5705adec0aedc2"
		 hash183= "b5caeaa00b5cbce06b5bcc90f2144ac6"
		 hash184= "b64d2e1151d93c9b242ba82a0077b8a7"
		 hash185= "b77ac8dd0e135ca889cd15820d5dbbd2"
		 hash186= "b7d15764983606b465d17492156cd210"
		 hash187= "b961b5d0bef7b056cde0460b2f02a4cb"
		 hash188= "ba97801d14b8a9c9efbd27cbcfe2e5ec"
		 hash189= "bb713e9e6fd59bf77f9a819e26adec1d"
		 hash190= "bb9bf1cdc2ddbc667193a50855f9d682"
		 hash191= "bbb3b09a9ec9807c84d4953fbd6236a1"
		 hash192= "bcdda3744f914a72a6e2f79d978ea2ab"
		 hash193= "be50f34a2405cce7e062156ef7180bd1"
		 hash194= "bea3d8d1e684f603f602ecc66c24dced"
		 hash195= "bf283da7507eb44900c3a6a20be86c67"
		 hash196= "bf4466fb4ced8c7929adc4b553be0af0"
		 hash197= "bfc805c8bef22062b5a9aedcb81b2c0a"
		 hash198= "c07ec1b8b23f1e414961ddd593a1250b"
		 hash199= "c24219859caa60dbe66e9acebce012d6"
		 hash200= "c2e216e4ff4a89056359ea4003369638"
		 hash201= "c30de8503da572544b9a0daacebe5ba2"
		 hash202= "c49078ec868fdce1a48ee7710838eee0"
		 hash203= "c79db3190271a5df837c558a18069d06"
		 hash204= "c7ef5bfc8ca0b1712ccc2f2e5b0dbbd2"
		 hash205= "cae0b7ea144830e5c89423e1da70f848"
		 hash206= "cc02f4d088989e26b2931096b61d084b"
		 hash207= "cc0aae4633a8bde70a89be21fdee2947"
		 hash208= "ccbb6793d2e0a6f4081eee896d28ec06"
		 hash209= "d102cc056d090d81344604758361f1ea"
		 hash210= "d13c219363e3362703efb97d2e608f8b"
		 hash211= "d21a1fc6dc3bedddfcdc760de4ca6f7e"
		 hash212= "d27fefffe3ac2d2d0b65cfaa2c5ea5a1"
		 hash213= "d32ddb1d79943f6d67ff3d0f10286458"
		 hash214= "d3ccd763ce5e26b19e33ccce2c5661ad"
		 hash215= "d3f84582f3afd9521cca0475da77c7f9"
		 hash216= "d42bf9302eb585323946affabdebed74"
		 hash217= "d527f3466b3b9fa0f37c638046f05b51"
		 hash218= "d6c825739e80baee60fb2192e213b258"
		 hash219= "d6f6ba2fac69533d43432684ae61a7d5"
		 hash220= "d76b72528c754f4a372d6462d84618f6"
		 hash221= "d77bd14041c7cb634a0d0c592e10d9a4"
		 hash222= "d7ac949a1e475716502089dfe24c146d"
		 hash223= "d7ca6481efcb0f310032aff7047c64ee"
		 hash224= "d7ddc957ef6ec3fc155bd6689b3ccdff"
		 hash225= "d86a79fdf799dd09370eeae150d15e32"
		 hash226= "d9602f830497308306ac7499acf30573"
		 hash227= "dcb2163c862a8592034a0c02d08f453a"
		 hash228= "ddb962d8a6468e7f87c4594ea8a4b1ed"
		 hash229= "ddcc508195cf43562cefd9f61c3b3fc7"
		 hash230= "dde11f319bb9a7394bd3c80706dd8088"
		 hash231= "dec3a47217591a2f1ec03c252a3b5355"
		 hash232= "df0223ca501823514a3d7a0025c1a0da"
		 hash233= "df21f88097253d94c2c73089089dff30"
		 hash234= "df4fe4e219a0352d0d1cb025ac9693f5"
		 hash235= "e1d888f2d63f34c49a19eb984dbba8cc"
		 hash236= "e1dc5775fe853e58c2c8fbf340c8815b"
		 hash237= "e3bb71b0206e5eb98ae2d625ae8d3f21"
		 hash238= "e6b6810e143bc10a61b51fab25609705"
		 hash239= "e7fa43a392c0cbaf7b01e8e46ad8ac08"
		 hash240= "e82f42434c7a1dd12f8581049bf2156f"
		 hash241= "e847643bd78bec251c0eaf1be62c31f6"
		 hash242= "eb22981a609ff8c1a1ad4f7b4ef877c9"
		 hash243= "eb28d86ad801b4359d839ad7172f982c"
		 hash244= "eccca1f00306a134dc3ea37ccf145491"
		 hash245= "ed3567b743e66be9625fdc61a1dd0fbe"
		 hash246= "edd834c5b9ce51452ecca34555b16403"
		 hash247= "ee11b280d6f34bf20d618fd963d4ab63"
		 hash248= "ee23d065174f08fde6183160df248d22"
		 hash249= "ef5e22006049089986342a0b88983689"
		 hash250= "eff17e9786d886e6214be93bab1dc5ab"
		 hash251= "f13324258f4cca734da16d4bbbb6a11b"
		 hash252= "f13c448d69907afcc6261c4638e19496"
		 hash253= "f15fd4a394673d235f71d8cdc8ec3536"
		 hash254= "f1c08845f327d012224917d7e88e0da9"
		 hash255= "f23857b5896ae2f1e81c0a87c4b1890e"
		 hash256= "f269a853d881e4d57410622186331e39"
		 hash257= "f3e6f1be7238366713e14a184aa85fd1"
		 hash258= "f4781a24cc63d881ede130b3c054ee0a"
		 hash259= "f51a295fd06afb86a7d8e6e28d211fde"
		 hash260= "f5ddaccd7d43eef9cbf954b031814fc6"
		 hash261= "f732c7477e1e66418e9fc056fccb09c3"
		 hash262= "f79e2097dd4a6faf923a7b61f15ba9e3"
		 hash263= "f7e59f21d472007013465623f546f38d"
		 hash264= "f7fc7bc59d81bba708ad84e2e0eb377a"
		 hash265= "fa053e1c543e7b4bc6a650320ce676e1"
		 hash266= "fb0063fd5ec1d0d25839c6747f24f24e"
		 hash267= "fbd6214537fe117c3d1a591b055b62a2"
		 hash268= "fbf6de85eb9149f8a08698ee1e3787b5"
		 hash269= "fc25681ff39b79732c253ad19add6aeb"
		 hash270= "fc73b96f5e5f05f051cfb24ef3fd3c1f"
		 hash271= "fea18651c8b44f30f437b7b2c2dbeaa1"
		 hash272= "ff1f85853ba10c9aff18d2306e94607f"

	strings:

	
 		 $s1= "! $$%$'%%&%%('**06:AGNRZZ`_]^YWSPKG@;5.&" fullword wide
		 $s2= "$$(,/04476::?>?CDEGINKOOPRQRQPQNNILGDA@>;852-,(%!" fullword wide
		 $s3= "$$&(-04;=?FEIMKJIJHD?@;:6651369==DKSX_iqvz" fullword wide
		 $s4= "$%(**)-*./+.,+-,+)+-,-,-..0-0/1./1++&#" fullword wide
		 $s5= "$%''*,,-//.-,,,),((**))**.0056668;;8865/*'$" fullword wide
		 $s6= "##%$&*++)/.0//14313232211222120H@@?>@?OQMNRTRPZfjkjdZirorosni_XZSWTPDFPMNKFD?897551.-/.*)'$##$$#!" fullword wide
		 $s7= "$%*-0155;8=;@@?@@A?A=A;>=8;846/.))%" fullword wide
		 $s8= "$&+01569@@DDJKLPRTXWXZY^[[[ZWWVQNKGE@:63.)% " fullword wide
		 $s9= "!$',&0,2/43666999;9@;?@?B>@@=?:?6933/-)*" fullword wide
		 $s10= "$*,026:>@CGJKNOUWYX]a``b_a^]]YUTONIBB961,&$" fullword wide
		 $s11= "$*.02:9=?CDDHGJKKKOOOQSTVVXZY[XXYVVQRNKHFA;:52/*%#" fullword wide
		 $s12= "$'+0469=BDHJMQUUZ^_bbdgefhfeca`][VTMKDB:80-& " fullword wide
		 $s13= "&$0*63@6HCNOT[b`lhioinikfjbb]_[[S]KXKQLLHDED?9=35-+#$" fullword wide
		 $s14= "$,07>BGLORWZ[_bbgglknorrtuuwxuvsqmje_ZPHA8-$" fullword wide
		 $s15= "$*09>AGJLQTV`dfiklmjkhga_YVQKHC?>?@BEFGGFHEFFEDBCABADAB?=:652-,($" fullword wide
		 $s16= "$0=AKPZ^dhemlkllikhccc^]]WYVWXWW^]bfjppx{}~|z{trg`YOF9/)!" fullword wide
		 $s17= "$'),10568;>ADCFIIMNNOQQQPOOMLJGFD>=850-&$" fullword wide
		 $s18= "##&$&*,+)/.1//14323332211222121H@@??@?ORLNRTQR[fikjdZirqrqspi^XZVYUODFPNOLHD>897362/-/.*)'$##%$#!" fullword wide
		 $s19= "##&$&*,+)/.1//14323332211222121H@@??@?OSMOSTRR[gjkld[isqrqtri_Y[XZUPDFPNOMHD?897562/-/.*)'$##%$#!" fullword wide
		 $s20= "$%),11569;>BBEHHINLOOQSRRROQMMLJGCA>852.)%" fullword wide
		 $s21= "#$()-/127:;=@BEGHJKMQQUUWY\\]__bbeefgiiijklnmmnlroqpqsqrrsrtutxxyzz~" fullword wide
		 $s22= "!$*,./1336330,+)(&(*-+,-+.03254488989674213..-/**#" fullword wide
		 $s23= "!$(136>AEHMPTZ^_bhikpqvuvx|w}zvwuuomie`[UOKC>9/,%" fullword wide
		 $s24= "$'-138;@AEHJNPUVZ[_`bcchfhhhddb`[WQMHD@950*# " fullword wide
		 $s25= "$#*+,1467=>?CEFJNLPTSXX[[^accfhellmrosquwtywy{|z~}~" fullword wide
		 $s26= "$'*.1489?@CDGKLQRQUXXXZ[Y[ZZWVSPKIE@>840.&!" fullword wide
		 $s27= "$(+-168:>@DFGMLQQUUXW[ZZYZYYUTSMMGE?>53.+%" fullword wide
		 $s28= "$+-18:@CGJNRUZZ`aegimoqqqtvsrppnkgd_URJG?93/'!" fullword wide
		 $s29= "$%&+,,-21678:=@BBCFFFEGDFDCBD?B;@36/.'%!" fullword wide
		 $s30= "$+,238;ABEIKPQUYZ__bcfdggfhedc]]YWPMHE>;6/,%" fullword wide
		 $s31= "$(,.238:=BAFGKLPQSVWYZ[ZZZXVUTOMHD@=63-,$ " fullword wide
		 $s32= "$*,238:?BFJKPRUXY^]`bcehfhhgeeb_^ZYSOJEA>51.%#" fullword wide
		 $s33= "!!$&**,//2579;==?CCEDGGJIIIGEFEEB@>;:76200-(*$&!" fullword wide
		 $s34= "$().27??BAAADHKNPQOOHJDFEJLRV[`bilortx{" fullword wide
		 $s35= "$+28?EKQV[aa]YRNGD@;:568;=DLV_jt~" fullword wide
		 $s36= "$)2;?DHJPOPPNOLHHECBA>>@=ACEHLPUX[^dgghihfba]WNLDB43,' " fullword wide
		 $s37= "$).36;>BIJLSTZ^cdghoporsrtssrqnljfaXTMHC;6/*&" fullword wide
		 $s38= "$&,/389AAGIMPSWZ]^abehilkmlmmjjiec_]WUMJC@85/+$" fullword wide
		 $s39= "$,3;EJQX_dlmqtvwwxuupnpjgicecb`__[UTQNKD?=62.& " fullword wide
		 $s40= "$+4BTfotvxxwtmec[XVVSSTPLLJLPSUYaedfeecQI@6-" fullword wide
		 $s41= "$+5:>FLNTX^`dfijloqpttvwzx{z|y~z|yusnjc]ULC;3)" fullword wide
		 $s42= "$-5;?GIQSX^`bcfihmkqrsvuzutqkj__TREA83)$ " fullword wide
		 $s43= "$#+./6::E?LDOKPOQRQOOOLNOHQFPINDNEKHDCE@D;?2>+5()&" fullword wide
		 $s44= "$-:@LTZcejkkmkifeb^YYTVUTTWVYaccggfghb`[XOF@3*" fullword wide
		 $s45= "!#&*)..011212179AGNQX[`_ffknsvzz}|}}~" fullword wide
		 $s46= "#(,-01247:==74/-()(,*.03:@GOQTTTPMKMMLNE@4/$!" fullword wide
		 $s47= "%'*0198;ACFJLQSUYY_`beffkknqqsxuzw|}}" fullword wide
		 $s48= "&'(+-.023499:;>=A@?ABA?@?=:8:61/,)(!" fullword wide
		 $s49= "!@0/2-3>98GAGIGIvb_PY^b^bnj^Z]T[WN,C>aWYWYOPY_" fullword wide
		 $s50= "!!%'&*,.02658;;>>ABDCBEDEBBE@A==96651-/*'(%! " fullword wide
		 $s51= "#%&(**()'(&%'*+.0288=?>CCBFGHHJLMKLIGC>70*!" fullword wide
		 $s52= "!%&(++032588:=?AEDHGKKPNQSUVVYYZ[^_`aaccdcefgdheiihhhihikjllkmqqrstyyz" fullword wide
		 $s53= "(+-038;?ADGJMPSSX[[]^`aa`baa_^ZZWRQIHD@840,&" fullword wide
		 $s54= "&)-039:?CFGKMTSV[[]^aabecedcbb]]YWRNJFA>82.)#" fullword wide
		 $s55= "*0489=940..()++12>>BEDA>>?AADGMQUY^dgg`^XTRQMPSX^]^[YWTXVY_diptstqopplhhkms|" fullword wide
		 $s56= "%%04;AGKPTY]abffkjmjjjigd`^[VSOHDA;40+&!" fullword wide
		 $s57= "!%).059:>CFILNSTXZ_`bbdhehegcca^ZXSOLFB>72/'!" fullword wide
		 $s58= "!%+05:=@DJLPRVVXYYYZZ[Y[ZZZZZYZZZXSSOPJFB>63-(#" fullword wide
		 $s59= "(05?GOVZ_ccfegfgiikkmnppormlgbSJ@5* " fullword wide
		 $s60= "+!+/&0'5*K>]PV_Qk>n*n+r9u;f-Y&O'=" fullword wide
		 $s61= "(06>FIRS_chiooprqqroklhdb]VPLGB?85.)$!" fullword wide
		 $s62= ")07;BFKQUWZ_`dgfilopquwwzz|}~~{yztomd^XME;1'" fullword wide
		 $s63= "#07@HPW_acdcc^ZUSPMKIHIIIJMNPQTUWXZ[[YXSQGB:/%" fullword wide
		 $s64= ")08EOY_eba][Z[]``dimpoolkhfhkprtxxusmihggdgc_XQLFE@CEGILJLID;949ACDEDFJNV]^b`^`[XOI@5,&%%& !!!" fullword wide
		 $s65= "#*08?GKPUWWYWVOMFB;71.*'%%&(,/5;@IPT^ehhjiec^YSJE;61)& " fullword wide
		 $s66= "(0-&(8KJ@79CSVQQU^c^WWdsqg_enux{~}}vx" fullword wide
		 $s67= "!(09ABIMPTTVVUTSQNMIJFDCEDDEGKMPUX^cflkmmklgc^YSKGB7/,%" fullword wide
		 $s68= "&'*''%()0:GPYZXXTSNGFEGLONMHD=;9:9464:==>?@CGJJFA94*" fullword wide
		 $s69= "##'')+++-.///1/.,/,/+*),+(*))&(%#!" fullword wide
		 $s70= "!#%),1047::>CAEHGJNLONQPPRQQONKIHE@A;740+)!" fullword wide
		 $s71= "'',1056:89:;;:;:88775444242532//.//++*'%#" fullword wide
		 $s72= "+'1089;ECLMVX_`ehimkskqmgm^eYYOSIHC>74.+'$#" fullword wide
		 $s73= "&+1132.-*,-/39?AGHJGJHJLKMPNOIE@8/'" fullword wide
		 $s74= "!#&(,/11657;=?BBCEGIHIJLGJIGGGBA@>974/,(% " fullword wide
		 $s75= "*,123/*(*,.-35;DEJMTWZZ]ZZYXUWZWZ[_hmpqmhmt" fullword wide
		 $s76= "'+.137;=@BDIMQRZWYXSUNLHC@:9310+*'#!" fullword wide
		 $s77= "#'*/157:?AEEJLMPSVVZYZ]]^[^\\XYWRPMJDC>:40+' " fullword wide
		 $s78= "!!'*-/1589:@AAEIIJMKNPPQPQPPMNKJFDB=:63.+%!" fullword wide
		 $s79= "+15@HMR[_dikpoqnqolkkjjfhcdbaa_][WVPPHEA=:1/+%" fullword wide
		 $s80= "#++.165;=?BFHILORTVVVZX[Z[YZXVURNLGCA;62/)%" fullword wide
		 $s81= "%*+16:>CDKKOQUSUVVXWXXWZZW\\]^^][Z[XURQNJDB;62,(#" fullword wide
		 $s82= "!'+16;@DKLPVOQZUSRMNHCA::12,**%*&,,33?>MNZ`kq{" fullword wide
		 $s83= "&'-/175>>BEEGDIJINKPLSSSPXUVQNQHMBD?;70.)'" fullword wide
		 $s84= "%+*176A>HGQMWW]`ggmmkqhrfmel`e`T^NPGCE8?370.(& " fullword wide
		 $s85= "(18@GOSX^addggcd^_ZVSMLJFHFGHLORVaelqv{" fullword wide
		 $s86= "#!*+19;@FLNRRYY]]]a`Z`]X]WYYRTNQOLMHLIFDH>C9?54)1 #" fullword wide
		 $s87= "&1>BJMPPQMIFFFGFGILSVWRI@942138CPYVTMIEA>7/* " fullword wide
		 $s88= "*1:CHQRY_a`e__`^]ZWVURPPOMOQQTY]_ejmpsxxzytpmg^[PJA:.)!" fullword wide
		 $s89= "!*1:?DKPUY]acdiimmnnprrtsvvxxyy{{wxvroif_YQG>6*" fullword wide
		 $s90= "'1?@ELDA:293471644I[RQVORTO[`\\YeS'(3$)+$*$" fullword wide
		 $s91= "!&1:@FQUbgmmquwwywwvspolfc^ZSPJE>84.($" fullword wide
		 $s92= "((!%,%20.:/825;=B?HI?YNZWQVBNZNRNJEKNB??aPP" fullword wide
		 $s93= "!#&&(),-/./2122/02.0.,-.*+.(+))$)##" fullword wide
		 $s94= "%&+-.224899;?=AADEGJJKPNPQRPQPONKKJHB@>=:53-.)$#" fullword wide
		 $s95= "22B;TNUVd_eblpjiwnunynunxslwnlonqlgv_x]nbi[]OUEF;54" fullword wide
		 $s96= "#%+22:=>EDHOOV]dgeqllviwiqihhg]cZ[YTVNRNILFI?G8=712)$%" fullword wide
		 $s97= "#)*247;=BEFJNPSXW]^cbfdgfgdfc``[YWRMHE>;3/+%" fullword wide
		 $s98= "%)+249;ABIJKQRTTXUXZY^]_^^__`ZaYUVTNPIIE?>79.*'" fullword wide
		 $s99= "!(.24:@EEKNTV[[`bfhkopptswuusurtnkkfcXVMGC:70*$" fullword wide
		 $s100= "#%&'+.24;?ELRX]befgiijijlkoonnjibXPHA=82.*'$" fullword wide
		 $s101= "%.-.24>IE@>AIQYbgjkhmpsunjgimlnlnqutsrs" fullword wide
		 $s102= "*/256554567;@DKQW^behhghcc`YXVTRQPOQNOMNMIHFB;941--,/37=DJNX_dfeeaWOG=1%" fullword wide
		 $s103= "#!&.+2579=@BJHQQXUWYXVXRUPNLKFEA@@7;530.+&#!" fullword wide
		 $s104= "!&)-/2589==ADFGJKMMQQRRTRTSRPMKLGGB@;931+(#" fullword wide
		 $s105= "!&-25:?DGKNTV[`fgklppsvuyxvxvvuqomjcb[VPKF?:1/%!" fullword wide
		 $s106= "%-25?@FLPNQORQMMFE@;;6625579AFRXajtz" fullword wide
		 $s107= "++*268;:D@>N?QBUAVIRMRQTNUTTSUOWJUMTKMHK>H:;5/-&" fullword wide
		 $s108= "%,27BDKQU[bahhlmkplkkhhedccb``_][XWRQKGB@:720*(#" fullword wide
		 $s109= "!'28=FMNQQPNLJHJHIKKMMNLJJFD>=72+# " fullword wide
		 $s110= "(-29=DLT_ffa]VVVY[^][XVURSSWUUQLC;.%" fullword wide
		 $s111= "(2:AKOX^cjmruv{z{xztrnic_[TRJIDBB??@ADDIJQQVY^beggiifc^YPH>1&" fullword wide
		 $s112= "#(),-325::@?CDHHKJMOONQRSNQNMIHHDA=:62.)&!" fullword wide
		 $s113= "#*/3468:==BEGIOORTUUWUVTSPNKKFGD@?:5.'" fullword wide
		 $s114= "&*.3598;::88640--*($&%&$&&'%))-,-..0-+)(%$#" fullword wide
		 $s115= "#%(,./369;>@BDFIHJMNPNRQPOQNLKJHDC@9910,'# " fullword wide
		 $s116= "!'*.36;?ADFFKIIFFE@@=9732./,((('%'$'('''&'%$!!" fullword wide
		 $s117= "&+-.377?>BEGIKLPSTVYXZY[[ZZXWVTPMKGC@:50-'$ " fullword wide
		 $s118= "+39ACKKNNPSOQRRRSSUVXXY[[^`b`deffhhjhighhbe_XULHC;5/(!" fullword wide
		 $s119= "#(39BJPY^cfhhfeb[XPKC@841/0.148>DJRX_fmprvwvrpjd]VOH>92-(#$!" fullword wide
		 $s120= "%+39=@KNSWY_addfhjljkhgheeefbaaa_ZZWVSQLIG@>:3..$" fullword wide
		 $s121= "#*3:CELNPOQONKLKILJONRQRSPPPJICA;91.+#" fullword wide
		 $s122= "'3>HRYahpsx||{~}{{|yyurqolkifegehljptu{~" fullword wide
		 $s123= "%(//423320//-,,+-/,-10558;=>BDGHKHMLJNLKKHDD@=630.'!" fullword wide
		 $s124= "&-45841)%$$&,37=@?@=8:8789;;:94300**'$" fullword wide
		 $s125= "#'.-459:>AAGGIJLNMORORRURZTSVRTNONGEA?:00-'#" fullword wide
		 $s126= "!(+.469:85225;?CA@?=:724/.),,1668;:955797451310+'$" fullword wide
		 $s127= "%-/47;ADHLMTVYabghlmnrrqrtsqrolkfa_YUNIE>72-$ " fullword wide
		 $s128= "! *,47:DDLPQVZ_^^cb`e]c^bY_Z[W[SUQSKSFOBL@K?C:>68-.&!!" fullword wide
		 $s129= "!(*./48;@FETI_Sdebhfjglelbi`_XZROLIEE>A7=-3('$" fullword wide
		 $s130= "(4ANU]_cccecbb`^^][]``cfiljkjb_UKA5'" fullword wide
		 $s131= "&.4:BGJQTXZ`_dehhiljllolnlmnlmlmmlihhc]XSIA8.%" fullword wide
		 $s132= "%-4:BGNQY`ggklonolhgbYTQMJHFCBFFDHKKOQSWY]`bfigkjkge_XTJA5+" fullword wide
		 $s133= "%.4>BKNTUWYWTRPOMNOOSVVZ[[YWTSOJC>6/(" fullword wide
		 $s134= "4C%3%C-35C5#-+-3%3.09798_QO9GIH?9>B?" fullword wide
		 $s135= "%.4?CKQV_bgkprrwwwzyuvsrokee`[UQKGB;60+%!" fullword wide
		 $s136= "'.4;CKTYbgmrx{y~|{{ztuqoijdfd`a`]^ZYSQOKD@=31*'" fullword wide
		 $s137= "&-4@DIRUXZ]\\ZYZVSSQNKJJKHMNQSX[aefmpqsttrrlg`ZVJG?8.*$" fullword wide
		 $s138= "%,4>DOSYbccfefedd__ZZXVVORPQRVYWafjlqzvzywvtnh`WQJA6/&!" fullword wide
		 $s139= "*4?ENVY_begihigffcd`a`]^[YXYWUXUUTSSSOONNKIGDA;73*'" fullword wide
		 $s140= "&.4=@IMQTZ]^`egijkmmolopqrqssuwutqplgf`URJE=5*$" fullword wide
		 $s141= "%)..548799787641/.,,,+)**)+)+.+,--,+-++&%$#" fullword wide
		 $s142= "&)55ABKNXUd_jgoovrwxwv{r}o{oqrkpcl`d`]VYQPIJAB6;1++" fullword wide
		 $s143= "!'-/57:BCFJLNMPQPRRPSTSUVUVYXYZYYTWUQPKJBB;;30+% " fullword wide
		 $s144= "#%,/57=?EIJPTVY]adgiklqoqrrvrrrpljgc^ZTOKD?93+'" fullword wide
		 $s145= "&(/5;BEHQSV][`_ffcheifgeeffdfc_aa``Y[YXUQMKJD@:8-- " fullword wide
		 $s146= "%)/5=@DHMPSXZ_afhikkgea[VNLD@=885465858898965510.,*)'%##! " fullword wide
		 $s147= "%5DR[djmnnmolkjhfeeedhjlttuxusld[OB5&" fullword wide
		 $s148= "&-5:EJPX_filtvttxuvsrqpllkjghecea``YYUSOIGA;64.'#" fullword wide
		 $s149= "#&&))+++*,+*+)*-./5:@GLS[`diimnlmihca[XPJD:0)" fullword wide
		 $s150= "%-5=HP[ahmuuxyvsohc]WOIE?::9:;@EKSZcjrw" fullword wide
		 $s151= "(5?HPUVX[Y[ZYYVXUVVWXZ^aab_XOG>4(" fullword wide
		 $s152= "/61CEOHR[X]]o_jhkmkjriilcohijboiekhfk[n[h[XZMTEK6@'2" fullword wide
		 $s153= "#>67>FECBDCJOPPQSQNPNHFGECDCC@8334+" fullword wide
		 $s154= "&-68>??BBCCDFHLNTW[[_`bbcaaa__]YUNIB9/)" fullword wide
		 $s155= "'/69AFMOT[]_bechgfdfa`^YUTNLDB>72,)%" fullword wide
		 $s156= "+6>AEHKJIEC==@BIJNROOQRSRRIF@::;;BGKRVX[^cfdbUG0" fullword wide
		 $s157= "!&+6=DGJIIHOUZ_aefefgd_]YSOLNQW]__aagjotvwwurqmhd][[[ehrsy}~" fullword wide
		 $s158= "!(.6>DINUY_dgeijlilkgihfeeed`aa_[^YWWOPJID=?62.*#" fullword wide
		 $s159= "%6GRX_``[XQOLMMRY^eikkhd_VRROPTZdq~" fullword wide
		 $s160= "@6Opihihigcdeabc^H+13.,DpM>XHFTHCQEKJB" fullword wide
		 $s161= ",754C@;A=@BGOLJMJHEAD@?B?=>>71/0.-!" fullword wide
		 $s162= "# ++77??HEOJXP]Z^gaphxnwuturosem`jZbV[WQPTHOIEFAC;?+8))$" fullword wide
		 $s163= "! *.78BDFQKYR]^cbkhqout|p~uxrukngb`^VNZJSIMEFF;B662-(%" fullword wide
		 $s164= "!-.78>DLMOT`[eaihkkqwnztzyxvvpufm]d[VVNSGKJDEF6H09-0%%" fullword wide
		 $s165= "&-7>FJSWWZ^^^_[YVWRRMOJLHLJOOPWYbdjmrsqtroldbYSJC;5-%" fullword wide
		 $s166= "::88:>IObhgfgdda^YULGFGIPNSTWVTPLD;0(!" fullword wide
		 $s167= "&/8ALT[chnsvy}||}yxsqoieb_ZYTUVVYX]dclnuz" fullword wide
		 $s168= "8>?BCDGKHNMQQOUSWRUVTYVXUVTONLFD==7.(( " fullword wide
		 $s169= "*+8:BMNVYe_lhlgollhojfhhgicgbdaaa]XUWJPA:6,#" fullword wide
		 $s170= "%/8DLU_dlowvy{|ywvtomhec^^XWVQPLJHGCAB=?:;97613.+&$" fullword wide
		 $s171= "8EDIMJKFGIQPUNRMXOUQVZZYTTSU[VUWKXFZDMHKSHHK?J@JDB?:.-(()*7.-(" fullword wide
		 $s172= "'/8=EKPRWXZ[]^^`cceedefecc`^[UQME@92-$" fullword wide
		 $s173= "*'(97@8@@YOXa_hqoxru{}zwpyns]b^RNC52/0(!" fullword wide
		 $s174= "#-9@HNSX[^bdgiknpstttsrpnljfb_ZTLE=3)" fullword wide
		 $s175= ">=A>>=:574/.,+*+**/1049;@EFJKMLMIHDA;92.)%" fullword wide
		 $s176= "^`^^]^_]aa``ab``a`_aa__^_]__]_][ZYZXYYVWVRTSOPOMMLKEIGDACA>?;:857221-+*(&!#" fullword wide
		 $s177= "A@@=@AAGFJGGA@?>EDDGGEEDBERYXSKEBLIYPEFC=97=I9/*)'(+0#" fullword wide
		 $s178= ">=?@ABAABCDDDEFEGEHHHJKKKNNQPRUUXWYY]__cbefjkmmnosrvwuxxz|{}" fullword wide
		 $s179= "=ABCBDGHIMMOQPSTRVRSRPQLIHDCA>;63/.)% " fullword wide
		 $s180= "A@CBDEHGGKJMLNRQSUVUWVXUUQRNKKFCA>55/.*$ " fullword wide
		 $s181= "ACILNQPSUTVUWWUWWWVYWXZ[YWYXUURQLJDA;73.*% " fullword wide
		 $s182= "ADJNOSVYZ^^_^_^`]^^_Z]^\\ZY[WWVRPPIG@?83.(!" fullword wide
		 $s183= ">AEIJLSUVZ[__bcdeifghdcaaXUSLID@851)%" fullword wide
		 $s184= "AHKPMMD;1+$$&,39BHILOSTZ^^[YZ[^chigaXPF?54/-./3369;8/&" fullword wide
		 $s185= "ALOSTTUX]bgjjnllhge`YQIEA:9=AELOSPPH@0&" fullword wide
		 $s186= "aZk`f[_Y^]X^XYYWXWVVVUVRQSRQRRQP:" fullword wide
		 $s187= "B?@DDEGHFLJOPQQSVUSVSQQPMJHEB=?75..,$!" fullword wide
		 $s188= "BECAACDDICCBUVPLITQUNRIKKEJCSVcXIFI_acOA*-" fullword wide
		 $s189= "@BEGIMNSSUVYX[Z[ZZ[VUTPMHFA>851+'!" fullword wide
		 $s190= "BEIMRUWZ]bdfimmoqsrrvptookhha]YRLHB=60)$" fullword wide
		 $s191= "BEKMVX^a]cYcVaO^L^PbSfUiUjPfKcPhZsd" fullword wide
		 $s192= "BGPSY_`fgkkoomnnnlkjlgefhfdaa]^WUSRJGC@>93-)%" fullword wide
		 $s193= "'.:BJV`jmptuywxtvvroollhfeccba`dfgmosu}" fullword wide
		 $s194= "BOSSMHF:7AEV_qzzrgcfcUSTY^gr}~{spkf_UWZb^akeW;$" fullword wide
		 $s195= "@CBEGKMLQSUVYY[_]bdddgiiknmrpprquuvwywyy|z{|}~~" fullword wide
		 $s196= "CBQJSXY`abjdnoksqusvwxyuxsprhia]YTQOHGCE>B6@37,-&$" fullword wide
		 $s197= "CCILOSW]_chilnppstrutrsomkhc`VRKHA;6/)#" fullword wide
		 $s198= "CJQWdejlrsqtsrppnnknkgghfcfda^]XXVNMGB>;61+(" fullword wide
		 $s199= "CKSX]aciffgffdbb^]YYVTSSSUSWZ]ddlnryzz|}{wnlg^VIF81( " fullword wide
		 $s200= "com.albumpro.videoslide.galleryphoto" fullword wide
		 $s201= "com.beautycamera.photoeditor.makeup" fullword wide
		 $s202= "com.calculator.hidephoto.galleryvault" fullword wide
		 $s203= "com.cleaner.memorybooster.ramoptimizer" fullword wide
		 $s204= "com.collagepro.cutpaste.photoeditor" fullword wide
		 $s205= "com.coramobile.phonecooler.cpucoolermaster" fullword wide
		 $s206= "com.coramobile.powerbattery.batterysaver" fullword wide
		 $s207= "com.coramobile.speedbooster.cleaner" fullword wide
		 $s208= "com.funnyvoice.voicechanger.soundeffects" fullword wide
		 $s209= "com.ijksoftware.pdfcreator.camscanner" fullword wide
		 $s210= "com.maxmitek.livewallpaperaquariumfishfish" fullword wide
		 $s211= "com.maxmitek.livewallpaperchristmas" fullword wide
		 $s212= "com.mirrorphoto.photoeditor.collagemaker" fullword wide
		 $s213= "com.smartvoice.digitalaudio.voicerecorder" fullword wide
		 $s214= "com.ssapps.photorecovery.restoreimage" fullword wide
		 $s215= "com.superrec.screenrecorder.capture" fullword wide
		 $s216= "C)SBbWihXdYX`JfEiFgFbE[JVTU][`f]rP}6" fullword wide
		 $s217= "?DIFLNLJMHHFCBC?=>>?=@DBGOPUX_aecgffc^]YQMIC=:3-*!" fullword wide
		 $s218= "dMaP^UTXQUTPTQRPQPOONMMOJLIJJKJIJIIFEFEEGFEEBCCCE1" fullword wide
		 $s219= "%e19c01b3-7f1d-1178-9834-8b8c758db555" fullword wide
		 $s220= "%e19c01b4-7f1d-1178-9834-8b8c758db555" fullword wide
		 $s221= "EFPMPRRPNOMIIFBBAB@A@DDGHOQVW^`dcifhed`_YSPJB=63-%!" fullword wide
		 $s222= "ej_f^`X`[]]WZXXYXYYTVTVTPTPSQPSNPOJ0" fullword wide
		 $s223= "ELV[behgfd]]ZVTSVZ]aeidc[PH=621/013/0,+)'%" fullword wide
		 $s224= "!,EUe[^frX_buficaNIMLC9=MMHJJRb]_[pxr" fullword wide
		 $s225= "'.,F9MGWR^]``khhiuimrqlmujnnkogngphjp_q`ff`^OSR@L.?'(" fullword wide
		 $s226= "--==>>FFYYgghhZZFF>>KKRRJJBB@@;;00**&&" fullword wide
		 $s227= "f[nb_f`ba]][Y][YZYWYUVVUTVSUQQSPQQ;" fullword wide
		 $s228= "fPcP_UUXQWVRTQRRQQPPPMONMNKJJJIKIKHFHGGFFEFEGAEBBDF5" fullword wide
		 $s229= "Generel RGB-beskrivelseAlgemeen RGB-profie" fullword wide
		 $s230= "%./;;HGKMYQ^PhZd`]a`ad]fbb^ic^hfcecba_]^O_LOFAA5-1" fullword wide
		 $s231= "-h|gmthvukuljqkjkhbQ>234222112112000%" fullword wide
		 $s232= "{hSPHEGKT_hklkdaVPJB==@ENYbhfaYV[eoz" fullword wide
		 $s233= ":.?JCXVZcgakkonjnwoosvjzi{eumpingpdkcibe_YUQFJC520!" fullword wide
		 $s234= "{k]NA5+($'-6>ITdnzz~xm`RF:527;AJW_n|" fullword wide
		 $s235= "l[?kRSNVUNRPKPKMJHLHGGDGECF?B?A@=C" fullword wide
		 $s236= "LucudZgaWQWa_YOANSEKEbVcURWHXQF:?H896R>B&26915,%1((0@0/:6:.9(00)545*')62/H9>J?G)87B6AOAGROORNAAG@(0'" fullword wide
		 $s237= "n{nsnknelal_l]m[mWlRiMfJfJiNmUo[k]d]XZIT8M%D" fullword wide
		 $s238= "^!N'P!]2LL[JQ>I-T!X0Q&L'O.R;M:Q0[2U$O$A" fullword wide
		 $s239= "NWDQPGPFGJFGHDDFBE@B?B@=>>=:N_?->D~" fullword wide
		 $s240= "+;NXcknqsvrtrpmljiggjlouv{}~xwpeQB5(" fullword wide
		 $s241= "P5O.K)H*G0J8OATHXL[NO^O_N`MbKdJgIkGnEp@p8m0k)j$k!n" fullword wide
		 $s242= "pXb_X_[W[XWXVWUUTVTUPQRQPPQOOMPNMPMJKJILIJKJF#" fullword wide
		 $s243= "{qi_YSSTX]djmponjida^[ZUTOOIIDC?:5/%" fullword wide
		 $s244= "qphgrEc^Y`XPGJ=;>Q@@6;5C>A?A@7:53.1'!" fullword wide
		 $s245= "&&**))==RRVVII??FFTTZZRRHHGGFFJJNNAA,," fullword wide
		 $s246= "{smjhbaYXVUSQOKFDDIJORTYZTME@=DPW^]ZUPLMOOLGCE@A?>ACEIJKHA2+" fullword wide
		 $s247= "{tmbZQJC>:89:@BFJKLKJGC?=620/+*)''&$%!" fullword wide
		 $s248= "{tpkgb`bhillimlooopmjaUHDCFLTWY`chii^QC3*!" fullword wide
		 $s249= "}tw{rhdc_\\VH;1)-50*+%#-,!%6FRYduxlZ=" fullword wide
		 $s250= "ukaXQMKKLPUY_dhkjih_ZPJC96.,*)+++('% " fullword wide
		 $s251= "vllklqtvxxuspopjifeddcghimttqh[J:,*,.69;===;;:9861-& " fullword wide
		 $s252= "||vvoonnqqoonnoosspp__IIBBOO^^bbhhvv" fullword wide
		 $s253= "vzutmbnjfce[NOKNIGIvTSVXYXORMSNIHwa`" fullword wide
		 $s254= "wgkgia]YaaeWO@>@GIJCD=CAELHGG=H@G@DAPU]UPPOZVTH7.(*6;D:1!" fullword wide
		 $s255= "wpb[QJD@AACGJLOSPRRRQQOOJHFCB===971,'!" fullword wide
		 $s256= "|wpqurwwttlecdaSKHFILPSVSPGCCEJSX]WG9(" fullword wide
		 $s257= "|{wsvwttpsqnja[TMMGHGKNTSTTTYZXUOD;40-.+)$%$!" fullword wide
		 $s258= "~}{wursnqlnif_^_YYWROMKECBA@87/-))!" fullword wide
		 $s259= "xbMEOHDN@GF@GA@D@?CLWUL4(HHLUPR8+7.%&!#'" fullword wide
		 $s260= "xpaSIC@AEDE@>;??CFHGLQSTPGC?8;:DJgu" fullword wide
		 $s261= "}xtstu|z{xtrjda]WWWXWXWWW[[_]XRC:50430/39=A=5, " fullword wide
		 $s262= "|xuwvssrsrtqrssvyxpi`SOOQPPKC;6300/.)&*+..(!" fullword wide
		 $s263= "xvtvxupmgdXVVXVXZ]^YVPLLPXcjlbYPD;95854118?EFHKMJF>2%" fullword wide
		 $s264= "}|{{xxwvtuqrroplnikhhhgeeddaa`__]^[Z[YZZZXYWWVUWUUWVVVRWTSRSUURVTUSTTUWUWVUWXXUWXYZYYZZXZ[Z[[Z[^]" fullword wide
		 $s265= "~}{{|{xxwvuvtuttptrqsrpqppqpqorqqssqsrqssuvuvvxyxx|{z~}" fullword wide
		 $s266= "yndZPE?6/-+'+.25;ELQXaglnlmih`YQH;3%" fullword wide
		 $s267= "yphQE@6-)&%#)).6>EKTZaglqpokh`YOF;0%" fullword wide
		 $s268= "~~}{yxssppkjhca]YTTOOMEEC>;94/.'##" fullword wide
		 $s269= "{yyytuvsrrpoqnnmiikkgghfhfeeceddcaccd`cdc`caccddccdcdddgggiehghkjikjmmmomqpoqprrsrttuutxwywwywyy{{|{" fullword wide
		 $s270= "|y}y|{{{z|y|z{{|zxwzwvvtsrqrqpmmlmjjhgcca`_YYYVSOPNIJFEB?=;:531.,,&%#" fullword wide
		 $s271= "yzzwxxtuqrqppvvsmb]b^]^J.5923524506" fullword wide
		 $s272= "zskfbYWTQTRRQRPMJHDBCBEIOSW^[XSI>/!" fullword wide
		 $s273= "{zvrqqqlpnkmjjhhgeedccgfiknqqqrruvxxz|" fullword wide
		 $s274= "}{zyyxurpqqpnjffdbb]\\XWSRNLKGCB>>8852/,*## " fullword wide
		 $s275= "}zzwpnkifca`_^_^`abbeeefdc_]XRKD;/$" fullword wide
		 $a1= "%+. &))-0)-2)/2(-1(.1)/3(/3(.2)/3*/4(03).2'14',0*13(.2'.2&-2(05!(+)/3(/3(.2)/3).3)/3)/4(/2(/2'-1(14)/3).2+15)04$14'+/(.3(.2'05)-1(-1(/2)/2(-2).2'/4&15" fullword ascii
		 $a2= "2BKBYaY+6+gpg:A:ZcZaja1=1$.$[d[+6+U^U8B8,7,#,#d]e]clc-9-]f]gpg,8,^g^kuk-9-%1%^g^]f].:._h_^h^2>2.:.`h`_h_>I>aia/;/'3'gpg" fullword ascii
		 $a3= "3ffF]]NbvUffUcqMffUamXajWfmYffWcnQgmXmmSglZmmWkkUej]choo]l|Oaa]]hQkkZxxP``NbbMff33f+UUZgoYgoWhrVfoVlnYkqVjnWimWjnWhmXjmVjmVhmVhmWjnVinUhmVhnVjnWilWgl" fullword ascii
		 $a4= "+48(.2,-/(.3)/3(/3(.1(/3(.2'.2(.2)/3(.2(.3(/2)/3(/2)/3).3'.2)/3(.2-00)/3)/3(/2)/3(.2(.2)/2).2(-3)/2'.3(/2)/3(.2(.2'.2(/3)/3(.2)/3(.2(.2(/3++1)/3(.3)/3" fullword ascii
		 $a5= "81,37382,37383,37384,37385,37386,37396,41483,41484,41486,41487,41488,41492,41493,41495,41728,41729,41730,41985,41986,41987,41988,41989,41990,41991,419" fullword ascii
		 $a6= "AAA???CCCMMMNNNDDDLLLGGGKKKFFF===OOOPPPRRR^^^oookkkggglllfffeeejjjlllqqqvvvhhhdddIII:::888555111333JJJIIISSSYYYaaa]]]aaatttmmmrrreeebb" fullword ascii
		 $a7= "apps/details?id=com.syntellia.fleksy.keyboard&referrer=utm_source%3DSolo%26utm_campaign%3Dsolotheme01;end" fullword ascii
		 $a8= "bjsRdkVhnUglUgnTflUhoUgmVff???UfmZmrYlrovou[nu[ntZmtZmsYlsYkqWkqWjpVioTgmTglUhnUgnWkpYkrUgo?UURdkYlrVhmSglXfmTfkTdkUenTgkShjTgoReiSfjUimSfiRhlSikRbk" fullword ascii
		 $a9= "%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cff" fullword ascii
		 $a10= "com.android.mms||com.facebook.orca||com.whatsapp||kik.android||com.jb.gosms||com.skype.raider||com.textmeinc.textme||jp.naver.line.android||ru.mail||c" fullword ascii
		 $a11= "EFL018EEK007DEK/07DDJ//6CDJ./6&&'./5CCJ..5BCJ-.5BCI-.4BBI--4ABI,-4ABH,-3AAH,,3%&'AAG+,2%%'++2%%&@AF*+1@@F**1@@E**0?@E)*0??E))0??D))/>?D()/>>C((.$%&=>C" fullword ascii
		 $a12= "EJ(.1%.1)04)/3$),).2'-1).2)/3'.1',1(.2(.2)/3,16).0)/2)/3(/3(/2)/3)/3'-2)/3).2).1)/2(.3).3+04)/3)/3&.1)/3)/3',/(/3)/3(/3" fullword ascii
		 $a13= "eO5iT:eO6dO7gQ8kU;gR9dN8fQ8fQ8hS9dN4eO6``@gQ8iT:gQ7dN7gS9hR8fM7f33gP8fR8fN7hR9bM7mI$gR9fP7bN7gR9hR9gN7hR9hR8hQ6fR9gP5hQ8hR9gQ8gN5gR8iS9gR5eO8gQ9eQ5hR9" fullword ascii
		 $a14= "?ffUhnUgnTgnTgmPglTdlUglUhm?__ShlUfmTglTemTflOhlUhmUgnPfiShmUfmRcjQhkU__RfiThnUfmNag6HmSikSflRinTinTfnShnShmOgkQhhH[dSgkTgmTfmUhlUfmSgmUhmSfnUhnSgnThm" fullword ascii
		 $a15= "gmUjpVglKbb:NuTflYhmUglKalZiiTfmVhoRflXccDkkNad?[[QhkVhmVhpVflR`iZltUioUikWkqVioXjqUimF`iQdjXhpYlsVfmSfnUinUhnUej[[hUikVhnUinRhmQinUgjYkrYkqWgnUjjWhrW" fullword ascii
		 $a16= "grXhnWisZlpXjoXdiUaaUjmWipZmrXipVknXgqZksWjoVhnWipYlqWjsUffXipXhnUmmbqqUenot[ms[mrZlqZlpZkoZkpXjoXjoWioYkp[mqmrosXhoWccZrr[fmWlqWhpXjqUgoWgqWhoXjn" fullword ascii
		 $a17= "GU7AONZiWdtQ^m>JX3=J@LZ)3@S`o8CQS_n#,9IUd?JY&0=GSbVcs+5B1;HTapO[j7BP4>LCO/9F(2>UbrAM[@KY *6MYh9DRHTbLXg3>K" fullword ascii
		 $a18= "hQ:eQ7hP8eO5fQ8mV;fQ8fM3gQ8iS9fQ8iT:eQ8`M9`L7eP8hS:hR9fP8gL7mU=dP6gR9iS:iS5cL4fN6`@@eP8gS9lU;eP8fQ7gR9hR9fR7bN;fQ8eQ8dQ8fQ9iT9hS9gQ8fM6jU+fO5fR8cP4bL6" fullword ascii
		 $a19= "#Intent;action=home.solo.launcher.free.action.LAUNCHER_THEME;package=com.syntellia.fleksy.keyboard;S.LAUNCHER_THEME_URL=https://play.google.com/store/" fullword ascii
		 $a20= "IqsJmoEno-Z)>@Cln4df%>?&BC>[]/MN%CE'EF;XZJgi)IK1OQIrt6bd3_b0XZC`b%@BJpr4SU/OQPkl5TVRlnQlmGoqDmn;Y[?^(JL.NPNikHoq5ac1]_Krt7VXEbd/PRJfg+KMOjl9dfKqsMhj" fullword ascii
		 $a21= "joWioVjoWipUjmRdnVimVhqWkoXjqSgm[ns[ntWjoUgmWgnUipVfmUfmUfpPiifffThm[nsZlsZnrUhnUhnXkoXipTeqUUjZmrYlrZhn" fullword ascii
		 $a22= "om.viber.voip||com.groupme.android||com.link.messages.sms||com.bbm||com.google.android.apps.messaging||com.htc.sense.mms||com.skype.rover||PK" fullword ascii
		 $a23= "PciUgnYjpThnQXXEssVbnXlpVjoXipVinIikVQlUhlXkoVipUelL[[WjnYkqWgmJc|TgmVipWhmSgl3ffVimVkoUioUflUinUfnBciXiq[biSflXkrXjqTeqVblYhmWjqNflKgoTfmV^cZnrYlrRfn" fullword ascii
		 $a24= "PjUhnTjoWjpVekYkqou[ntRelH$mIjjUjoNgkTgmTfmUdlQekRfkUinT`iQgjSfiVdhTemUfmUfmUhnZmrVioUfmH]`VjoXipUgnUhmWinUmmUjnVipSelTflTflRfkVikPcjTfkSfmSgjRelU^l" fullword ascii
		 $a25= "Q46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46Ec" fullword ascii
		 $a26= "Rj{QffWilVjnUinVhnVioVinUhnUgnVioVhoUhpVhlWipUfmQhqPbUehWgmVjpVipUinVjoWipVioUinVjpUinVhoRjpNbbCUUTgqVipVinUhpWjoWjpVipVioUioVfoUfkMio$HHUfpVhoVjoVin" fullword ascii
		 $a27= "RT>UVBdfPxzG`aDhj3WXHbcIjlMfhNtv,BC4[]HpqSoq0KL7OP0HJA`b3PQ.HI>^`?Z7gi1TW.QS2ZMmo-EGNsuB^_-TV,PR%EGDac3^`+JL*JL-LNRkm" fullword ascii
		 $a28= "ru}-.0mpz_j013loyknx[^iknw[^hjmwZ]h003jlvZg/03iluYfhkuX[f/02hktX[egjsWZd//2fisVYdfhrVXcfhqUXbegpTWa//1efoTV`,-/[]fILU++-UW_CENUW^CEMTV^BDMTU]BCLSU]" fullword ascii
		 $a29= "S46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46Ec" fullword ascii
		 $a30= "SiiTiiTfoVinUimWimWgnWimWimUgnUgmWgmVeoUUaUinUioWimWioVhmWgmTflOfkTinUgoUhmUimUgmNdoTinUgoVhnII[WioWio;NNWbmUinWekTim@``UimVikUgmUimVimTfmThlVikVhnVdm" fullword ascii
		 $a31= "_\\SimUhmUgmUflSfmUgoP[lUgnWipRfnDWWUhmYmrUioObbZlsSekRckXjp@[dSehRjjUioUenRipSclUfmUdoVipXjqVhoO_gWjoZkqXkqWfnNddThhUhl\\LffThlNdlVgnVinM`UgoUinU]" fullword ascii
		 $a32= "TfmUgnSfkThmUdlRglSfnRbmTeqQfiTilSciOfiPdnOcjS^iRilSjjUaePffM_hNfkN]pUddVbnVbbLffMccU\\U\\O`lVioZmsThnUUjRkknuUim.\\WkqYmsUgnWjpUinZntUhlHffGffPffZms" fullword ascii
		 $a33= "TgmSfmSggTelXjqUfkShmXinWiqUhlBcnPWjTgmWjpRejRik:uuXkrUgn___UepUgmRfkTfkShjWdlThmUglThnUhoUhmSglUbkTirTbkTgmThmTfmDSSUfnRagUcgQ[[VipU][ntYnrRcgQggWjp" fullword ascii
		 $a34= "T]gWinXkpThnTfmP_dO[dUflRfnVelfffA8KUhoYlrTgjXjoVjnVfmM_aWWgTgoWinTgnTjm?__UhmWioQfk@aaF]]TekUfmUgnSglUgoWipUhnUhnRglUgnVjpXlqUhoYkrUgnUflNbpRgjVhnUin" fullword ascii
		 $a35= "TinQekXZZXXXTfnTilUelXko^llUgnVjnUjpXjpTgqRhnUgoVko'66TipUhhXjoUgoWioRhmUfmVimVhoUfkWjoLfrNffXkrShjKalSgnSggQhnWipOOhUejUflTdlUimRglUfmUgnYlqUgoXjoSej" fullword ascii
		 $a36= "TinThl[mv[nu[ntUioQgqUfpXlqouYlrVioUhnUinSflUei!RROUUPfgXkqZmsYkrWjpWioVioEsRfjVhpVjoYkqZlsVipXkqUioSimWeQikVgoTglUfnUhmUhmUioTfmVjpUhnTgmXkrTgk\\" fullword ascii
		 $a37= "TjnXjnWjoXjnVioVisWhrXmm999ZkkWjm[ntot[mrlrYkrZlrZjqYkrXjpXiqYjpXioXipWipYjqYipZlsZkrZlr]nsnsZnsXjm`fl" fullword ascii
		 $a38= "U[aUfmQiiUimU^lUglUfnTfnUhlWinSfoVflXjoXkpTfmUglTgnTgnTfkLgmUhlSjnUfoNhhWkpQdlQinRgmUUNflTimSfnUilUioWiqThlShnR`mSdjSdlRgi?" fullword ascii
		 $a39= "UfmVioVhoVhpVioWipWioVipUioWioVimUfnYjpWhmVhpWgpYjqXhoViqZhoVjr@``IImUjjQ]]JRc]llY``U``WggUeeWafSggShhU`e]]]WmmDM^YYY`" fullword ascii
		 $a40= "UhmVemUjpXkpUkoVil[mtZmtVhlQcl4QQ[[aVhk[mtVfmTciUhjSbjBZaShkAkkTdmUhnRchY_bAbbLacYgoSfnVhkTgmUgmSfnUdlRfmUhkTfmYlsUgpUgiQfl]nvRel[mtShkThrXdhHaoSejUin" fullword ascii
		 $a41= "UjnYjoVgoWflVhlUqqF]]XhnVglIUaVhjWioSaoXjoRffWikVgnUgmXhoYgnYkpmsWimRjnXinWipWip]jjWhoTilYgpThnWhnUjqW`jNlb``pUhkVjnUim]]tWfpWkpYlqXiqXjo[lrWinVhmWho" fullword ascii
		 $a42= "U__TfnYlpXjqUflIddUiiVkpWkpUfnShhUjpXkpTilRfiVhmVjoWjpXkqTglQ[[YdkVjoTgnTgmWjoXgnUglXjpYlqXjpTdlVimVkoYlrUhmUekDPcHHHTipYmrWipSgmUimWioUhmUfmSfjSahVko" fullword ascii
		 $a43= "VeoUfkUimNdoWgnNdoVgmVinWimVimII[VilUffThlUgnSffVimVhmWioUimUdhWhmS`gQ^^Who3ffUgmUenRgkUiiThoUioUfmWgoW`oWimUhhTgmTilVfmWimWioWimUgm@``WhnUgmUdoUgoWio" fullword ascii
		 $a44= "VglVgnUinTioUioWhnVinTgoVimWimWimU]dTenUgoWiiWimQdjUgoUiiWhmUimVhnWgmUgoWimUimSffUioUioVhoWbmTfjSfiRgkS`gWgmUioSiiWgmWioWinWimUflWioMekUcUimWioUagQee" fullword ascii
		 $a45= "Vii_pp:OO0AA6JJReemm*::Xjjeuu+;;dtt?SS@VV?UU[llYjjnnWii^pp[mm@TTWjj^ooZllVhhUhhUggTffReeRddbssYkk]ooBWWAUUarrQddMaaK^^SffAVVduuK__NaaI]]J]]DXXCXXBVV" fullword ascii
		 $a46= "ViiSeeL``I\\H[[_qq[ll]nnmmRdddttMaa?SS]oo_ppJ]]^ppUggCXX^ooAUUDYYK__UhhVhh@TTTggTffSffnn[mmBWWduuZllarr`qqReeXjjJ^^WiiAVVYkkM``L__BVVQddbssK^^CWW@UU" fullword ascii
		 $a47= "V`iTgmUinUfmTejIbgUhrUfmVipUgm8iiIjmVgkVipXjpUgmUglVjoYlrUdmT]lVkpUfkUgnUilW`cVjoWkpTenYlsTflLAYUhpUikVjpUgnOipIffVjpUgmT`jVhoWkpDW^PfjUgnPffUenUhmRdm" fullword ascii
		 $a48= "WhlVioRddUaaOaaXfoVjmUcmXinXllVinWgnVgoZkpZkqWjoWkpVilUUqDffWhmVkrWhkVhnVclWhnJUUZhpVfnlsVjpRff]]]fffUqq^^k" fullword ascii
		 $a49= "WhnWioVioWinVhnWinWhnWioVioVhnVhmUhmVhmWhmUglTgnUfmTgnUfoSfkVhnVinVgnVhoUejSekVinUgkWhnUcjUfoWhoPhhUgmWinU`jKiiUinVimUUj3ffWhnQhhWioVinWioVhoVhoVinWhn" fullword ascii
		 $a50= "WinWinMffMffWinVhoWgoVhoWinUflVhoVhoWinVfnTilVioVhnVhnWhmWioVhoWhnVhoWhoVgoVgoUhnUgnUgoVgoVflSiiTenVhnVimTimUffVinWimShmVhnVioSgnVhlVhnRffVio" fullword ascii
		 $a51= "XffWjpVemVhmWhoWhlVioRddUaaOaaXfoVjmUcmXinXllVinWgnYlp[ntXjoVhoXjpYjqYgqUqqWkpVilUUqDffWhmVkrWhkVhnVclWhnJUUZhpVhoWjoVloWirWjpVjpYipfffIII]]]fffSggXko" fullword ascii
		 $a52= "YqqXhpWjoWioWipWhnSqqWhnWipWjoXioWhoWhoYloWjoXhlXgqXkqXkpWjpRfjUooZjnWjqYmpXipXjpTll[mmUmqYhqWhpYkp333amySgoXhnZmqWhoXhpTjmXjoXppWgoWjoWhkYjq[mrQmmIII" fullword ascii
		 $a53= "ywxwuuqppnlmnmmrqqvtt~|}tsttsrvtuigggefgeehggkjjmkkomnqppsrrvtutssrqqpnonllkjjkijcbcjhi^]]dccfeehggjiixwwussmllihhgefbaa`__`^_dbbommtrrpnnigha__cbblkk" fullword ascii
		 $a54= "{zz]\\ZYYWVVjhi_^^]\\xvv_^^YWW[ZZMLL[ZZXWW_]^_]^XVWbaabaaPOOQPPQPPWVWb``]\\TTSZXXihhwuv[[dcc]`a_^^cbba``gefhggcbbmllgffjiihfgjiiomnsqrqpponnpooutt" fullword ascii

		 $hex1= {246131303d2022636f}
		 $hex2= {246131313d20224546}
		 $hex3= {246131323d2022454a}
		 $hex4= {246131333d2022654f}
		 $hex5= {246131343d20223f66}
		 $hex6= {246131353d2022676d}
		 $hex7= {246131363d20226772}
		 $hex8= {246131373d20224755}
		 $hex9= {246131383d20226851}
		 $hex10= {246131393d20222349}
		 $hex11= {2461313d2022252b2e}
		 $hex12= {246132303d20224971}
		 $hex13= {246132313d20226a6f}
		 $hex14= {246132323d20226f6d}
		 $hex15= {246132333d20225063}
		 $hex16= {246132343d2022506a}
		 $hex17= {246132353d20225134}
		 $hex18= {246132363d2022526a}
		 $hex19= {246132373d20225254}
		 $hex20= {246132383d20227275}
		 $hex21= {246132393d20225334}
		 $hex22= {2461323d202232424b}
		 $hex23= {246133303d20225369}
		 $hex24= {246133313d20225f53}
		 $hex25= {246133323d20225466}
		 $hex26= {246133333d20225467}
		 $hex27= {246133343d2022545d}
		 $hex28= {246133353d20225469}
		 $hex29= {246133363d20225469}
		 $hex30= {246133373d2022546a}
		 $hex31= {246133383d2022555b}
		 $hex32= {246133393d20225566}
		 $hex33= {2461333d2022336666}
		 $hex34= {246134303d20225568}
		 $hex35= {246134313d2022556a}
		 $hex36= {246134323d2022555f}
		 $hex37= {246134333d20225665}
		 $hex38= {246134343d20225667}
		 $hex39= {246134353d20225669}
		 $hex40= {246134363d20225669}
		 $hex41= {246134373d20225660}
		 $hex42= {246134383d20225768}
		 $hex43= {246134393d20225768}
		 $hex44= {2461343d20222b3438}
		 $hex45= {246135303d20225769}
		 $hex46= {246135313d20225866}
		 $hex47= {246135323d20225971}
		 $hex48= {246135333d20227977}
		 $hex49= {246135343d20227b7a}
		 $hex50= {2461353d202238312c}
		 $hex51= {2461363d2022414141}
		 $hex52= {2461373d2022617070}
		 $hex53= {2461383d2022626a73}
		 $hex54= {2461393d2022252525}
		 $hex55= {24733130303d202223}
		 $hex56= {24733130313d202225}
		 $hex57= {24733130323d20222a}
		 $hex58= {24733130333d202223}
		 $hex59= {24733130343d202221}
		 $hex60= {24733130353d202221}
		 $hex61= {24733130363d202225}
		 $hex62= {24733130373d20222b}
		 $hex63= {24733130383d202225}
		 $hex64= {24733130393d202221}
		 $hex65= {247331303d2022242a}
		 $hex66= {24733131303d202228}
		 $hex67= {24733131313d202228}
		 $hex68= {24733131323d202223}
		 $hex69= {24733131333d202223}
		 $hex70= {24733131343d202226}
		 $hex71= {24733131353d202223}
		 $hex72= {24733131363d202221}
		 $hex73= {24733131373d202226}
		 $hex74= {24733131383d20222b}
		 $hex75= {24733131393d202223}
		 $hex76= {247331313d2022242a}
		 $hex77= {24733132303d202225}
		 $hex78= {24733132313d202223}
		 $hex79= {24733132323d202227}
		 $hex80= {24733132333d202225}
		 $hex81= {24733132343d202226}
		 $hex82= {24733132353d202223}
		 $hex83= {24733132363d202221}
		 $hex84= {24733132373d202225}
		 $hex85= {24733132383d202221}
		 $hex86= {24733132393d202221}
		 $hex87= {247331323d20222427}
		 $hex88= {24733133303d202228}
		 $hex89= {24733133313d202226}
		 $hex90= {24733133323d202225}
		 $hex91= {24733133333d202225}
		 $hex92= {24733133343d202234}
		 $hex93= {24733133353d202225}
		 $hex94= {24733133363d202227}
		 $hex95= {24733133373d202226}
		 $hex96= {24733133383d202225}
		 $hex97= {24733133393d20222a}
		 $hex98= {247331333d20222624}
		 $hex99= {24733134303d202226}
		 $hex100= {24733134313d202225}
		 $hex101= {24733134323d202226}
		 $hex102= {24733134333d202221}
		 $hex103= {24733134343d202223}
		 $hex104= {24733134353d202226}
		 $hex105= {24733134363d202225}
		 $hex106= {24733134373d202225}
		 $hex107= {24733134383d202226}
		 $hex108= {24733134393d202223}
		 $hex109= {247331343d2022242c}
		 $hex110= {24733135303d202225}
		 $hex111= {24733135313d202228}
		 $hex112= {24733135323d20222f}
		 $hex113= {24733135333d202223}
		 $hex114= {24733135343d202226}
		 $hex115= {24733135353d202227}
		 $hex116= {24733135363d20222b}
		 $hex117= {24733135373d202221}
		 $hex118= {24733135383d202221}
		 $hex119= {24733135393d202225}
		 $hex120= {247331353d2022242a}
		 $hex121= {24733136303d202240}
		 $hex122= {24733136313d20222c}
		 $hex123= {24733136323d202223}
		 $hex124= {24733136333d202221}
		 $hex125= {24733136343d202221}
		 $hex126= {24733136353d202226}
		 $hex127= {24733136363d20223a}
		 $hex128= {24733136373d202226}
		 $hex129= {24733136383d202238}
		 $hex130= {24733136393d20222a}
		 $hex131= {247331363d20222430}
		 $hex132= {24733137303d202225}
		 $hex133= {24733137313d202238}
		 $hex134= {24733137323d202227}
		 $hex135= {24733137333d20222a}
		 $hex136= {24733137343d202223}
		 $hex137= {24733137353d20223e}
		 $hex138= {24733137363d20225e}
		 $hex139= {24733137373d202241}
		 $hex140= {24733137383d20223e}
		 $hex141= {24733137393d20223d}
		 $hex142= {247331373d20222427}
		 $hex143= {24733138303d202241}
		 $hex144= {24733138313d202241}
		 $hex145= {24733138323d202241}
		 $hex146= {24733138333d20223e}
		 $hex147= {24733138343d202241}
		 $hex148= {24733138353d202241}
		 $hex149= {24733138363d202261}
		 $hex150= {24733138373d202242}
		 $hex151= {24733138383d202242}
		 $hex152= {24733138393d202240}
		 $hex153= {247331383d20222323}
		 $hex154= {24733139303d202242}
		 $hex155= {24733139313d202242}
		 $hex156= {24733139323d202242}
		 $hex157= {24733139333d202227}
		 $hex158= {24733139343d202242}
		 $hex159= {24733139353d202240}
		 $hex160= {24733139363d202243}
		 $hex161= {24733139373d202243}
		 $hex162= {24733139383d202243}
		 $hex163= {24733139393d202243}
		 $hex164= {247331393d20222323}
		 $hex165= {2473313d2022212024}
		 $hex166= {24733230303d202263}
		 $hex167= {24733230313d202263}
		 $hex168= {24733230323d202263}
		 $hex169= {24733230333d202263}
		 $hex170= {24733230343d202263}
		 $hex171= {24733230353d202263}
		 $hex172= {24733230363d202263}
		 $hex173= {24733230373d202263}
		 $hex174= {24733230383d202263}
		 $hex175= {24733230393d202263}
		 $hex176= {247332303d20222425}
		 $hex177= {24733231303d202263}
		 $hex178= {24733231313d202263}
		 $hex179= {24733231323d202263}
		 $hex180= {24733231333d202263}
		 $hex181= {24733231343d202263}
		 $hex182= {24733231353d202263}
		 $hex183= {24733231363d202243}
		 $hex184= {24733231373d20223f}
		 $hex185= {24733231383d202264}
		 $hex186= {24733231393d202225}
		 $hex187= {247332313d20222324}
		 $hex188= {24733232303d202225}
		 $hex189= {24733232313d202245}
		 $hex190= {24733232323d202265}
		 $hex191= {24733232333d202245}
		 $hex192= {24733232343d202221}
		 $hex193= {24733232353d202227}
		 $hex194= {24733232363d20222d}
		 $hex195= {24733232373d202266}
		 $hex196= {24733232383d202266}
		 $hex197= {24733232393d202247}
		 $hex198= {247332323d20222124}
		 $hex199= {24733233303d202225}
		 $hex200= {24733233313d20222d}
		 $hex201= {24733233323d20227b}
		 $hex202= {24733233333d20223a}
		 $hex203= {24733233343d20227b}
		 $hex204= {24733233353d20226c}
		 $hex205= {24733233363d20224c}
		 $hex206= {24733233373d20226e}
		 $hex207= {24733233383d20225e}
		 $hex208= {24733233393d20224e}
		 $hex209= {247332333d20222124}
		 $hex210= {24733234303d20222b}
		 $hex211= {24733234313d202250}
		 $hex212= {24733234323d202270}
		 $hex213= {24733234333d20227b}
		 $hex214= {24733234343d202271}
		 $hex215= {24733234353d202226}
		 $hex216= {24733234363d20227b}
		 $hex217= {24733234373d20227b}
		 $hex218= {24733234383d20227b}
		 $hex219= {24733234393d20227d}
		 $hex220= {247332343d20222427}
		 $hex221= {24733235303d202275}
		 $hex222= {24733235313d202276}
		 $hex223= {24733235323d20227c}
		 $hex224= {24733235333d202276}
		 $hex225= {24733235343d202277}
		 $hex226= {24733235353d202277}
		 $hex227= {24733235363d20227c}
		 $hex228= {24733235373d20227c}
		 $hex229= {24733235383d20227e}
		 $hex230= {24733235393d202278}
		 $hex231= {247332353d20222423}
		 $hex232= {24733236303d202278}
		 $hex233= {24733236313d20227d}
		 $hex234= {24733236323d20227c}
		 $hex235= {24733236333d202278}
		 $hex236= {24733236343d20227d}
		 $hex237= {24733236353d20227e}
		 $hex238= {24733236363d202279}
		 $hex239= {24733236373d202279}
		 $hex240= {24733236383d20227e}
		 $hex241= {24733236393d20227b}
		 $hex242= {247332363d20222427}
		 $hex243= {24733237303d20227c}
		 $hex244= {24733237313d202279}
		 $hex245= {24733237323d20227a}
		 $hex246= {24733237333d20227b}
		 $hex247= {24733237343d20227d}
		 $hex248= {24733237353d20227d}
		 $hex249= {247332373d20222428}
		 $hex250= {247332383d2022242b}
		 $hex251= {247332393d20222425}
		 $hex252= {2473323d2022242428}
		 $hex253= {247333303d2022242b}
		 $hex254= {247333313d20222428}
		 $hex255= {247333323d2022242a}
		 $hex256= {247333333d20222121}
		 $hex257= {247333343d20222428}
		 $hex258= {247333353d2022242b}
		 $hex259= {247333363d20222429}
		 $hex260= {247333373d20222429}
		 $hex261= {247333383d20222426}
		 $hex262= {247333393d2022242c}
		 $hex263= {2473333d2022242426}
		 $hex264= {247334303d2022242b}
		 $hex265= {247334313d2022242b}
		 $hex266= {247334323d2022242d}
		 $hex267= {247334333d20222423}
		 $hex268= {247334343d2022242d}
		 $hex269= {247334353d20222123}
		 $hex270= {247334363d20222328}
		 $hex271= {247334373d20222527}
		 $hex272= {247334383d20222627}
		 $hex273= {247334393d20222140}
		 $hex274= {2473343d2022242528}
		 $hex275= {247335303d20222121}
		 $hex276= {247335313d20222325}
		 $hex277= {247335323d20222125}
		 $hex278= {247335333d2022282b}
		 $hex279= {247335343d20222629}
		 $hex280= {247335353d20222a30}
		 $hex281= {247335363d20222525}
		 $hex282= {247335373d20222125}
		 $hex283= {247335383d20222125}
		 $hex284= {247335393d20222830}
		 $hex285= {2473353d2022242527}
		 $hex286= {247336303d20222b21}
		 $hex287= {247336313d20222830}
		 $hex288= {247336323d20222930}
		 $hex289= {247336333d20222330}
		 $hex290= {247336343d20222930}
		 $hex291= {247336353d2022232a}
		 $hex292= {247336363d20222830}
		 $hex293= {247336373d20222128}
		 $hex294= {247336383d20222627}
		 $hex295= {247336393d20222323}
		 $hex296= {2473363d2022232325}
		 $hex297= {247337303d20222123}
		 $hex298= {247337313d20222727}
		 $hex299= {247337323d20222b27}
		 $hex300= {247337333d2022262b}
		 $hex301= {247337343d20222123}
		 $hex302= {247337353d20222a2c}
		 $hex303= {247337363d2022272b}
		 $hex304= {247337373d20222327}
		 $hex305= {247337383d20222121}
		 $hex306= {247337393d20222b31}
		 $hex307= {2473373d202224252a}
		 $hex308= {247338303d2022232b}
		 $hex309= {247338313d2022252a}
		 $hex310= {247338323d20222127}
		 $hex311= {247338333d20222627}
		 $hex312= {247338343d2022252b}
		 $hex313= {247338353d20222831}
		 $hex314= {247338363d20222321}
		 $hex315= {247338373d20222631}
		 $hex316= {247338383d20222a31}
		 $hex317= {247338393d2022212a}
		 $hex318= {2473383d202224262b}
		 $hex319= {247339303d20222731}
		 $hex320= {247339313d20222126}
		 $hex321= {247339323d20222828}
		 $hex322= {247339333d20222123}
		 $hex323= {247339343d20222526}
		 $hex324= {247339353d20223232}
		 $hex325= {247339363d20222325}
		 $hex326= {247339373d20222329}
		 $hex327= {247339383d20222529}
		 $hex328= {247339393d20222128}
		 $hex329= {2473393d2022212427}

	condition:
		41 of them
}
