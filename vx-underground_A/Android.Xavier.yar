
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
		 date = "2022-01-12_19-43-15" 
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

	
 		 $s1= "##&'&)**)*,*)+()((($&##!" fullword wide
		 $s2= "! %$%&+)+*,*-,,+,+(*)(&&$!" fullword wide
		 $s3= "!%/-***+,(**()**)$(#&%%&%$&% " fullword wide
		 $s4= ")$!%#)/)*-*+'%)-.--,-*-)+$ " fullword wide
		 $s5= ")*)())(&*'*'&%##%%$#$#%$$ " fullword wide
		 $s6= "! $$%$'%%&%%('**06:AGNRZZ`_]^YWSPKG@;5.&" fullword wide
		 $s7= "$%$)&**).'0)-,)/(+)*%($$!!" fullword wide
		 $s8= "$$(,/04476::?>?CDEGINKOOPRQRQPQNNILGDA@>;852-,(%!" fullword wide
		 $s9= "$$&(-04;=?FEIMKJIJHD?@;:6651369==DKSX_iqvz" fullword wide
		 $s10= "$$22AAJJ99&&##((FFOOLL[[ww" fullword wide
		 $s11= "$$55EEHH>>00$$!!++88JJcc||" fullword wide
		 $s12= "$%(**)-*./+.,+-,+)+-,-,-..0-0/1./1++&#" fullword wide
		 $s13= "$%''*,,-//.-,,,),((**))**.0056668;;8865/*'$" fullword wide
		 $s14= "##%$&*++)/.0//14313232211222120H@@?>@?OQMNRTRPZfjkjdZirorosni_XZSWTPDFPMNKFD?897551.-/.*)'$##$$#!" fullword wide
		 $s15= "$%*-0155;8=;@@?@@A?A=A;>=8;846/.))%" fullword wide
		 $s16= "$&+01569@@DDJKLPRTXWXZY^[[[ZWWVQNKGE@:63.)% " fullword wide
		 $s17= "!$',&0,2/43666999;9@;?@?B>@@=?:?6933/-)*" fullword wide
		 $s18= "$*,026:>@CGJKNOUWYX]a``b_a^]]YUTONIBB961,&$" fullword wide
		 $s19= "$*.02:9=?CDDHGJKKKOOOQSTVVXZY[XXYVVQRNKHFA;:52/*%#" fullword wide
		 $s20= "$'+0469=BDHJMQUUZ^_bbdgefhfeca`][VTMKDB:80-& " fullword wide
		 $s21= "&$0*63@6HCNOT[b`lhioinikfjbb]_[[S]KXKQLLHDED?9=35-+#$" fullword wide
		 $s22= "#$*.069>>BDHJKLNMMNKJIEB>:51,$" fullword wide
		 $s23= "$,07>BGLORWZ[_bbgglknorrtuuwxuvsqmje_ZPHA8-$" fullword wide
		 $s24= "$*09>AGJLQTV`dfiklmjkhga_YVQKHC?>?@BEFGGFHEFFEDBCABADAB?=:652-,($" fullword wide
		 $s25= "$09?EKQW`flopkgec^[SI?4)!" fullword wide
		 $s26= "$0=AKPZ^dhemlkllikhccc^]]WYVWXWW^]bfjppx{}~|z{trg`YOF9/)!" fullword wide
		 $s27= "$'),10568;>ADCFIIMNNOQQQPOOMLJGFD>=850-&$" fullword wide
		 $s28= "##&$&*,+)/.1//14323332211222121H@@??@?ORLNRTQR[fikjdZirqrqspi^XZVYUODFPNOLHD>897362/-/.*)'$##%$#!" fullword wide
		 $s29= "##&$&*,+)/.1//14323332211222121H@@??@?OSMOSTRR[gjkld[isqrqtri_Y[XZUPDFPNOMHD?897562/-/.*)'$##%$#!" fullword wide
		 $s30= "$%),11569;>BBEHHINLOOQSRRROQMMLJGCA>852.)%" fullword wide
		 $s31= "#$()-/127:;=@BEGHJKMQQUUWY\\]__bbeefgiiijklnmmnlroqpqsqrrsrtutxxyzz~" fullword wide
		 $s32= "!$*,./1336330,+)(&(*-+,-+.03254488989674213..-/**#" fullword wide
		 $s33= "!$),1368>>BBCFFDGDDB@?>883/-'% " fullword wide
		 $s34= "!$(136>AEHMPTZ^_bhikpqvuvx|w}zvwuuomie`[UOKC>9/,%" fullword wide
		 $s35= "$'-138;@AEHJNPUVZ[_`bcchfhhhddb`[WQMHD@950*# " fullword wide
		 $s36= "#$*.13:>@DFJLPSY]^`ehiolstwxz" fullword wide
		 $s37= "$#*+,1467=>?CEFJNLPTSXX[[^accfhellmrosquwtywy{|z~}~" fullword wide
		 $s38= "$'*.1489?@CDGKLQRQUXXXZ[Y[ZZWVSPKIE@>840.&!" fullword wide
		 $s39= "$(+-168:>@DFGMLQQUUXW[ZZYZYYUTSMMGE?>53.+%" fullword wide
		 $s40= "$)*/178=?DEJMQUU[^bdhioqrwx}~" fullword wide
		 $s41= "$+-18:@CGJNRUZZ`aegimoqqqtvsrppnkgd_URJG?93/'!" fullword wide
		 $s42= "$18CJQV[`degfgea_[VLG>7/$" fullword wide
		 $s43= "$&**212712*1375946.,-(4(2$9(4,.*" fullword wide
		 $s44= "$%&+,,-21678:=@BBCFFFEGDFDCBD?B;@36/.'%!" fullword wide
		 $s45= "#$!&%((,-./23258674530/,''%!" fullword wide
		 $s46= "$+,238;ABEIKPQUYZ__bcfdggfhedc]]YWPMHE>;6/,%" fullword wide
		 $s47= "$(,.238:=BAFGKLPQSVWYZ[ZZZXVUTOMHD@=63-,$ " fullword wide
		 $s48= "$*,238:?BFJKPRUXY^]`bcehfhhgeeb_^ZYSOJEA>51.%#" fullword wide
		 $s49= "#$)+2488;>>?>>A@CDHJOORRPPKEA90)!" fullword wide
		 $s50= "!!$&**,//2579;==?CCEDGGJIIIGEFEEB@>;:76200-(*$&!" fullword wide
		 $s51= "$().27??BAAADHKNPQOOHJDFEJLRV[`bilortx{" fullword wide
		 $s52= "$+28?EKQV[aa]YRNGD@;:568;=DLV_jt~" fullword wide
		 $s53= "$29GP[hov{|{zunjc[SMHFECKMV`jv" fullword wide
		 $s54= "$)2;?DHJPOPPNOLHHECBA>>@=ACEHLPUX[^dgghihfba]WNLDB43,' " fullword wide
		 $s55= "$)2;DHPUY]__`b__ZXRMF?7.%" fullword wide
		 $s56= "$320/1//1,.,,,-,.)-)*)('()'(''&&%$" fullword wide
		 $s57= "$&&'+++///3344746766745431--)('$ " fullword wide
		 $s58= "#$&,-348==BCFGIKLMLMKIHEB==62,&$" fullword wide
		 $s59= "$35125.200/-0//-,--,-*.-()(())($" fullword wide
		 $s60= "$'--35:=ABGJNOTWX_begknpry|" fullword wide
		 $s61= "$).36;>BIJLSTZ^cdghoporsrtssrqnljfaXTMHC;6/*&" fullword wide
		 $s62= "$&,/389AAGIMPSWZ]^abehilkmlmmjjiec_]WUMJC@85/+$" fullword wide
		 $s63= "$+38AHOX`lpz{|{wtnkhaYRG:/" fullword wide
		 $s64= "$,3;EJQX_dlmqtvwwxuupnpjgicecb`__[UTQNKD?=62.& " fullword wide
		 $s65= "$+4=AHKKJHD@97/+)&$%$&'*-0///-*(#" fullword wide
		 $s66= "$+4BTfotvxxwtmec[XVVSSTPLLJLPSUYaedfeecQI@6-" fullword wide
		 $s67= "$/4@FNSY_efjkligd^ZRNE:4) " fullword wide
		 $s68= "$+.5:=DFLNSSUXYZZVUUNKG@;1-$" fullword wide
		 $s69= "$-5=EJPRXY[]][YYRRJE>7/& " fullword wide
		 $s70= "$/5?EKRX^abc_^[UQME@?:99;:DKT]ht|" fullword wide
		 $s71= "$,5=FJTX[_bfcdc_XSNF@8.$" fullword wide
		 $s72= "$+5:>FLNTX^`dfijloqpttvwzx{z|y~z|yusnjc]ULC;3)" fullword wide
		 $s73= "$-5;?GIQSX^`bcfihmkqrsvuzutqkj__TREA83)$ " fullword wide
		 $s74= "$+6;DLOVX]_^`a^[ZUOJC;5+$" fullword wide
		 $s75= "$#+./6::E?LDOKPOQRQOOOLNOHQFPINDNEKHDCE@D;?2>+5()&" fullword wide
		 $s76= "!!$*.6=@GLSTWYVYTPKG?6/&!" fullword wide
		 $s77= "$-7=EMUY]`cefeda`ZVNI@;0'" fullword wide
		 $s78= "$+7@FMT]`cghhjfga]ZQLD=1+" fullword wide
		 $s79= "$/7@FMV[`cehgghda[WQJB91(" fullword wide
		 $s80= "$7KXage]YRMIEB?94/,.3;FSYac_ZM@4(" fullword wide
		 $s81= "$-8AISZbfjnnrqpnkh`[UKC:.%" fullword wide
		 $s82= "$-8>FKTX[`b`db`_UQLD>5-#" fullword wide
		 $s83= "$/8@GOUX^afdhed`^YSMF@9/$" fullword wide
		 $s84= "$/9CKPV[bbhgffeb`[TPG@70%" fullword wide
		 $s85= "$=c_X_Y[[[Y[UPDFIDEFDEFADBP" fullword wide
		 $s86= "$-:@LTZcejkkmkifeb^YYTVUTTWVYaccggfghb`[XOF@3*" fullword wide
		 $s87= "$/;MW][ZURPRU]^bb]UNGIMYiu" fullword wide
		 $s88= "/.$,*'(&/To^]e^_W]WVXVUUQQQVv" fullword wide
		 $s89= "!'-/0.0/.2248:>?BCEHMQW_gnw}" fullword wide
		 $s90= "0.*/-+-072'*+)((%)(&($$%$$#$% %#!%" fullword wide
		 $s91= "00DMVNMV0ZBjMVBVBNMDB9008809" fullword wide
		 $s92= "%),--))(&'%(*+.-0/1/0*)$!" fullword wide
		 $s93= "'+010--//47=FNTW[`_cfinswz" fullword wide
		 $s94= "!#&*)..011212179AGNQX[`_ffknsvzz}|}}~" fullword wide
		 $s95= "(+0120-/-036:>EJNQUWWUPIA7,$" fullword wide
		 $s96= "#(,-01247:==74/-()(,*.03:@GOQTTTPMKMMLNE@4/$!" fullword wide
		 $s97= "###%*(+-.-0-13//././--'(%'!!" fullword wide
		 $s98= "&(.01348=BGNXbcdb]XPF?7/(" fullword wide
		 $s99= "#!!%#(')-0-16456645421*($% " fullword wide
		 $s100= "%'*0198;ACFJLQSUYY_`beffkknqqsxuzw|}}" fullword wide
		 $s101= "!!#&%)).-/021030./-,*)&%##!!" fullword wide
		 $s102= "&'(+-.023499:;>=A@?ABA?@?=:8:61/,)(!" fullword wide
		 $s103= "!&#)*+0-2356767989:8;899653/.)&& !" fullword wide
		 $s104= "!@0/2-3>98GAGIGIvb_PY^b^bnj^Z]T[WN,C>aWYWYOPY_" fullword wide
		 $s105= "%%&++/024333403...-+))%%!!#! " fullword wide
		 $s106= "!!%'&*,.02658;;>>ABDCBEDEBBE@A==96651-/*'(%! " fullword wide
		 $s107= "#%&(**()'(&%'*+.0288=?>CCBFGHHJLMKLIGC>70*!" fullword wide
		 $s108= "%))028:;>@BADBE@C?==;851.+'$" fullword wide
		 $s109= "*!**-,/03134563470806.3-2+,)()$% !" fullword wide
		 $s110= "!%&(++032588:=?AEDHGKKPNQSUVVYYZ[^_`aaccdcefgdheiihhhihikjllkmqqrstyyz" fullword wide
		 $s111= "!%&-035598;==;>8:441/1,,**'&&" fullword wide
		 $s112= "(+-038;?ADGJMPSSX[[]^`aa`baa_^ZZWRQIHD@840,&" fullword wide
		 $s113= "&)-039:?CFGKMTSV[[]^aabecedcbb]]YWRNJFA>82.)#" fullword wide
		 $s114= "))/0449>@D?HOR]baioulrx~x~" fullword wide
		 $s115= "!#%)-0479@CCHINOUVY]bchklopruyz|~" fullword wide
		 $s116= "*0489=940..()++12>>BEDA>>?AADGMQUY^dgg`^XTRQMPSX^]^[YWTXVY_diptstqopplhhkms|" fullword wide
		 $s117= "%%04;AGKPTY]abffkjmjjjigd`^[VSOHDA;40+&!" fullword wide
		 $s118= "'*058>AFJJPPRTTRRNKIE=91*$" fullword wide
		 $s119= "!%).059:>CFILNSTXZ_`bbdhehegcca^ZXSOLFB>72/'!" fullword wide
		 $s120= "!%+05:=@DJLPRVVXYYYZZ[Y[ZZZZZYZZZXSSOPJFB>63-(#" fullword wide
		 $s121= "(05?GOVZ_ccfegfgiikkmnppormlgbSJ@5* " fullword wide
		 $s122= "+!+/&0'5*K>]PV_Qk>n*n+r9u;f-Y&O'=" fullword wide
		 $s123= "06/03/0///.-.,,--+,,*))(()*)'&(&'" fullword wide
		 $s124= "#(,069=CDJMOXX`efjpsvx}}" fullword wide
		 $s125= "(06>FIRS_chiooprqqroklhdb]VPLGB?85.)$!" fullword wide
		 $s126= "#,07999862438=ELVdcd`XMB0 " fullword wide
		 $s127= ")07;BFKQUWZ_`dgfilopquwwzz|}~~{yztomd^XME;1'" fullword wide
		 $s128= "#07@HPW_acdcc^ZUSPMKIHIIIJMNPQTUWXZ[[YXSQGB:/%" fullword wide
		 $s129= "!)07?HU^cgeec`^VTPQKF>:4(#!" fullword wide
		 $s130= ")08EOY_eba][Z[]``dimpoolkhfhkprtxxusmihggdgc_XQLFE@CEGILJLID;949ACDEDFJNV]^b`^`[XOI@5,&%%& !!!" fullword wide
		 $s131= "08FPYagkoptrpqomhb^TLC8/$" fullword wide
		 $s132= "#*08?GKPUWWYWVOMFB;71.*'%%&(,/5;@IPT^ehhjiec^YSJE;61)& " fullword wide
		 $s133= "&08>GKTZ_aebe`_WQLE=4,$" fullword wide
		 $s134= "(0-&(8KJ@79CSVQQU^c^WWdsqg_enux{~}}vx" fullword wide
		 $s135= "!(09ABIMPTTVVUTSQNMIJFDCEDDEGKMPUX^cflkmmklgc^YSKGB7/,%" fullword wide
		 $s136= "%09AIOU]^fehifgda[XSJB:1(" fullword wide
		 $s137= ")09>CDFHIHIHHIFFGHGHLKNMPMNIF?80' " fullword wide
		 $s138= "'0:CISW]behjihiea]VRGB91%" fullword wide
		 $s139= "&'*''%()0:GPYZXXTSNGFEGLONMHD=;9:9464:==>?@CGJJFA94*" fullword wide
		 $s140= ")0>GQ[agqvyz|yytqlbTL@9,#" fullword wide
		 $s141= "##'')+++-.///1/.,/,/+*),+(*))&(%#!" fullword wide
		 $s142= "1/+0+..-*-,,*,+')&*')(&(&%$%#$$$%$" fullword wide
		 $s143= "!#%),1047::>CAEHGJNLONQPPRQQONKIHE@A;740+)!" fullword wide
		 $s144= "'',1056:89:;;:;:88775444242532//.//++*'%#" fullword wide
		 $s145= ":'1079'2-[=CVQWR=[FIPH_ZVQYUlSnjf" fullword wide
		 $s146= "+'1089;ECLMVX_`ehimkskqmgm^eYYOSIHC>74.+'$#" fullword wide
		 $s147= "!#).-//1/10/248?BJPV[_`b`]XTKB:/'" fullword wide
		 $s148= "&+1132.-*,-/39?AGHJGJHJLKMPNOIE@8/'" fullword wide
		 $s149= "1:1430231/0//.,.+-,,,.-()('*'))(" fullword wide
		 $s150= "!#&(,/11657;=?BBCEGIHIJLGJIGGGBA@>974/,(% " fullword wide
		 $s151= "#%),1168;;A?BADCCA@=;842+(!" fullword wide
		 $s152= "*,123/*(*,.-35;DEJMTWZZ]ZZYXUWZWZ[_hmpqmhmt" fullword wide
		 $s153= ".1.-3-.--,-,,**+)+)**))(%" fullword wide
		 $s154= "!'+13777966600,()%&$()-17>ENXanx" fullword wide
		 $s155= "'+.137;=@BDIMQRZWYXSUNLHC@:9310+*'#!" fullword wide
		 $s156= "!%,13:ADHKPU[]_ehknsuw|}~" fullword wide
		 $s157= "&**13:;@BFKMRRW[`degnprux||" fullword wide
		 $s158= "!&'*.-14667867856422-,*(&# " fullword wide
		 $s159= "#'*/157:?AEEJLMPSVVZYZ]]^[^\\XYWRPMJDC>:40+' " fullword wide
		 $s160= "!!'*-/1589:@AAEIIJMKNPPQPQPPMNKJFDB=:63.+%!" fullword wide
		 $s161= "+15@HMR[_dikpoqnqolkkjjfhcdbaa_][WVPPHEA=:1/+%" fullword wide
		 $s162= "#++.165;=?BFHILORTVVVZX[Z[YZXVURNLGCA;62/)%" fullword wide
		 $s163= "%,169@DHMQRYY_aeglmpsuw}~" fullword wide
		 $s164= "'+16:ADHLPV[^cfhmostv|{~" fullword wide
		 $s165= "!&,16;AEIMRUX[_^bbac`_YUOKD?61(" fullword wide
		 $s166= "%*+16:>CDKKOQUSUVVXWXXWZZW\\]^^][Z[XURQNJDB;62,(#" fullword wide
		 $s167= "#).16;>CIMOVZ[cdgknpswy~~" fullword wide
		 $s168= "!'+16;@DKLPVOQZUSRMNHCA::12,**%*&,,33?>MNZ`kq{" fullword wide
		 $s169= "+/+,175545467;?8896685663440+#" fullword wide
		 $s170= "&'-/175>>BEEGDIJINKPLSSSPXUVQNQHMBD?;70.)'" fullword wide
		 $s171= "%+*176A>HGQMWW]`ggmmkqhrfmel`e`T^NPGCE8?370.(& " fullword wide
		 $s172= "!'+179>CHIJONNPPLLHE@;4/(#" fullword wide
		 $s173= "#&+-179=?CHJMQTWZ`aegkqpvyz" fullword wide
		 $s174= "#17DITYbehmnonnkhc_XQJ>9*$" fullword wide
		 $s175= "%(*+**--17;>EGJHIIGFCA?>951)!" fullword wide
		 $s176= "(18BIRW[_bfffgea_XTLF>5-%" fullword wide
		 $s177= "'18CKPW^cciglhfea[WQJC71'" fullword wide
		 $s178= "'-18>@FKMOOPQQQMKHE>:4-&" fullword wide
		 $s179= "&1#**&)'8fr_fj_c^^b\\YWXWT_" fullword wide
		 $s180= "(18@GOSX^addggcd^_ZVSMLJFHFGHLORVaelqv{" fullword wide
		 $s181= "!#'*18?HOVbehhihcc_YWQNF?8/$" fullword wide
		 $s182= "%19CMTdhmpqsvsnmia]SME:0#" fullword wide
		 $s183= "!*19DJQW[_dgfffd`ZQLC>3*#" fullword wide
		 $s184= "(19>EJMQTTTUSQPQNPNNHA=2'" fullword wide
		 $s185= "#!*+19;@FLNRRYY]]]a`Z`]X]WYYRTNQOLMHLIFDH>C9?54)1 #" fullword wide
		 $s186= "(19@HMTZZ_aeba^_WUPFD71*!" fullword wide
		 $s187= "(19?INTY`_becc`^YUQID=3)#" fullword wide
		 $s188= ")1;BHOT[]`acc``WSNG?9/(" fullword wide
		 $s189= "&1>BJMPPQMIFFFGFGILSVWRI@942138CPYVTMIEA>7/* " fullword wide
		 $s190= "(1;BJSW[`dggghdb^YTMG>6+$" fullword wide
		 $s191= "1C76BOaT_TWXUVTRVSRRIUxynvr" fullword wide
		 $s192= "*1:CHQRY_a`e__`^]ZWVURPPOMOQQTY]_ejmpsxxzytpmg^[PJA:.)!" fullword wide
		 $s193= "*.1DAO[Vdagfc`^YZJOC;=/4.,)+)+#)" fullword wide
		 $s194= "!*1;DIQX[^afdeeb][XNLD:4) " fullword wide
		 $s195= "!*1:?DKPUY]acdiimmnnprrtsvvxxyy{{wxvroif_YQG>6*" fullword wide
		 $s196= "'1?@ELDA:293471644I[RQVORTO[`\\YeS'(3$)+$*$" fullword wide
		 $s197= ")1=FKU`ejklmnkhf_YTKE;1)" fullword wide
		 $s198= "!&1:@FQUbgmmquwwywwvspolfc^ZSPJE>84.($" fullword wide
		 $s199= "1@R[gmnttuqndgc]ZWPLFB;2*" fullword wide
		 $s200= "1SALRBRO(+==A;/93#8IAQ`SSVA;B)" fullword wide
		 $s201= "((!%,%20.:/825;=B?HI?YNZWQVBNZNRNJEKNB??aPP" fullword wide
		 $s202= "!#&&(),-/./2122/02.0.,-.*+.(+))$)##" fullword wide
		 $s203= "!.2--2-,..,,*-)+++*),)()'&'&" fullword wide
		 $s204= "%&+-.224899;?=AADEGJJKPNPQRPQPONKKJHB@>=:53-.)$#" fullword wide
		 $s205= "))2255221177AAEE77,,++**''$$" fullword wide
		 $s206= "22B;TNUVd_eblpjiwnunynunxslwnlonqlgv_x]nbi[]OUEF;54" fullword wide
		 $s207= "#%+22:=>EDHOOV]dgeqllviwiqihhg]cZ[YTVNRNILFI?G8=712)$%" fullword wide
		 $s208= "#)*247;=BEFJNPSXW]^cbfdgfgdfc``[YWRMHE>;3/+%" fullword wide
		 $s209= "%)+249;ABIJKQRTTXUXZY^]_^^__`ZaYUVTNPIIE?>79.*'" fullword wide
		 $s210= "!(.24:@EEKNTV[[`bfhkopptswuusurtnkkfcXVMGC:70*$" fullword wide
		 $s211= "#%&'+.24;?ELRX]befgiijijlkoonnjibXPHA=82.*'$" fullword wide
		 $s212= "%.-.24>IE@>AIQYbgjkhmpsunjgimlnlnqutsrs" fullword wide
		 $s213= "*/256554567;@DKQW^behhghcc`YXVTRQPOQNOMNMIHFB;941--,/37=DJNX_dfeeaWOG=1%" fullword wide
		 $s214= "#(.2567762332326499:=>?DFNT^ht" fullword wide
		 $s215= "#!&.+2579=@BJHQQXUWYXVXRUPNLKFEA@@7;530.+&#!" fullword wide
		 $s216= "!&)-/2589==ADFGJKMMQQRRTRTSRPMKLGGB@;931+(#" fullword wide
		 $s217= "#&).259=ACFHJOOORPQPPNJJFB=94.(!" fullword wide
		 $s218= "%*259@FINRUWZ^a`a`__WROG@;1*#" fullword wide
		 $s219= "!(-25:@BFJNQWY[affkmqqvw{" fullword wide
		 $s220= "!&-25:?DGKNTV[`fgklppsvuyxvxvvuqomjcb[VPKF?:1/%!" fullword wide
		 $s221= "%-25?@FLPNQORQMMFE@;;6625579AFRXajtz" fullword wide
		 $s222= "++*268;:D@>N?QBUAVIRMRQTNUTTSUOWJUMTKMHK>H:;5/-&" fullword wide
		 $s223= "%+.26:>CDIJLPQQRSSQQNKHDA85.' " fullword wide
		 $s224= "%,27BDKQU[bahhlmkplkkhhedccb``_][XWRQKGB@:720*(#" fullword wide
		 $s225= "!%(-27;@BHJLKNJJHB=;40+'#" fullword wide
		 $s226= "%2,**!7EMJDAF54/TZEIRdJCMYHA3$" fullword wide
		 $s227= "#)27@FJNTWYYZZZVSQKG=91* " fullword wide
		 $s228= "#%*27?GNUZ``dbb`_YWRLHB84*#" fullword wide
		 $s229= "!'28=FMNQQPNLJHJHIKKMMNLJJFD>=72+# " fullword wide
		 $s230= ")29AIMSV[\\][XVWUTTQNF>6)" fullword wide
		 $s231= "&29AKQX[adfhihgca[WNH@7/%" fullword wide
		 $s232= "%29COQW]_^`dcchlno{z|y}tmiYOB/$" fullword wide
		 $s233= "(-29=DLT_ffa]VVVY[^][XVURSSWUUQLC;.%" fullword wide
		 $s234= "(2:AKOX^cjmruv{z{xztrnic_[TRJIDBB??@ADDIJQQVY^beggiifc^YPH>1&" fullword wide
		 $s235= "&2CNSW`dfhjffjgnjplllmdd_VL>/" fullword wide
		 $s236= "*2=DLRX_fglnpmnlg_YRK?7-$" fullword wide
		 $s237= "'2>DMTbgkomqnmmgc^XOG@6," fullword wide
		 $s238= ")2=DNW[cgkloonlljjgca_^^^]`bglpw{" fullword wide
		 $s239= "#*2:?FLPTWZY[[YVROJE?90(!" fullword wide
		 $s240= "%2:FQX^glruwyxytrli_ZPG?2'" fullword wide
		 $s241= "2/!?grbgidcb]``[]XXXWXUQXz" fullword wide
		 $s242= "3%=0E8CA:J2O3N>LKKWG`8e&f" fullword wide
		 $s243= "-3#0Qjj`ec_c^`_YYXWTUWSRUt" fullword wide
		 $s244= "!,31/3...//.*-+.*,*,,++&!" fullword wide
		 $s245= "#(),-325::@?CDHHKJMOONQRSNQNMIHHDA=:62.)&!" fullword wide
		 $s246= "#*/3468:==BEGIOORTUUWUVTSPNKKFGD@?:5.'" fullword wide
		 $s247= "34;@DDAAB@A?=C;:EQNFNLIJGHIE#" fullword wide
		 $s248= "&*.3598;::88640--*($&%&$&&'%))-,-..0-+)(%$#" fullword wide
		 $s249= "#%(,./369;>@BDFIHJMNPNRQPOQNLKJHDC@9910,'# " fullword wide
		 $s250= "!'*.36;?ADFFKIIFFE@@=9732./,((('%'$'('''&'%$!!" fullword wide
		 $s251= "#(,.36:=>FEKMPTW[[adhkoqqwx~" fullword wide
		 $s252= "&+-.377?>BEGIKLPSTVYXZY[[ZZXWVTPMKGC@:50-'$ " fullword wide
		 $s253= "+39ACKKNNPSOQRRRSSUVXXY[[^`b`deffhhjhighhbe_XULHC;5/(!" fullword wide
		 $s254= "#(39BJPY^cfhhfeb[XPKC@841/0.148>DJRX_fmprvwvrpjd]VOH>92-(#$!" fullword wide
		 $s255= "3'&>>9=DALjwjktjpniogijimf^aW." fullword wide
		 $s256= "!)39DKPRUSQRPNOQSTY_`fffd]YNC8.$" fullword wide
		 $s257= "%+39=@KNSWY_addfhjljkhgheeefbaaa_ZZWVSQLIG@>:3..$" fullword wide
		 $s258= "'.3;AK[hryvl^OD:2437@IWbo|" fullword wide
		 $s259= "#*3:CELNPOQONKLKILJONRQRSPPPJICA;91.+#" fullword wide
		 $s260= "+3=DJgp`hhajeegaeddd`_YWYVJ(" fullword wide
		 $s261= "%-3;EKUY^bbdbcca]XSLE>6/)$" fullword wide
		 $s262= "!,3?ENUZbdghljjge_[TNG?6-#" fullword wide
		 $s263= "%-3>GOY^glqpplgb^URHDB=:;>DJT^ht" fullword wide
		 $s264= "#3=HOY`fkptxwvtnj`[QMF?;62+(!" fullword wide
		 $s265= "'3>HRYahpsx||{~}{{|yyurqolkifegehljptu{~" fullword wide
		 $s266= "/4+/00/.-0*--,-*-*'((*()(')''%#$%#" fullword wide
		 $s267= "%(//423320//-,,+-/,-10558;=>BDGHKHMLJNLKKHDD@=630.'!" fullword wide
		 $s268= "!'-.4455575676585787:8::;962/)$" fullword wide
		 $s269= "&-45841)%$$&,37=@?@=8:8789;;:94300**'$" fullword wide
		 $s270= "#'.-459:>AAGGIJLNMORORRURZTSVRTNONGEA?:00-'#" fullword wide
		 $s271= "!(+.469:85225;?CA@?=:724/.),,1668;:955797451310+'$" fullword wide
		 $s272= "%-/47;ADHLMTVYabghlmnrrqrtsqrolkfa_YUNIE>72-$ " fullword wide
		 $s273= "'.47=?@B@@;>==CIMSZYXRSQX`mt|" fullword wide
		 $s274= "! *,47:DDLPQVZ_^^cb`e]c^bY_Z[W[SUQSKSFOBL@K?C:>68-.&!!" fullword wide
		 $s275= "!(*./48;@FETI_Sdebhfjglelbi`_XZROLIEE>A7=-3('$" fullword wide
		 $s276= "'/4;@??A@?>AAABDCC@CBCHKSZaksx" fullword wide
		 $s277= "%'./4:=ACGJLNQQQRPQOMKGE?=60*%" fullword wide
		 $s278= "(4ANU]_cccecbb`^^][]``cfiljkjb_UKA5'" fullword wide
		 $s279= "&.4:BGJQTXZ`_dehhiljllolnlmnlmlmmlihhc]XSIA8.%" fullword wide
		 $s280= "%-4:BGNQY`ggklonolhgbYTQMJHFCBFFDHKKOQSWY]`bfigkjkge_XTJA5+" fullword wide
		 $s281= "%.4>BKNTUWYWTRPOMNOOSVVZ[[YWTSOJC>6/(" fullword wide
		 $s282= "4C%3%C-35C5#-+-3%3.09798_QO9GIH?9>B?" fullword wide
		 $s283= "%.4?CKQV_bgkprrwwwzyuvsrokee`[UQKGB;60+%!" fullword wide
		 $s284= "'.4;CKTYbgmrx{y~|{{ztuqoijdfd`a`]^ZYSQOKD@=31*'" fullword wide
		 $s285= "&-4@DIRUXZ]\\ZYZVSSQNKJJKHMNQSX[aefmpqsttrrlg`ZVJG?8.*$" fullword wide
		 $s286= "*4;DJRW_edefeb_[WRKC>2+!" fullword wide
		 $s287= ",4;DKQ[blrwy|ytqojecUNB5(" fullword wide
		 $s288= "!,4>DKRX^``fffda_[VOIB90)" fullword wide
		 $s289= "!*4;DLQW[`ddffec_WQID=2+" fullword wide
		 $s290= "%,4>DOSYbccfefedd__ZZXVVORPQRVYWafjlqzvzywvtnh`WQJA6/&!" fullword wide
		 $s291= "!*4=ELRY_`efifgfb][SLE>5+#" fullword wide
		 $s292= "*4?ENVY_begihigffcd`a`]^[YXYWUXUUTSSSOONNKIGDA;73*'" fullword wide
		 $s293= "%-4?FMSW_adfeef``ZTOG@80$" fullword wide
		 $s294= ")4:GMYbkoswyxwxvrmf_VME;6-%" fullword wide
		 $s295= "*4=GNUZ^efhhfgc_]VQLD;5+!" fullword wide
		 $s296= "+4?GRX^djkqrqookic]WMG=3*" fullword wide
		 $s297= "&.4=@IMQTZ]^`egijkmmolopqrqssuwutqplgf`URJE=5*$" fullword wide
		 $s298= "!-4?JR]dnqwyxxzxvtmfVMD:5+#" fullword wide
		 $s299= "*4=KPZ`gmosvutunngcRLB8- " fullword wide
		 $s300= "'4@KS^dlpux|||z{ytni_UNC5*" fullword wide
		 $s301= "4wlaseijagaa`_^]Y[XXXWTUSS}" fullword wide
		 $s302= "%)..548799787641/.,,,+)**)+)+.+,--,+-++&%$#" fullword wide
		 $s303= "&)55ABKNXUd_jgoovrwxwv{r}o{oqrkpcl`d`]VYQPIJAB6;1++" fullword wide
		 $s304= "!!))++))55CCEEFFJJRRXX__ll}}" fullword wide
		 $s305= "56735;>CIQW_gipqppmhc[OG:1&" fullword wide
		 $s306= "!'-/57:BCFJLNMPQPRRPSTSUVUVYXYZYYTWUQPKJBB;;30+% " fullword wide
		 $s307= "#%,/57=?EIJPTVY]adgiklqoqrrvrrrpljgc^ZTOKD?93+'" fullword wide
		 $s308= "!&(-58>ENSdiovx}}|zwrleb][Y^ciqx" fullword wide
		 $s309= "!%*.5:?ACGGJJJMLNORMMF=4&" fullword wide
		 $s310= "''&(+5==?AGNQYZddrgikwws{" fullword wide
		 $s311= "&(/5;BEHQSV][`_ffcheifgeeffdfc_aa``Y[YXUQMKJD@:8-- " fullword wide
		 $s312= "!+5>BKOWZ``baa`]^][[UQJ?3(" fullword wide
		 $s313= "+5::>BKV`hgc[SNONPMJ>6+(%%(%$" fullword wide
		 $s314= "%)/5=@DHMPSXZ_afhikkgea[VNLD@=885465858898965510.,*)'%##! " fullword wide
		 $s315= "+5;DLSW[_cdefd`][SQHA:2)" fullword wide
		 $s316= "%5DR[djmnnmolkjhfeeedhjlttuxusld[OB5&" fullword wide
		 $s317= "&-5:EJPX_filtvttxuvsrqpllkjghecea``YYUSOIGA;64.'#" fullword wide
		 $s318= "#-5=EKOWZ]^bbb_^ZUQID;7+#" fullword wide
		 $s319= "%-5?FMPY``cdec_XSMF?6-%" fullword wide
		 $s320= "#&&))+++*,+*+)*-./5:@GLS[`diimnlmihca[XPJD:0)" fullword wide
		 $s321= "+5?GOVagjlmpmmhf_ZRMB92(" fullword wide
		 $s322= "%-5=HP[ahmuuxyvsohc]WOIE?::9:;@EKSZcjrw" fullword wide
		 $s323= "(5?HPUVX[Y[ZYYVXUVVWXZ^aab_XOG>4(" fullword wide
		 $s324= "%,5?ISZ`glovxz|yusmf_VJ>3& " fullword wide
		 $s325= "&5>JTWY`]_a`X_^_XYRNJA9. " fullword wide
		 $s326= "/61CEOHR[X]]o_jhkmkjriilcohijboiekhfk[n[h[XZMTEK6@'2" fullword wide
		 $s327= "%*.67?BFKPSW[achimoswv}|~~" fullword wide
		 $s328= "#>67>FECBDCJOPPQSQNPNHFGECDCC@8334+" fullword wide
		 $s329= "&-68>??BBCCDFHLNTW[[_`bbcaaa__]YUNIB9/)" fullword wide
		 $s330= "69.79.6115.23/10..1-..*/(" fullword wide
		 $s331= "'/69AFMOT[]_bechgfdfa`^YUTNLDB>72,)%" fullword wide
		 $s332= "+6>AEHKJIEC==@BIJNROOQRSRRIF@::;;BGKRVX[^cfdbUG0" fullword wide
		 $s333= "+6AJUZcinptwxutrlhbZRJ>8)" fullword wide
		 $s334= ",6BLRWZ[`^_^^]^_[cYZYWPKD5-" fullword wide
		 $s335= ",6CMW^emtwy}|}yytngaXPD:/%" fullword wide
		 $s336= "!&+6=DGJIIHOUZ_aefefgd_]YSOLNQW]__aagjotvwwurqmhd][[[ehrsy}~" fullword wide
		 $s337= "!(.6>DINUY_dgeijlilkgihfeeed`aa_[^YWWOPJID=?62.*#" fullword wide
		 $s338= "#+6>DMRV]_bdddba^YTNHA61'" fullword wide
		 $s339= "%,6>EKRX`_cbb_^ZWQLC>5+$" fullword wide
		 $s340= "6ESclrux{yzwutrnmmkkopvz{" fullword wide
		 $s341= "#).6?FLPWVYX[YWUUNHB=6.+%" fullword wide
		 $s342= "#.6?FMTUXVTRPLHED??=;8932-*%#" fullword wide
		 $s343= "&,6@FOTZ_befggfcbVOJC:/)" fullword wide
		 $s344= "%6GRX_``[XQOLMMRY^eikkhd_VRROPTZdq~" fullword wide
		 $s345= "(6GUSWh^aYd^bb]_]YVSSROQI?5#" fullword wide
		 $s346= "-6@HOUZahmnqsronigbb]WQE>0!" fullword wide
		 $s347= "+6?KRchotuxyxxsqke]VMC:-%" fullword wide
		 $s348= "@6Opihihigcdeabc^H+13.,DpM>XHFTHCQEKJB" fullword wide
		 $s349= "7&#2%)*#'&#&6_t_bk]ba^^[^YV_" fullword wide
		 $s350= ",754C@;A=@BGOLJMJHEAD@?B?=>>71/0.-!" fullword wide
		 $s351= "&/7=;634>IR]eieaYUX^cipuuollx" fullword wide
		 $s352= "# ++77??HEOJXP]Z^gaphxnwuturosem`jZbV[WQPTHOIEFAC;?+8))$" fullword wide
		 $s353= "! *.78BDFQKYR]^cbkhqout|p~uxrukngb`^VNZJSIMEFF;B662-(%" fullword wide
		 $s354= "!-.78>DLMOT`[eaihkkqwnztzyxvvpufm]d[VVNSGKJDEF6H09-0%%" fullword wide
		 $s355= "+/7AEMTW]^ZURMED=860316:AIP]gt" fullword wide
		 $s356= "!-7>DFJKLNLLMLKKJJKKLNQSRTRPLHB92'" fullword wide
		 $s357= "*7=DPRWWYX]XX^`a_aad]gXVJ>3$" fullword wide
		 $s358= "%-7>EMQWZ`eghgge_a[[WRME=1%" fullword wide
		 $s359= "#/7=FIOUWZ]_[YURLE>92' " fullword wide
		 $s360= "&-7>FJSWWZ^^^_[YVWRRMOJLHLJOOPWYbdjmrsqtroldbYSJC;5-%" fullword wide
		 $s361= "%/7@GPV`fjjkljge_[TMD?4+" fullword wide
		 $s362= "#/7>HLT[^ehjjihba`[YUOF=3(" fullword wide
		 $s363= "%.7@HNU[acgghied`^YQKB:1( " fullword wide
		 $s364= ".>85979846675563:EGRlkiwqnrjni`e" fullword wide
		 $s365= ">=@=;:865533210./.03:=CGLNHE>4)" fullword wide
		 $s366= "8=8C8J@MJMRPTSPTHQBC?27''" fullword wide
		 $s367= "))88DDJJQQZZ``ffggeeZZHH22" fullword wide
		 $s368= "::88:>IObhgfgdda^YULGFGIPNSTWVTPLD;0(!" fullword wide
		 $s369= "&/8ALT[chnsvy}||}yxsqoieb_ZYTUVVYX]dclnuz" fullword wide
		 $s370= "8>?BCDGKHNMQQOUSWRUVTYVXUVTONLFD==7.(( " fullword wide
		 $s371= "*+8:BMNVYe_lhlgollhojfhhgicgbdaaa]XUWJPA:6,#" fullword wide
		 $s372= "8D48@4::58557435346Qqjbjdfmlljjgdz" fullword wide
		 $s373= "%/8DLU_dlowvy{|ywvtomhec^^XWVQPLJHGCAB=?:;97613.+&$" fullword wide
		 $s374= ")/8=DMPUX]]^^_YYUPKE>70) " fullword wide
		 $s375= "!/8DMW_gnsx{z~zzurnf]WMC:,!" fullword wide
		 $s376= "8EDIMJKFGIQPUNRMXOUQVZZYTTSU[VUWKXFZDMHKSHHK?J@JDB?:.-(()*7.-(" fullword wide
		 $s377= "'/8=EKPRWXZ[]^^`cceedefecc`^[UQME@92-$" fullword wide
		 $s378= "!)/8?EQT[^^`]__][WQKE>50+#" fullword wide
		 $s379= "#*8>KQ^ehpornlebZUQJFFCEEKPZdp|" fullword wide
		 $s380= "946012067?GRXdhjmjghedilnv|" fullword wide
		 $s381= "*'(97@8@@YOXa_hqoxru{}zwpyns]b^RNC52/0(!" fullword wide
		 $s382= "9:8.,6Qix|~ywtrmaZTPQYbiqiM*" fullword wide
		 $s383= "&.9AIRU`ehhigee_]VOHB90%" fullword wide
		 $s384= "9B08B9DD9)))0V8r)Z)ZMVN8M" fullword wide
		 $s385= "'/9CMWbjqv{z}{|yyulf]UKB94)#" fullword wide
		 $s386= "#/9DLV_ekoruuxvsrngaYPG>3*" fullword wide
		 $s387= "'/9@EMUW[`aedcb^YWRJD=3,#" fullword wide
		 $s388= "9_E@W>LL@JCDFAEB@@B=>>==;>:7;9:6F" fullword wide
		 $s389= "#-9@HNSX[^bdgiknpstttsrpnljfb_ZTLE=3)" fullword wide
		 $s390= "&9IV_gmnrssnligc`]]VQJB=0%" fullword wide
		 $s391= "%/9@JOV[^cgifghc`ZVPIA:/&" fullword wide
		 $s392= ">=A>>=:574/.,+*+**/1049;@EFJKMLMIHDA;92.)%" fullword wide
		 $s393= ";A9;?8:8:8979575774532210@{" fullword wide
		 $s394= "#/?A?:9?EJLPVZYZZ^bccilnmnpx{{|~" fullword wide
		 $s395= "?@@A@A@@A@>AAABAFDGEFA?;5.&" fullword wide
		 $s396= "^`^^]^_]aa``ab``a`_aa__^_]__]_][ZYZXYYVWVRTSOPOMMLKEIGDACA>?;:857221-+*(&!#" fullword wide
		 $s397= "A@@=@AAGFJGGA@?>EDDGGEEDBERYXSKEBLIYPEFC=97=I9/*)'(+0#" fullword wide
		 $s398= ">=?@ABAABCDDDEFEGEHHHJKKKNNQPRUUXWYY]__cbefjkmmnosrvwuxxz|{}" fullword wide
		 $s399= "=ABCBDGHIMMOQPSTRVRSRPQLIHDCA>;63/.)% " fullword wide
		 $s400= "ABEEGIKLMMONONNNLJIGCC?:750,'%" fullword wide
		 $s401= "A@CBDEHGGKJMLNRQSUVUWVXUUQRNKKFCA>55/.*$ " fullword wide
		 $s402= "ACILNQPSUTVUWWUWWWVYWXZ[YWYXUURQLJDA;73.*% " fullword wide
		 $s403= "===@@ADEFGJLKNNMPNQONNMLIED?;61+$" fullword wide
		 $s404= "A@DFHIKLMONPROQONMLJHD@?:74-,%! " fullword wide
		 $s405= "ADJNOSVYZ^^_^_^`]^^_Z]^\\ZY[WWVRPPIG@?83.(!" fullword wide
		 $s406= "=AEFINNRQSQQTTWWZ]aekqu|~" fullword wide
		 $s407= "AEHLMMMKLLNPSRRNOLMMNRRPQLKGC;71(#" fullword wide
		 $s408= ">AEIJLSUVZ[__bcdeifghdcaaXUSLID@851)%" fullword wide
		 $s409= "AHKPMMD;1+$$&,39BHILOSTZ^^[YZ[^chigaXPF?54/-./3369;8/&" fullword wide
		 $s410= "Allgemeines Graustufen-Profil" fullword wide
		 $s411= "ALOSTTUX]bgjjnllhge`YQIEA:9=AELOSPPH@0&" fullword wide
		 $s412= "APILKGPXXTSVVYZVXVSQJNKJLIE;8:(" fullword wide
		 $s413= "aZk`f[_Y^]X^XYYWXWVVVUVRQSRQRRQP:" fullword wide
		 $s414= "B!:$4)-9>BF9>090>30>0>4/!" fullword wide
		 $s415= "(B95=58:;FPQTTQUQQONP[xzknojkp" fullword wide
		 $s416= "=BA>EAKCFJEHHCLAHFI9O3H2D+=&6" fullword wide
		 $s417= "++BB``vvzzttkkddiitt{{wwvv" fullword wide
		 $s418= ">BCEGIMKOPRTTUSVTSSOPLJIDB?;820+%#" fullword wide
		 $s419= "?BCEHEFC?>98310-,(*(&'&$!" fullword wide
		 $s420= "B?@DDEGHFLJOPQQSVUSVSQQPMJHEB=?75..,$!" fullword wide
		 $s421= "BECAACDDICCBUVPLITQUNRIKKEJCSVcXIFI_acOA*-" fullword wide
		 $s422= "@BEGIMNSSUVYX[Z[ZZ[VUTPMHFA>851+'!" fullword wide
		 $s423= "BEIMRUWZ]bdfimmoqsrrvptookhha]YRLHB=60)$" fullword wide
		 $s424= "BEKMVX^a]cYcVaO^L^PbSfUiUjPfKcPhZsd" fullword wide
		 $s425= "BeUV`RVYPVOQRKPNKLJIIIFHCFDE@BS" fullword wide
		 $s426= "?BGFILNOSWZ[[[UTLHA84-% " fullword wide
		 $s427= "BGPSY_`fgkkoomnnnlkjlgefhfdaa]^WUSRJGC@>93-)%" fullword wide
		 $s428= ";!B)I1N8R>XE]L`QcVe[h_kdohsmwrzv}y" fullword wide
		 $s429= "&/;BIQX_dfihgfe`[UQG@90%" fullword wide
		 $s430= "'.:BJV`jmptuywxtvvroollhfeccba`dfgmosu}" fullword wide
		 $s431= "BOSSMHF:7AEV_qzzrgcfcUSTY^gr}~{spkf_UWZb^akeW;$" fullword wide
		 $s432= "?BPgZYaX[^UZXUWTTRRMAELc}yo" fullword wide
		 $s433= "*%C69(/9`>D;ED:@797Q7A'1." fullword wide
		 $s434= ">CAHGIJIMOLONMTNMNIEDC=:931,+!!" fullword wide
		 $s435= "!Canon MX420 series _A8C5D468F692" fullword wide
		 $s436= "@CBEGKMLQSUVYY[_]bdddgiiknmrpprquuvwywyy|z{|}~~" fullword wide
		 $s437= ">CBGFHMMMOOOSQPOQMLHGDB@:75/,&#" fullword wide
		 $s438= "CBQJSXY`abjdnoksqusvwxyuxsprhia]YTQOHGCE>B6@37,-&$" fullword wide
		 $s439= "=?@CCCDEFCEECBB?>;9520-(&!" fullword wide
		 $s440= "CCILOSW]_chilnppstrutrsomkhc`VRKHA;6/)#" fullword wide
		 $s441= "=CDHJMOQQSUVQVTNLIHC=;83/*&" fullword wide
		 $s442= "=?CGIMNPQQNNNJIEFDBAA:93.%!" fullword wide
		 $s443= "CJQWdejlrsqtsrppnnknkgghfcfda^]XXVNMGB>;61+(" fullword wide
		 $s444= "CKSX]aciffgffdbb^]YYVTSSSUSWZ]ddlnryzz|}{wnlg^VIF81( " fullword wide
		 $s445= "com.acridjute.sefiecamera" fullword wide
		 $s446= "com.acridjute.unitconverter" fullword wide
		 $s447= "com_adobe_image_promo_image" fullword wide
		 $s448= "com.aecenraw.emojionphoto" fullword wide
		 $s449= "com.aecenraw.workoutsevenminutes" fullword wide
		 $s450= "com.albumpro.videoslide.galleryphoto" fullword wide
		 $s451= "com.allinone.screenonoffpro" fullword wide
		 $s452= "com.appative.antitheftalarm" fullword wide
		 $s453= "com.appativesh.masterclean" fullword wide
		 $s454= "com.appgpfaq.prankcrackscreen" fullword wide
		 $s455= "com.appideaaz.sleep.alarmclock" fullword wide
		 $s456= "com.appovidik.emojikeyboard" fullword wide
		 $s457= "com.autolockscreen.taptap.lock" fullword wide
		 $s458= "com.autolockscreen.taptaplock" fullword wide
		 $s459= "com.azurersweet.app2sdandremover" fullword wide
		 $s460= "com.azurersweet.beautymakeup" fullword wide
		 $s461= "com.azurersweet.djvirtual" fullword wide
		 $s462= "com.azurer.vpnproxy.supervpn" fullword wide
		 $s463= "com.beautycamera.photoeditor.makeup" fullword wide
		 $s464= "com.beifymobile.cpucoolermaster" fullword wide
		 $s465= "com.billowy.equalizer.bassbooster" fullword wide
		 $s466= "com.calculator.hidephoto.galleryvault" fullword wide
		 $s467= "com.cleaner.memorybooster.ramoptimizer" fullword wide
		 $s468= "com.collagepro.cutpaste.photoeditor" fullword wide
		 $s469= "com.convertmp3.videoconverter" fullword wide
		 $s470= "com.coramobile.phonecooler.cpucoolermaster" fullword wide
		 $s471= "com.coramobile.powerbattery.batterysaver" fullword wide
		 $s472= "com.coramobile.security.antivirus" fullword wide
		 $s473= "com.coramobile.speedbooster.cleaner" fullword wide
		 $s474= "com.efflicnetwork.ringtonecutter" fullword wide
		 $s475= "com.equalizer.volumebooster" fullword wide
		 $s476= "com.fancyrunes.motorracing" fullword wide
		 $s477= "com.fancyrunesteams.hillracing" fullword wide
		 $s478= "com.fastestnetwork.freevpn.vpn" fullword wide
		 $s479= "com.fattys.automaticcallrecording" fullword wide
		 $s480= "com.fattystudio.convertertomp3" fullword wide
		 $s481= "com.fattystudioringtone.mp3cutter" fullword wide
		 $s482= "com.fearsome.fastcameragif" fullword wide
		 $s483= "com.fearsome.screenfilter" fullword wide
		 $s484= "com.fluidcrambo.horseracing" fullword wide
		 $s485= "com.forecast.weatherlive.weather" fullword wide
		 $s486= "com.fourvideo.videoshow.videoslide" fullword wide
		 $s487= "com.funnyvoice.voicechanger.soundeffects" fullword wide
		 $s488= "com.galaxygame.fighterwar" fullword wide
		 $s489= "com.gilonibasila.periodtracker" fullword wide
		 $s490= "com.gilonibasila.slowvideo" fullword wide
		 $s491= "com.gilonibasila.voicechanger" fullword wide
		 $s492= "com.gilonibasila.volumebooster" fullword wide
		 $s493= "com.gpsonline.phonetracker" fullword wide
		 $s494= "com.greenapp.voicerecorder" fullword wide
		 $s495= "com.gusaboda.princesscoloring" fullword wide
		 $s496= "com.gusaboda.weddingpreparation" fullword wide
		 $s497= "com.gutsynot.animalhunting" fullword wide
		 $s498= "com.gutsynot.sportbaseball" fullword wide
		 $s499= "com.hallu.app.removedupcontact" fullword wide
		 $s500= "com.headysnack.sniperguns" fullword wide
		 $s501= "com.healthmeasure.bmicalculator" fullword wide
		 $s502= "com.ijksoftware.pdfcreator.camscanner" fullword wide
		 $s503= "com.inateam.cooler.master" fullword wide
		 $s504= "com.inateam.duplicatecontacts" fullword wide
		 $s505= "com.inpteam.autocallrecorder" fullword wide
		 $s506= "com.iratelake.videoconverter" fullword wide
		 $s507= "com.jumbledsheep.aquariumfishtanks" fullword wide
		 $s508= "com.jumbledsheep.callflashlight" fullword wide
		 $s509= "com.jumbledsheep.funnyphoto" fullword wide
		 $s510= "com.jumbledsheep.mp3videoconverter" fullword wide
		 $s511= "com.locker.videosvault.hidephotos" fullword wide
		 $s512= "com.lullabieskids.antivirus" fullword wide
		 $s513= "com.lullabies.screenrecorder" fullword wide
		 $s514= "com.magicvideo.editor.reversevideo" fullword wide
		 $s515= "com.maxmitek.beachwallpaper" fullword wide
		 $s516= "com.maxmitek.livewallpaperaquariumfishfish" fullword wide
		 $s517= "com.maxmitek.livewallpaperchristmas" fullword wide
		 $s518= "com.maxmitek.livewallpaperwinter" fullword wide
		 $s519= "com.maxmitek.sunsetwallpaper" fullword wide
		 $s520= "com.maxmitek.wallpaperhalloween" fullword wide
		 $s521= "com.maxmitek.waterfallwallpaper" fullword wide
		 $s522= "com.minfiapps.screenshost_capture" fullword wide
		 $s523= "com.minfivezapps.sharesit" fullword wide
		 $s524= "com.mirrorphoto.photoeditor.collagemaker" fullword wide
		 $s525= "com.navajo.screenrecorder" fullword wide
		 $s526= "com.nicewallpaper.beautigirl" fullword wide
		 $s527= "com.nicewallpaper.s6wallpaper" fullword wide
		 $s528= "com.nicewallpaper.supercar" fullword wide
		 $s529= "com.ninetwoworks.venturousracing" fullword wide
		 $s530= "com.oxenplay.phonetracker" fullword wide
		 $s531= "com.pdfviewer.pdfreader.edit" fullword wide
		 $s532= "com.penfour.downloadspeedbooster" fullword wide
		 $s533= "com.photogrid.frame.photocollage" fullword wide
		 $s534= "com.photoshow.videoeditor.slide" fullword wide
		 $s535= "com.placideagles.volumebooster" fullword wide
		 $s536= "com.playnos.videomaker.videoshow" fullword wide
		 $s537= "com.podhengy.cartoonphoto.filters" fullword wide
		 $s538= "com.ponosnocelleh.cartheme" fullword wide
		 $s539= "com.ponosnocelleh.galaxy7theme" fullword wide
		 $s540= "com.ponosnocelleh.launchers7" fullword wide
		 $s541= "com.ponosnocelleh.lolipoptheme" fullword wide
		 $s542= "com.ponosnocelleh.themebeautiful" fullword wide
		 $s543= "com.ponosnocelleh.threedtheme" fullword wide
		 $s544= "com.sassyingot.spidersolitaire" fullword wide
		 $s545= "com.secretdiary.diarywithlock" fullword wide
		 $s546= "com.sedotesodeni.toytruck" fullword wide
		 $s547= "com.sevideo.slideshow.videoeditor" fullword wide
		 $s548= "com.smartvoice.digitalaudio.voicerecorder" fullword wide
		 $s549= "com.ssapps.photorecovery.restoreimage" fullword wide
		 $s550= "com.styletext.font.textonphotos" fullword wide
		 $s551= "com.superrec.screenrecorder.capture" fullword wide
		 $s552= "com.thinkdif.blockcontacts" fullword wide
		 $s553= "com.tineweniseni.cookinggame" fullword wide
		 $s554= "com.unziptool.rarextractor" fullword wide
		 $s555= "com.videomusic.slideshowmaker" fullword wide
		 $s556= "com.volumestudio.volumebooster" fullword wide
		 $s557= "com.writeonpicture.textphoto" fullword wide
		 $s558= "com.xatedses.changehaircoloreye" fullword wide
		 $s559= "com.xatedsesmobile.picturesketch" fullword wide
		 $s560= "com.yamagame.stormfighter" fullword wide
		 $s561= "com.zelylabs.photocollage" fullword wide
		 $s562= "connect_screen_video_first" fullword wide
		 $s563= "-:COU]Z^YZWVVURQQOLH=;6%" fullword wide
		 $s564= "C)SBbWihXdYX`JfEiFgFbE[JVTU][`f]rP}6" fullword wide
		 $s565= "cy_an]de[e_]aXdytPScMVXOXOPRKP;" fullword wide
		 $s566= "Czbn_eee]^]ZYYWXWSSTRPOQKg" fullword wide
		 $s567= "cZyZffZe_X_ZZYXXWSVTSOPPPK_" fullword wide
		 $s568= "/D7NAYKeTnr_o]hV_P[LLcOnT{Z" fullword wide
		 $s569= "?DFMPRTTSNID>;21.,,*+)+(%$!" fullword wide
		 $s570= "?DIFLNLJMHHFCBC?=>>?=@DBGOPUX_aecgffc^]YQMIC=:3-*!" fullword wide
		 $s571= "dMaP^UTXQUTPTQRPQPOONMMOJLIJJKJIJIIFEFEEGFEEBCCCE1" fullword wide
		 $s572= "d[pa_e]_cYc]`Y][YXYWXWXUWTVUUQT9" fullword wide
		 $s573= "%e19c01b3-7f1d-1178-9834-8b8c758db555" fullword wide
		 $s574= "%e19c01b4-7f1d-1178-9834-8b8c758db555" fullword wide
		 $s575= "`?eEiIlMoNqOqNqLqKsKvLyM|P" fullword wide
		 $s576= "een]cd[`X[TUVNSOMKLKFGEH4h" fullword wide
		 $s577= "??EFIINQQUWY]^bechgkmmpqrtuwxx|{z" fullword wide
		 $s578= "EFPMPRRPNOMIIFBBAB@A@DDGHOQVW^`dcifhed`_YSPJB=63-%!" fullword wide
		 $s579= "EGeneric Gray ProfileGenerel gr" fullword wide
		 $s580= "EGeneric RGB ProfileGenerel RGB-beskrivels" fullword wide
		 $s581= "??EHIOPUWVXYXVVRQKIC>96/,( " fullword wide
		 $s582= "EIQMSTWZbejkotsxvtpg_UJ80" fullword wide
		 $s583= "ej_f^`X`[]]WZXXYXYYTVTVTPTPSQPSNPOJ0" fullword wide
		 $s584= "ELNRPRSTYX[`ciifeeijnomltv~" fullword wide
		 $s585= "ELV[behgfd]]ZVTSVZ]aeidc[PH=621/013/0,+)'%" fullword wide
		 $s586= "%/;EMY_elqvvzzxwqohcYUJC8.%" fullword wide
		 $s587= ".?EOY[_dgfighmonqrwuustob_QA4'" fullword wide
		 $s588= "EPSONC91B2F (XP-215 217 Series)" fullword wide
		 $s589= "!,EUe[^frX_buficaNIMLC9=MMHJJRb]_[pxr" fullword wide
		 $s590= "'.,F9MGWR^]``khhiuimrqlmujnnkogngphjp_q`ff`^OSR@L.?'(" fullword wide
		 $s591= "--==>>FFYYgghhZZFF>>KKRRJJBB@@;;00**&&" fullword wide
		 $s592= "f[nb_f`ba]][Y][YZYWYUVVUTVSUQQSPQQ;" fullword wide
		 $s593= "fPcP_UUXQWVRTQRRQQPPPMONMNKJJJIKIKHFHGGFFEFEGAEBBDF5" fullword wide
		 $s594= "':FSafkkif_TNA;652;?IR]ckmldOA/!" fullword wide
		 $s595= "G|bVoT_^TZVPUONQHMIGHDBDCA@@3b" fullword wide
		 $s596= "Genel Gri ProfiliYleinen harmaaprofiiliUniwersalny profil szar" fullword wide
		 $s597= "Genel RGB ProfiliYleinen RGB-profiiliUniwersalny profil RG" fullword wide
		 $s598= "Generel RGB-beskrivelseAlgemeen RGB-profie" fullword wide
		 $s599= "GGRRYY\\ggtt}}||{{wwnnaaNN66" fullword wide
		 $s600= "Gmbc^_[[[V[UWWQURQPOOPKLLJJKf" fullword wide
		 $s601= "{GPXT_e]abYa[]faZWZSP4 ,93D3" fullword wide
		 $s602= "/?GRZadggfd_UOHE@:2/*&!" fullword wide
		 $s603= "H@/D87@56>1:64926615222121.1.7m" fullword wide
		 $s604= "%./;;HGKMYQ^PhZd`]a`ad]fbb^ic^hfcecba_]^O_LOFAA5-1" fullword wide
		 $s605= "-h|gmthvukuljqkjkhbQ>234222112112000%" fullword wide
		 $s606= "HjWZ_XXZSWVQSPQPMPKLJHIHGGFECEEC@J" fullword wide
		 $s607= "h_odcj^dcd_^a[`]Y[ZXZXVVWVUB" fullword wide
		 $s608= "homflffefggcedb``_`_`^]R" fullword wide
		 $s609= "{hSPHEGKT_hklkdaVPJB==@ENYbhfaYV[eoz" fullword wide
		 $s610= "hxuksjglccd]_ZZYWUSSQNOKKJ=j" fullword wide
		 $s611= "hyjmrinlliigideQ115/12011.2//0./" fullword wide
		 $s612= ":ig]fd_d]VB;A=>>5,-//../-" fullword wide
		 $s613= ",?ILNNT^jw}ztj]YZ[]ZRD8/---/.+$ " fullword wide
		 $s614= "IT]bggjijhgfccc``abeikopqqmfbWNB5'" fullword wide
		 $s615= ":.?JCXVZcgakkonjnwoosvjzi{eumpingpdkcibe_YUQFJC520!" fullword wide
		 $s616= "*joYghXgZaV]YVXVWUSSRONQn" fullword wide
		 $s617= "/.%.*&*%&)#&%?j]VcXY[UYVTUSSQNPk" fullword wide
		 $s618= "ki profil sivih tonovaPerfil de gris gen" fullword wide
		 $s619= "ki RGB profilPerfil RGB gen" fullword wide
		 $s620= "{{kkZZKK@@884400--0099EENNZZmm" fullword wide
		 $s621= "kmrijnhjgggegfcdcca_`_`U " fullword wide
		 $s622= "{k]NA5+($'-6>ITdnzz~xm`RF:527;AJW_n|" fullword wide
		 $s623= "!/=KW`hnpsqpkic[YQJE?85.-'$" fullword wide
		 $s624= "lajj]hbaK/AA7[kfjdhddf`eaH,2;'" fullword wide
		 $s625= ")Le]V`YXWXWSVUSOGCHADBC?Qq" fullword wide
		 $s626= "&LhWfV_W[YXWXTVUTHBHEDDX" fullword wide
		 $s627= "l[?kRSNVUNRPKPKMJHLHGGDGECF?B?A@=C" fullword wide
		 $s628= "L RGBUniwersalny profil RGB" fullword wide
		 $s629= "LucudZgaWQWa_YOANSEKEbVcURWHXQF:?H896R>B&26915,%1((0@0/:6:.9(00)545*')62/H9>J?G)87B6AOAGROORNAAG@(0'" fullword wide
		 $s630= "MBDFBA=.66134HONVLQQMNMMV[X7" fullword wide
		 $s631= "'mg[hb^c]^`Y]XXXWVQSSNQNOPLJMf" fullword wide
		 $s632= "N3N/R2[8d=j@k?h>c@^BZDVAO8C)2" fullword wide
		 $s633= "net.camspecial.clonecamera" fullword wide
		 $s634= "net.electronic.alarmclock" fullword wide
		 $s635= "{ng^VPJFEDEGKPSYabgedbUMB6(" fullword wide
		 $s636= "==NNPPFFCCIIQQRRMMCC77--!!" fullword wide
		 $s637= "n{nsnknelal_l]m[mWlRiMfJfJiNmUo[k]d]XZIT8M%D" fullword wide
		 $s638= "n^OD;79;FMW`fihaZUOGB@8530./38GQgy" fullword wide
		 $s639= "^!N'P!]2LL[JQ>I-T!X0Q&L'O.R;M:Q0[2U$O$A" fullword wide
		 $s640= "NWDQPGPFGJFGHDDFBE@B?B@=>>=:N_?->D~" fullword wide
		 $s641= "+;NXcknqsvrtrpmljiggjlouv{}~xwpeQB5(" fullword wide
		 $s642= "Optimized by JPEGmini 3.8.8.1 Internal 0x28c83e2a" fullword wide
		 $s643= "Optimized by JPEGmini 3.8.8.1 Internal 0x5509d0e9" fullword wide
		 $s644= "Optimized by JPEGmini 3.8.8.1 Internal 0xce1fff3c" fullword wide
		 $s645= "(oyfrpgofifde``a_]^[YZWVX" fullword wide
		 $s646= "P5O.K)H*G0J8OATHXL[NO^O_N`MbKdJgIkGnEp@p8m0k)j$k!n" fullword wide
		 $s647= "~pibfdf`TI9222543/)#$'.01,*'#!! " fullword wide
		 $s648= "popup_advanced_audio 11.36.16" fullword wide
		 $s649= "popup_essential_fx 11.36.15" fullword wide
		 $s650= "Profilo grigio genericoGenerisk gr" fullword wide
		 $s651= "|Profilo RGB GenericoGeneric RGB Profil" fullword wide
		 $s652= "Profilo RGB genericoGenerisk RGB-profi" fullword wide
		 $s653= "pXb_X_[W[XWXVWUUTVTUPQRQPPQOOMPNMPMJKJILIJKJF#" fullword wide
		 $s654= "!'& !Q{gdqdfieeebT;@D202010/1/.0.," fullword wide
		 $s655= "}qh``acgdd`_]ZTSUSVVUTSTOI?4+$" fullword wide
		 $s656= "{qi_YSSTX]djmponjida^[ZUTOOIIDC?:5/%" fullword wide
		 $s657= "qphgrEc^Y`XPGJ=;>Q@@6;5C>A?A@7:53.1'!" fullword wide
		 $s658= "{{qq``OOIIMMHHFFKKQQNNCC22" fullword wide
		 $s659= "q|syvm~ezfpohhh]iTYMM@D+7!" fullword wide
		 $s660= "qyLmkVkbXgW^V^UWVRTRTOPONNl" fullword wide
		 $s661= "r3l+d()W.V4W7W4T/P/O9UMdgx" fullword wide
		 $s662= "ricoAllgemeines RGB-Profi" fullword wide
		 $s663= "rico de cinzentosAlgemeen grijsprofielPerfil gris gen" fullword wide
		 $s664= "{|~~|{{r|jwkhe_^QWEP=B:;6310*)!!" fullword wide
		 $s665= "~roppg_YXXRKEFFC93332,($&#" fullword wide
		 $s666= "&&**))==RRVVII??FFTTZZRRHHGGFFJJNNAA,," fullword wide
		 $s667= "Sh]]a^^]ZYYVWURSSTNPOPLLKIHHGGGDW" fullword wide
		 $s668= "skhjiiaXI;3557741*%'+0320,'$!!" fullword wide
		 $s669= "{smjhbaYXVUSQOKFDDIJORTYZTME@=DPW^]ZUPLMOOLGCE@A?>ACEIJKHA2+" fullword wide
		 $s670= "sO]gP_[P^PVVPROOPLJNLKHGGHEF`" fullword wide
		 $s671= "splash_android_apps_land_mohu" fullword wide
		 $s672= "splash_android_apps_port_mohu" fullword wide
		 $s673= "szyqwrnsopmllg`bb]`__^]H./5/03-2" fullword wide
		 $s674= "tlc[TQJGGHLKRVagorvxyxwricQE7.#" fullword wide
		 $s675= "{tmbZQJC>:89:@BFJKLKJGC?=620/+*)''&$%!" fullword wide
		 $s676= "}{tojd^YTOHE@=7330,,+*')('$%#" fullword wide
		 $s677= "{tpkgb`bhillimlooopmjaUHDCFLTWY`chii^QC3*!" fullword wide
		 $s678= "}tpmhilnotwxvwsqnjfb[RH?." fullword wide
		 $s679= "}tw{rhdc_\\VH;1)-50*+%#-,!%6FRYduxlZ=" fullword wide
		 $s680= "~uibYNHB:5421157;?BEFHGID>:2)" fullword wide
		 $s681= "ukaXQMKKLPUY_dhkjih_ZPJC96.,*)+++('% " fullword wide
		 $s682= "vbrgckbdh`baab``_`^[][YZYWZQ#" fullword wide
		 $s683= "ViFV^KYRLXJPNLNIIMFHHCFDDE@B@A=s" fullword wide
		 $s684= "vle^YRQOMMRSXchmrvuwyurkbPI9.$" fullword wide
		 $s685= "vllklqtvxxuspopjifeddcghimttqh[J:,*,.69;===;;:9861-& " fullword wide
		 $s686= "vltx{wy{g]lg]bTRLLA'!*(3WR" fullword wide
		 $s687= "{vtplee_YWUNLHEA=:72/+%% " fullword wide
		 $s688= "[vUdjPkW]W/LiTOcOWVNWPT*" fullword wide
		 $s689= "||vvoonnqqoonnoosspp__IIBBOO^^bbhhvv" fullword wide
		 $s690= "vzutmbnjfce[NOKNIGIvTSVXYXORMSNIHwa`" fullword wide
		 $s691= "wgkgia]YaaeWO@>@GIJCD=CAELHGG=H@G@DAPU]UPPOZVTH7.(*6;D:1!" fullword wide
		 $s692= "wkc[SKFAA@@DEKPZdinttuwrmiUM@4+ " fullword wide
		 $s693= "W_lZc`Y_YY[UXWRSSQPPNOMJMLKHIj" fullword wide
		 $s694= "wpb[QJD@AACGJLOSPRRRQQOOJHFCB===971,'!" fullword wide
		 $s695= "|wpqurwwttlecdaSKHFILPSVSPGCCEJSX]WG9(" fullword wide
		 $s696= "wsomiddegkkd`]ZWTNPTTRNC8* " fullword wide
		 $s697= "|{wsvwttpsqnja[TMMGHGKNTSTTTYZXUOD;40-.+)$%$!" fullword wide
		 $s698= "~wtjc_ZWTPLOPNJGHJKNS[en|" fullword wide
		 $s699= "||wunmhfce_`^]ZXVSOMDB;5/+$" fullword wide
		 $s700= "|{wurpihda][XQPNHDA>872-*&!" fullword wide
		 $s701= "~}{wursnqlnif_^_YYWROMKECBA@87/-))!" fullword wide
		 $s702= "}wutlmggfbd``^][XVUOLIA=6-#" fullword wide
		 $s703= "wwbbYYVVGG==??LL__mmxxzzrr{{" fullword wide
		 $s704= "xbMEOHDN@GF@GA@D@?CLWUL4(HHLUPR8+7.%&!#'" fullword wide
		 $s705= "XdQV]OWUPXNPPLNLLJHGGGHFDFDEAAN" fullword wide
		 $s706= "xogd`[[]_cfmnswuxvwqke]SI>4(" fullword wide
		 $s707= "xpaSIC@AEDE@>;??CFHGLQSTPGC?8;:DJgu" fullword wide
		 $s708= "xqfXPRZ_`_XMHGEADJE;=EEB@7&" fullword wide
		 $s709= "x|q~uqxtnrmp^pda[]YFPK4>3#(" fullword wide
		 $s710= "}xtstu|z{xtrjda]WWWXWXWWW[[_]XRC:50430/39=A=5, " fullword wide
		 $s711= "|xuwvssrsrtqrssvyxpi`SOOQPPKC;6300/.)&*+..(!" fullword wide
		 $s712= "}{xvqpnmlmkmoppqrsstqqnkfb[RK@6(" fullword wide
		 $s713= "xvtvxupmgdXVVXVXZ]^YVPLLPXcjlbYPD;95854118?EFHKMJF>2%" fullword wide
		 $s714= "xxuussookkmmnnjjggiillkkiijjqqyy" fullword wide
		 $s715= "}|{{xxwvtuqrroplnikhhhgeeddaa`__]^[Z[YZZZXYWWVUWUUWVVVRWTSRSUURVTUSTTUWUWVUWXXUWXYZYYZZXZ[Z[[Z[^]" fullword wide
		 $s716= "~}{{|{xxwvuvtuttptrqsrpqppqpqorqqssqsrqssuvuvvxyxx|{z~}" fullword wide
		 $s717= "xxZZ@@77>>HHTT``jjllhh``WWbb" fullword wide
		 $s718= "Yleinen RGB-profiiliGenerisk RGB-profilProfil G" fullword wide
		 $s719= "ymkb][WVYX[^`glrswwyyyrmg^TH>2&" fullword wide
		 $s720= "yndZPE?6/-+'+.25;ELQXaglnlmih`YQH;3%" fullword wide
		 $s721= "yn`OA1'%%3ARdmstodRJHECDHKV_oz" fullword wide
		 $s722= "yog`YSRQSSYZaghmprqnieQF7+" fullword wide
		 $s723= "yphQE@6-)&%#)).6>EKTZaglqpokh`YOF;0%" fullword wide
		 $s724= "yqlljhe_]YZXVRKA853/0-)&" fullword wide
		 $s725= "yrh_ZTOHD?:750/.,+**)&$%$!" fullword wide
		 $s726= "}yuokd_YVOMEC@9:5523000//--)*%#" fullword wide
		 $s727= "~ywsqkied]]XSQLHFB?:860.+&$ " fullword wide
		 $s728= "~~}{yxssppkjhca]YTTOOMEEC>;94/.'##" fullword wide
		 $s729= "{yyytuvsrrpoqnnmiikkgghfhfeeceddcaccd`cdc`caccddccdcdddgggiehghkjikjmmmomqpoqprrsrttuutxwywwywyy{{|{" fullword wide
		 $s730= "}~|y~y|y{yxvxxwutssttrtqqqpoqsP" fullword wide
		 $s731= "|y}y|{{{z|y|z{{|zxwzwvvtsrqrqpmmlmjjhgcca`_YYYVSOPNIJFEB?=;:531.,,&%#" fullword wide
		 $s732= "}~|{{yzwwvsrl`[^^bgbbba`Y>05220" fullword wide
		 $s733= "yzzwxxtuqrqppvvsmb]b^]^J.5923524506" fullword wide
		 $s734= "zskfbYWTQTRRQRPMJHDBCBEIOSW^[XSI>/!" fullword wide
		 $s735= "ztmje_[XRPJHED?=;973//,&#" fullword wide
		 $s736= "~zupjh``ZZWUSPQNKJDB>82-%!" fullword wide
		 $s737= "~zuuqpjge`_XWQNIGDC@7410,*%#" fullword wide
		 $s738= "~|z~uysrlmgjhgc`c[WRLIB9/+$" fullword wide
		 $s739= "zvnhb]UTMJCA972/./4:ELW^cdcPA/" fullword wide
		 $s740= "}zvroiga`[WSPLFEA=8730+)$!" fullword wide
		 $s741= "{zvrqqqlpnkmjjhhgeedccgfiknqqqrruvxxz|" fullword wide
		 $s742= "]ZvVfdXe^Y^XXZRWSSRPQPONLMHT" fullword wide
		 $s743= "|~zwsnmihcea``]]ZWWRRMIC?95.*!" fullword wide
		 $s744= "z{wuurpmljeda_]YYWRPKKGCA>964/,+($" fullword wide
		 $s745= "zxpkc]XMH?94,)&%%*/5=DLYcq}" fullword wide
		 $s746= "z}{xrh_XOKJHB=66=GLKIGEGLNNG=." fullword wide
		 $s747= "}{zyyxurpqqpnjffdbb]\\XWSRNLKGCB>>8852/,*## " fullword wide
		 $s748= "}zzwpnkifca`_^_^`abbeeefdc_]XRKD;/$" fullword wide
		 $s749= "z~z{yuxmskkice^_XYQPIH>@37'*" fullword wide
		 $s750= "|z{zz{{zywxxxwvtttrssurqqr4" fullword wide
		 $a1= "[$HHSeeVipWjoVjpYlqUin6HmRfiVgpTfmUenRgkVhmUipTgmQbnNhjFNNWjnWjpSgnUff[?vThhWipYlrWkqWjpVjpUgmSdhQgk" fullword ascii
		 $a2= ")(0*(1''1)(0*(0,#,)(0##+)(0))0007-+2,,4)(0**2+++)(0))0$$,)(0**0)(0**1+++)).##.&%,##'*(0**0...+*2**1)" fullword ascii
		 $a3= ",0.597),*,0.*-,),*-0.-1/-0.+.--1/*-+%(&,0.&)'-20+.,&*(,1.042)-+163/42&)'/41/41&)'.30$'&052275/41%'%'" fullword ascii
		 $a4= "'.1%+.&-1'.1'/4'.1(.2(/3(.3(.3(/3&-1(.2(.3)/3*.2)/3(04'.2$-0'-1(.2(.2).2)/3(/2(.2&+0$*-(/3(.2)04%-1'" fullword ascii
		 $a5= "20&020RX20$&00RX20$&20RX20$&00PXRPFPRRRXRPFPRRRX2PFPRRRX2PDPRRRXRPFFRRRXRPFFRRRXRPFFRRRXRPFFRRRXrPFP" fullword ascii
		 $a6= "'.2%+.&-1'.1'/4&-1(,0(03(.3)/3(/3&-1(.2(.3(.3)/3*.2)/3(04(.3$-0',0'.1'.2(/2).3(.2(.2).2)/3)/3(/2(.2&" fullword ascii
		 $a7= "(27[irWdm(.2Q]eMY`(.2=FL(/2(-129>)/3%+.*15%+/AKQ'-0(-1'/2*.2(/3)/3%+/(.2.596>C#5:)/3)/3DOU$)-(/3(.2)" fullword ascii
		 $a8= "(/3(27[irWdm(.2R^fMY`(.2=FL(-129>)/3%+.%+/AKQ'.1&,0'/2*.2(/3)/3%+/(.2.596>C#5:)/3)/3DOU$)-(.2)04).3)" fullword ascii
		 $a9= "(/3(/3(.3&./(.2)/2(/3)/3(/3(.2(/2(/3(.2'01'13)/3)/3(.2&.0++6(.2).2*.3(.3'01)048,I).3(.2(/2).2++4)-0)" fullword ascii
		 $a10= "33amySgoXhnZmqWhoXhpTjmXjoXppWgoWjoWhkYjq[mrQmmIIIgrXhnWisZlpXjoXdiUaaUjmWipZmrXipVknXgqZksWjoVhnWi" fullword ascii
		 $a11= "39;(.2)/3(.2)/3).3).3)/3(/2)/3(.2'-3)/3)/4)/3'.0(/3(/2).3(.3(.2)/2).3(.2)/3).3)/3(/2(-2,.3(.2(.3).2*" fullword ascii
		 $a12= "3ffF]]NbvUffUcqMffUamXajWfmYffWcnQgmXmmSglZmmWkkUej]choo]l|Oaa]]hQkkZxxP``NbbMff33f+UUZgoYgoWhrVfoV" fullword ascii
		 $a13= "3ffXflXioWhnWhoWjpXglWhhXkpYioWhnXjoZcmUimWfmMffImmVdkYlrZkpF]]YhoUhnUdlYdoU``ZZiYgkXlqZhnmrWioP``@" fullword ascii
		 $a14= "+48(.2,-/(.3)/3(/3(.1(/3(.2'.2(.2)/3(.2(.3(/2)/3(/2)/3).3'.2)/3(.2-00)/3)/3(/2)/3(.2(.2)/2).2(-3)/2'" fullword ascii
		 $a15= "9:)/3*15)/3)/3*-1).3+03%-1&,0)/3'/3(/3+15)/3(-2)/3).2$*-&+/)04)15*04)03).3(/3(/3%+.)/3).2(14(/3(.1)/" fullword ascii
		 $a16= "9hb8d^7b:kd1NK3UQ8g`3VQ8d^6`[5[V6`[;pi4YU5]X6^X4W6`Z7a7c^8e_9ic1OK5ZU9ga3XT4XT0JG3VR9hb1NJ0NK&EA$" fullword ascii
		 $a17= ",,,a-,,,a-,,a-,,,a-,,,a-,,a-,,,a-,,,a-,,a-,,,a-,,,a-,,a-,,,a-,,,a-,,a-,,,a-,,,a-,,a-,,,a-,,,a-,,a-," fullword ascii
		 $a18= "assets/aviary/cdsv2/assets/images.androidDetailImage.3270dd88-afcf-45da-a8c6-4aafd53354a3.1080.jpgPK" fullword ascii
		 $a19= "assets/aviary/cdsv2/assets/images.androidDetailImage.5e96bfcc-62ec-4a4c-bf3b-20f3cf295bd2.1080.jpgPK" fullword ascii
		 $a20= "assets/aviary/cdsv2/assets/images.androidDetailImage.87ea0744-5ddb-47f6-8253-728f4215d77e.1080.jpgPK" fullword ascii
		 $a21= "assets/aviary/cdsv2/assets/images.androidDetailImage.9cdb2f88-b089-458a-9f23-76400c261b0b.1080.jpgPK" fullword ascii
		 $a22= "assets/aviary/cdsv2/assets/images.androidDetailImage.9cf957a7-be64-4dbb-818b-63ba2854dec9.1080.jpgPK" fullword ascii
		 $a23= "BF(.2)/29::(.3)24)/3)/3).3)/3&-3(.3(-2(/1*.2(/3(.3(.2(.3)/2)/3)/3).3).2'.4)/3).3).2(.3(/3)/3(.2(.2(/" fullword ascii
		 $a24= "bjsRdkVhnUglUgnTflUhoUgmVff???UfmZmrYlrovou[nu[ntZmtZmsYlsYkqWkqWjpVioTgmTglUhnUgnWkpYkrUgo?UURdkY" fullword ascii
		 $a25= "cchttps://docs.google.com/forms/d/1jDMXE0ye9r8G_IyTeVoUdqwIaBJ9qxJb7MTzXFKN5Qs/viewform?usp=send_for" fullword ascii
		 $a26= "cf_]]^[dh_`c]\\[kqe[[Zioc_b[Y^`[OTILLLJJJGHHFFFRRREKCSSRaf]YZYWXWXYW_YWWVgm`ciY[W[^X_cZfl`UVTZ" fullword ascii
		 $a27= "%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%Cffww%%%C" fullword ascii
		 $a28= "com.android.mms||com.facebook.orca||com.whatsapp||kik.android||com.jb.gosms||com.skype.raider||com.t" fullword ascii
		 $a29= "eeres/drawable-xhdpi-v4/com_dot_android_dot_settings_pound_com_dot_miui_dot_securitycenter_dot_main." fullword ascii
		 $a30= "eO5iT:eO6dO7gQ8kU;gR9dN8fQ8fQ8hS9dN4eO6``@gQ8iT:gQ7dN7gS9hR8fM7f33gP8fR8fN7hR9bM7mI$gR9fP7bN7gR9hR9g" fullword ascii
		 $a31= "extmeinc.textme||jp.naver.line.android||ru.mail||com.viber.voip||com.groupme.android||com.link.messa" fullword ascii
		 $a32= "ffres/drawable-xxhdpi-v4/com_dot_android_dot_settings_pound_com_dot_miui_dot_securitycenter_dot_main" fullword ascii
		 $a33= "?ffUhnUgnTgnTgmPglTdlUglUhm?__ShlUfmTglTemTflOhlUhmUgnPfiShmUfmRcjQhkU__RfiThnUfmNag6HmSikSflRinTinT" fullword ascii
		 $a34= "fnShnShmOgkQhhH[dSgkTgmTfmUhlUfmSgmUhmSfnUhnSgnThmTgkTgmUfkUhn:NNUhmUddSenUflQgkShkRfiSfnShnRekPfnTf" fullword ascii
		 $a35= "**;=GH9GIAIMCLNAJNGUUBHKBLO9=E333...IRVGPSBKN?HKFOSISVCUU:?D?ILBKN@JKCLO@HL559?HLDMO>GNAJL3??AJNCLO@" fullword ascii
		 $a36= "gi1TW.QS2ZMmo-EGNsuB^_-TV,PR%EGDac3^`+JL*JL-LNRkmIqsJmoEno-Z)>@Cln4df%>?&BC>[]/MN%CE'EF;XZJgi)IK1O" fullword ascii
		 $a37= "glUgoWipUhnUhnRglUgnVjpXlqUhoYkrUgnUflNbpRgjVhnUinTgmSfmSggTelXjqUfkShmXinWiqUhlBcnPWjTgmWjpRejRik:u" fullword ascii
		 $a38= "gmWinU`jKiiUinVimUUj3ffWhnQhhWioVinWioVhoVhoVinWhnWinWinMffMffWinVhoWgoVhoWinUflVhoVhoWinVfnTilVioVh" fullword ascii
		 $a39= "gnUhmWinUmmUjnVipSelTflTflRfkVikPcjTfkSfmSgjRelU^lWckUhmVioUgnThjUaeRinSekUgmTfnUhmPdjWbbH[[VjoVhnQa" fullword ascii
		 $a40= "goW`oWimUhhTgmTilVfmWimWioWimUgm@``WhnUgmUdoUgoWioUimIIIWflWgmUhoVhnWhnF]]VioWgmWglTgkWflWgmP``UggWi" fullword ascii
		 $a41= "gP5fO6fR6hS9hS9eP6ZK-eN8hS9iS:hS9gP6eQ6jS9hP8eP8gS9hR9fR7cN6iR:jT:hS9dP8eR8eP4gR9fQ8jT;gQ9jU+dO7gR8h" fullword ascii
		 $a42= "gqVipVinUhpWjoWjpVipVioUioVfoUfkMio$HHUfpVhoVjoVinXcgDffRdjSfmWipXioWipWioUjlXfp?QQLffUgnXjqVkoUjqQc" fullword ascii
		 $a43= "hY=hZ=h[=h=h]=h^=h_=h`=ha=hb=hc=hd=he=hf=hg=hh=hi=hj=hk=hl=hm=hn=ho=hp=hq=hr=hs=ht=hu=hv=hw=hx=hy=h" fullword ascii
		 $a44= "iixwwussmllihhgefbaa`__`^_dbbommtrrpnnigha__cbblkkqopgffrpqMLLfddcbbbaadbbgefdccfeefdenmmrqqfeemllqp" fullword ascii
		 $a45= "ikVjpUgnOipIffVjpUgmT`jVhoWkpDW^PfjUgnPffUenUhmRdmTinQekXZZXXXTfnTilUelXko^llUgnVjnUjpXjpTgqRhnUgoVk" fullword ascii
		 $a46= "#Intent;action=home.solo.launcher.free.action.LAUNCHER_THEME;package=com.syntellia.fleksy.keyboard;S" fullword ascii
		 $a47= "io;NNWbmUinWekTim@``UimVikUgmUimVimTfmThlVikVhnVdmUdoThnWhnUgjS`gIIIQeeUfoTgoWffVhmUioUioWgnWii3ffWi" fullword ascii
		 $a48= "iWioVjoXkrUhoUhlTglTfmUgmXjqU[[NNuXgiWhnSfjUUaJccVgmUjpVglKbb:NuTflYhmUglKalZiiTfmVhoRflXccDkkNad?[[" fullword ascii
		 $a49= "jnnWii^pp[mm@TTWjj^ooZllVhhUhhUggTffReeRddbssYkk]ooBWWAUUarrQddMaaK^^SffAVVduuK__NaaI]]J]]DXXCXXBVV" fullword ascii
		 $a50= "joWioVjoWipUjmRdnVimVhqWkoXjqSgm[ns[ntWjoUgmWgnUipVfmUfmUfpPiifffThm[nsZlsZnrUhnUhnXkoXipTeqUUjZmrYl" fullword ascii
		 $a51= "jqW`jNlb``pUhkVjnUim]]tWfpWkpYlqXiqXjo[lrWinVhmWhoWhlVioRddUaaOaaXfoVjmUcmXinXllVinWgnVgoZkpZkqWjoWk" fullword ascii
		 $a52= ".LAUNCHER_THEME_URL=https://play.google.com/store/apps/details?id=com.syntellia.fleksy.keyboard&refe" fullword ascii
		 $a53= "lnYkqVjnWimWjnWhmXjmVjmVhmVhmWjnVinUhmVhnVjnWilWglTjnXjnWjoXjnVioVisWhrXmm999ZkkWjm[ntot[mrlrYkrZl" fullword ascii
		 $a54= "lrVhmSglXfmTfkTdkUenTgkShjTgoReiSfjUimSfiRhlSikRbkTfmUgnSfkThmUdlRglSfnRbmTeqQfiTilSciOfiPdnOcjS^iRi" fullword ascii
		 $a55= "lSjjUaePffM_hNfkN]pUddVbnVbbLffMccU\\U\\O`lVioZmsThnUUjRkknuUim.\\WkqYmsUgnWjpUinZntUhlHffGffPffZms" fullword ascii
		 $a56= "MM*H_+I^*G_*I_*H^+I_-Db+H_*H^*H_*I^*H^*H_*H^*H_)I^*H_*I_*H_*G_*H_+J^*H_*G_+H_*G_*H^*H^*F](F+H`+G_)G" fullword ascii
		 $a57= "mmUgpXjpWgmWioVho[mrVjq]]tXfqZmsXkq[msZkpZlsVhnOXaL^hXjnWgnWhpWkpXinVgmWhmXjpUgpUfo]htfffUgoZkpYlrX" fullword ascii
		 $a58= "NAJNDUUBLOENQBMOGGR8DGCEG5CCDNQDJLAIL9>F@JN=JJDIM=IIBHJ?GKCHLELNEKN8UUBUUCKMBJN@INFOSBKOCLODLOCMOFMP" fullword ascii
		 $a59= "o'66TipUhhXjoUgoWioRhmUfmVimVhoUfkWjoLfrNffXkrShjKalSgnSggQhnWipOOhUejUflTdlUimRglUfmUgnYlqUgoXjoSej" fullword ascii
		 $a60= "OkkUflSfmTfmTgmUglUilUimUgnVjpPhhPffUcHffThnThlU[hUfnMcnSenU[aSfm???UgmYjqOfkUhn^rx[nuRcjQgkQggP`mH" fullword ascii
		 $a61= "PciUgnYjpThnQXXEssVbnXlpVjoXipVinIikVQlUhlXkoVipUelL[[WjnYkqWgmJc|TgmVipWhmSgl3ffVimVkoUioUflUinUfnB" fullword ascii
		 $a62= "PjUhnTjoWjpVekYkqou[ntRelH$mIjjUjoNgkTgmTfmUdlQekRfkUinT`iQgjSfiVdhTemUfmUfmUhnZmrVioUfmH]`VjoXipU" fullword ascii
		 $a63= "pUggCXX^ooAUUDYYK__UhhVhh@TTTggTffSffnn[mmBWWduuZllarr`qqReeXjjJ^^WiiAVVYkkM``L__BVVQddbssK^^CWW@UU" fullword ascii
		 $a64= "pYlqWjsUffXipXhnUmmbqqUenot[ms[mrZlqZlpZkoZkpXjoXjoWioYkp[mqmrosXhoWccZrr[fmWlqWhpXjqUgoWgqWhoXjn" fullword ascii
		 $a65= "Q46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46Ec" fullword ascii
		 $a66= "QhkVhmVhpVflR`iZltUioUikWkqVioXjqUimF`iQdjXhpYlsVfmSfnUinUhnUej[[hUikVhnUinRhmQinUgjYkrYkqWgnUjjWhrW" fullword ascii
		 $a67= "QIrt6bd3_b0XZC`b%@BJpr4SU/OQPkl5TVRlnQlmGoqDmn;Y[?^(JL.NPNikHoq5ac1]_Krt7VXEbd/PRJfg+KMOjl9dfKqsMhj" fullword ascii
		 $a68= "res/drawable-xhdpi-v4/com_dot_android_dot_settings_pound_com_dot_miui_dot_securitycenter_dot_main.pn" fullword ascii
		 $a69= "res/drawable-xxhdpi-v4/com_dot_android_dot_settings_pound_com_dot_miui_dot_securitycenter_dot_main.p" fullword ascii
		 $a70= "Rj{QffWilVjnUinVhnVioVinUhnUgnVioVhoUhpVhlWipUfmQhqPbUehWgmVjpVipUinVjoWipVioUinVjpUinVhoRjpNbbCUUT" fullword ascii
		 $a71= "S46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46EcS46Ec" fullword ascii
		 $a72= "SdmUflEhRgmVelQffUfm?ff???TgkPffSelUcgPahTgmTfmTgmMdjSelRdkUfmTelSglUinUekTilUelUUcRflRY`TdmLffUaeU" fullword ascii
		 $a73= "SftWhoVimVkoMMMXllVgnfwwVgkXjpXipWddYin[lt[msWinXllWjqYlrVjmWjm[iqRfpXekVkoVjnWgmSfkWhoTllVgnYkkTekV" fullword ascii
		 $a74= "SftWhoVimVkoMMMXllVgnWelWjpZlsXkqYkqYjrVglWjqYlrVjmWjm[iqRfpXekVkoRfVjnWgmSfkWhoTllVgnYkkTekVgoUgjW" fullword ascii
		 $a75= "SiiTiiTfoVinUimWimWgnWimWimUgnUgmWgmVeoUUaUinUioWimWioVhmWgmTflOfkTinUgoUhmUimUgmNdoTinUgoVhnII[WioW" fullword ascii
		 $a76= "_\\SimUhmUgmUflSfmUgoP[lUgnWipRfnDWWUhmYmrUioObbZlsSekRckXjp@[dSehRjjUioUenRipSclUfmUdoVipXjqVhoO_g" fullword ascii
		 $a77= "SSUTfjSekUfnTgmTgnWjoYls[nt[nuVjoUgnUhnSfmSao3UU*UUVepUioZmsYkqWjpVioVhnVhoXkpotWhoVjpVhnX`dUgnWjpU" fullword ascii
		 $a78= "TbgTfhLffUUcTeiUgmTejUgkasz]ov^pwZlrThibuuVgmWipVhnUgmUfkZiiUZ_UfmVioXkq^pvUflTfjVjnUekUekSckVhnUfmH" fullword ascii
		 $a79= "TgkVhnVgnVfmUemUhn[msVinUgnTgjVfmUfmUhl[msUciYioVfmSejVgnWipUccWioUdlWioUhk3ffXjqP]]SdjYkqUekUfmUglX" fullword ascii
		 $a80= "T]gWinXkpThnTfmP_dO[dUflRfnVelfffA8KUhoYlrTgjXjoVjnVfmM_aWWgTgoWinTgnTjm?__UhmWioQfk@aaF]]TekUfmUgnS" fullword ascii
		 $a81= "TinThl[mv[nu[ntUioQgqUfpXlqouYlrVioUhnUinSflUei!RROUUPfgXkqZmsYkrWjpWioVioEsRfjVhpVjoYkqZlsVipXkqU" fullword ascii
		 $a82= "TSSSRSUTTXWWjhiYYYWVVUSTPOONMMSRRWVVZYY[[Z`_^ONNONNMLLNMMTSSUTTXWW[[[[`__UTTQPPMMMNMMMLLONNPOOZYY]" fullword ascii
		 $a83= "UaaVgoVhnVioVhnNddVhlUfkU``TglWipUgmVgnVilVgmVhmUfoWioWhpYdoMffUhoWioXhnVfl@P`WhnWiqTfjXenNXbWilQjjS" fullword ascii
		 $a84= "U[aUfmQiiUimU^lUglUfnTfnUhlWinSfoVflXjoXkpTfmUglTgnTgnTfkLgmUhlSjnUfoNhhWkpQdlQinRgmUUNflTimSfnUilU" fullword ascii
		 $a85= "UfmVioVhoVhpVioWipWioVipUioWioVimUfnYjpWhmVhpWgpYjqXhoViqZhoVjr@``IImUjjQ]]JRc]llY``U``WggUeeWafSggS" fullword ascii
		 $a86= "UfnYlrYkpWioVipUdUUgUgoUhlRbkXhpWfoZinTgkWkoUioMcj3UUVfpYloWjoWgnRiqVeoWjoUdgYlqXkqXlrTflXkpRgnVgoR" fullword ascii
		 $a87= "UgkLffUgmUfl???UflRfiTgmUfkP]]UglUbjTikHffUgmTemfffUflO`iUgmTem?__TgmUgmUgmSfmDffU]fSemUgmUaeSgmHHHU" fullword ascii
		 $a88= "UhmVemUjpXkpUkoVil[mtZmtVhlQcl4QQ[[aVhk[mtVfmTciUhjSbjBZaShkAkkTdmUhnRchY_bAbbLacYgoSfnVhkTgmUgmSfnU" fullword ascii
		 $a89= "UjnYjoVgoWflVhlUqqF]]XhnVglIUaVhjWioSaoXjoRffWikVgnUgmXhoYgnYkpmsWimRjnXinWipWip]jjWhoTilYgpThnWhnU" fullword ascii
		 $a90= "UjnYjoVgoWflVhlUqqXhnVglIUaVhjWioSaoXjoRffWikVgnUgmXhoZhhXjq[nsVioXenFttZhhWipZnsYkrUglWip]jjWhoTilY" fullword ascii
		 $a91= "U__TfnYlpXjqUflIddUiiVkpWkpUfnShhUjpXkpTilRfiVhmVjoWjpXkqTglQ[[YdkVjoTgnTgmWjoXgnUglXjpYlqXjpTdlVimV" fullword ascii
		 $a92= "UUmQcnRfjThlUhnThmUfnUimUgmLfnVioTgnUgmUinUfmGggSfkUioTglUgnUhlBcnUcNbhUenUhnTgmTglUhnSfmPinUhlThnS" fullword ascii
		 $a93= "UXjqWjoZlsXhlYflWipWipVjoVgnUwfWhlWhmUlqUffWhpZkpZksXjpQ^kntVimQctDUUWip[lsVjnUcqUhpWkpXkpVjmVelWio" fullword ascii
		 $a94= "uXkrUgn___UepUgmRfkTfkShjWdlThmUglThnUhoUhmSglUbkTirTbkTgmThmTfmDSSUfnRagUcgQ[[VipU][ntYnrRcgQggWjp" fullword ascii
		 $a95= "VeoUfkUimNdoWgnNdoVgmVinWimVimII[VilUffThlUgnSffVimVhmWioUimUdhWhmS`gQ^^Who3ffUgmUenRgkUiiThoUioUfmW" fullword ascii
		 $a96= "VglVgnUinTioUioWhnVinTgoVimWimWimU]dTenUgoWiiWimQdjUgoUiiWhmUimVhnWgmUgoWimUimSffUioUioVhoWbmTfjSfiR" fullword ascii
		 $a97= "VgnNdoRckVioWinWhmWhoUflWinUinUhnQhhVgnMffUffUgoKiiVhnUimUiiUgmVioRdmMffWhnUhlVhnVinQ^kVinVgnWioVinV" fullword ascii
		 $a98= "Vim[mqWioWinVgoVhnYjrZknQ^kQgmXilUipVik[ltkpVhmWmmVgoUggS^mWjoTdhVgoWhoXhnXhpVgnZkkWgmXioJ``UgnVelV" fullword ascii
		 $a99= "V`iTgmUinUfmTejIbgUhrUfmVipUgm8iiIjmVgkVipXjpUgmUglVjoYlrUdmT]lVkpUfkUgnUilW`cVjoWkpTenYlsTflLAYUhpU" fullword ascii
		 $a100= "__VjpUhnPddSdmUhm3UUVkkVioPfnUflTglUjoUfnH$mUfiUgmRaiHddWfl?__Sgn:NNSiiXfmUimUioViqUgnUekUhkUdUfoWi" fullword ascii
		 $a101= "__VjpUhnPddSdmUhm3UUVkkVioPfnVim]otUhnKZZ?__VhpZouVln?UUH$mUfiUgmRaiHddWflSgnSiiPffUio]nuUgmWgq[otQ[" fullword ascii
		 $a102= "VVGGffDDVVGGffDDVVGGffDDVVGGffDDVVGGffDDVVGGffDDVVGGffDDVVGGffDDVVGGffDDVVGGffDDVVGGffDDVVGGffDDVVGG" fullword ascii
		 $a103= "WhnWioVioWinVhnWinWhnWioVioVhnVhmUhmVhmWhmUglTgnUfmTgnUfoSfkVhnVinVgnVhoUejSekVinUgkWhnUcjUfoWhoPhhU" fullword ascii
		 $a104= "wrwQV1D1T!T1T!T!T1T1U!T1T!T!T1TAeAe1TAd-C?D_v2D1T1U1D1D!D1D1D!D!D1D!D!D1T!T!D!D1T1T6T?U_UZfQVADATAD1" fullword ascii
		 $a105= "wwwzzztttqqqvvvsssmmmjjjkkkhhhooolllrrrnnniiieeeZZZTTTXXX\\___gggIIIEEEGGGJJJKKKLLLVVV^^^ONNPPPbbbW" fullword ascii
		 $a106= "XccWinWiqUhnVjnUgoUdoLfrPddVimTglUjlWipWkpUjoPdkVknXjrVioUglSbhVdlWlpXkrUhh[huVjoSglOiiVckXlpXlqVinU" fullword ascii
		 $a107= "XffWjpVemVhmWhoWhlVioRddUaaOaaXfoVjmUcmXinXllVinWgnYlp[ntXjoVhoXjpYjqYgqUqqWkpVilUUqDffWhmVkrWhkVhnV" fullword ascii
		 $a108= "YqqXhpWjoWioWipWhnSqqWhnWipWjoXioWhoWhoYloWjoXhlXgqXkqXkpWjpRfjUooZjnWjqYmpXipXjpTll[mmUmqYhqWhpYkp3" fullword ascii
		 $a109= "ywxwuuqppnlmnmmrqqvtt~|}tsttsrvtuigggefgeehggkjjmkkomnqppsrrvtutssrqqpnonllkjjkijcbcjhi^]]dccfeehggj" fullword ascii
		 $a110= "ZiiTfnUhoWjpUgnTgmTglReeSbbEddU]]MggU`dTeiUckWgnYlqUhoSbj;GGPglVipWlqWjnRdjU[p333N[gRfiUgkUioThoUUfU" fullword ascii
		 $a111= "_%}[&{Z&|[&|Z&{Y&zX&yX&xV'yW'xV'xW'wU'vT(sQ(vS'uS(tR(sQ(rP)sP(qO)qN)nK*pM)oL*nK*mJ*mJ+lI+mI*hE,kH+kG" fullword ascii
		 $a112= "ZZZSSS]]][[[XXX\\[[[YYYVVV___^^^VVVSSS]]]XXX```___ZZZ]]]XXX\\___aaa\\VVVWWWXXXaaaXXXaaa^^^aaa[[[`" fullword ascii
		 $a113= "{zz]\\ZYYWVVjhi_^^]\\xvv_^^YWW[ZZMLL[ZZXWW_]^_]^XVWbaabaaPOOQPPQPPWVWb``]\\TTSZXXihhwuv[[dcc]`a_" fullword ascii

		 $hex1= {24613130303d20225f}
		 $hex2= {24613130313d20225f}
		 $hex3= {24613130323d202256}
		 $hex4= {24613130333d202257}
		 $hex5= {24613130343d202277}
		 $hex6= {24613130353d202277}
		 $hex7= {24613130363d202258}
		 $hex8= {24613130373d202258}
		 $hex9= {24613130383d202259}
		 $hex10= {24613130393d202279}
		 $hex11= {246131303d20223333}
		 $hex12= {24613131303d20225a}
		 $hex13= {24613131313d20225f}
		 $hex14= {24613131323d20225a}
		 $hex15= {24613131333d20227b}
		 $hex16= {246131313d20223339}
		 $hex17= {246131323d20223366}
		 $hex18= {246131333d20223366}
		 $hex19= {246131343d20222b34}
		 $hex20= {246131353d2022393a}
		 $hex21= {246131363d20223968}
		 $hex22= {246131373d20222c2c}
		 $hex23= {246131383d20226173}
		 $hex24= {246131393d20226173}
		 $hex25= {2461313d20225b2448}
		 $hex26= {246132303d20226173}
		 $hex27= {246132313d20226173}
		 $hex28= {246132323d20226173}
		 $hex29= {246132333d20224246}
		 $hex30= {246132343d2022626a}
		 $hex31= {246132353d20226363}
		 $hex32= {246132363d20226366}
		 $hex33= {246132373d20222525}
		 $hex34= {246132383d2022636f}
		 $hex35= {246132393d20226565}
		 $hex36= {2461323d2022292830}
		 $hex37= {246133303d2022654f}
		 $hex38= {246133313d20226578}
		 $hex39= {246133323d20226666}
		 $hex40= {246133333d20223f66}
		 $hex41= {246133343d2022666e}
		 $hex42= {246133353d20222a2a}
		 $hex43= {246133363d20226769}
		 $hex44= {246133373d2022676c}
		 $hex45= {246133383d2022676d}
		 $hex46= {246133393d2022676e}
		 $hex47= {2461333d20222c302e}
		 $hex48= {246134303d2022676f}
		 $hex49= {246134313d20226750}
		 $hex50= {246134323d20226771}
		 $hex51= {246134333d20226859}
		 $hex52= {246134343d20226969}
		 $hex53= {246134353d2022696b}
		 $hex54= {246134363d20222349}
		 $hex55= {246134373d2022696f}
		 $hex56= {246134383d20226957}
		 $hex57= {246134393d20226a6e}
		 $hex58= {2461343d2022272e31}
		 $hex59= {246135303d20226a6f}
		 $hex60= {246135313d20226a71}
		 $hex61= {246135323d20222e4c}
		 $hex62= {246135333d20226c6e}
		 $hex63= {246135343d20226c72}
		 $hex64= {246135353d20226c53}
		 $hex65= {246135363d20224d4d}
		 $hex66= {246135373d20226d6d}
		 $hex67= {246135383d20224e41}
		 $hex68= {246135393d20226f27}
		 $hex69= {2461353d2022323026}
		 $hex70= {246136303d20224f6b}
		 $hex71= {246136313d20225063}
		 $hex72= {246136323d2022506a}
		 $hex73= {246136333d20227055}
		 $hex74= {246136343d20227059}
		 $hex75= {246136353d20225134}
		 $hex76= {246136363d20225168}
		 $hex77= {246136373d20225149}
		 $hex78= {246136383d20227265}
		 $hex79= {246136393d20227265}
		 $hex80= {2461363d2022272e32}
		 $hex81= {246137303d2022526a}
		 $hex82= {246137313d20225334}
		 $hex83= {246137323d20225364}
		 $hex84= {246137333d20225366}
		 $hex85= {246137343d20225366}
		 $hex86= {246137353d20225369}
		 $hex87= {246137363d20225f53}
		 $hex88= {246137373d20225353}
		 $hex89= {246137383d20225462}
		 $hex90= {246137393d20225467}
		 $hex91= {2461373d2022283237}
		 $hex92= {246138303d2022545d}
		 $hex93= {246138313d20225469}
		 $hex94= {246138323d20225453}
		 $hex95= {246138333d20225561}
		 $hex96= {246138343d2022555b}
		 $hex97= {246138353d20225566}
		 $hex98= {246138363d20225566}
		 $hex99= {246138373d20225567}
		 $hex100= {246138383d20225568}
		 $hex101= {246138393d2022556a}
		 $hex102= {2461383d2022282f33}
		 $hex103= {246139303d2022556a}
		 $hex104= {246139313d2022555f}
		 $hex105= {246139323d20225555}
		 $hex106= {246139333d20225558}
		 $hex107= {246139343d20227558}
		 $hex108= {246139353d20225665}
		 $hex109= {246139363d20225667}
		 $hex110= {246139373d20225667}
		 $hex111= {246139383d20225669}
		 $hex112= {246139393d20225660}
		 $hex113= {2461393d2022282f33}
		 $hex114= {24733130303d202225}
		 $hex115= {24733130313d202221}
		 $hex116= {24733130323d202226}
		 $hex117= {24733130333d202221}
		 $hex118= {24733130343d202221}
		 $hex119= {24733130353d202225}
		 $hex120= {24733130363d202221}
		 $hex121= {24733130373d202223}
		 $hex122= {24733130383d202225}
		 $hex123= {24733130393d20222a}
		 $hex124= {247331303d20222424}
		 $hex125= {24733131303d202221}
		 $hex126= {24733131313d202221}
		 $hex127= {24733131323d202228}
		 $hex128= {24733131333d202226}
		 $hex129= {24733131343d202229}
		 $hex130= {24733131353d202221}
		 $hex131= {24733131363d20222a}
		 $hex132= {24733131373d202225}
		 $hex133= {24733131383d202227}
		 $hex134= {24733131393d202221}
		 $hex135= {247331313d20222424}
		 $hex136= {24733132303d202221}
		 $hex137= {24733132313d202228}
		 $hex138= {24733132323d20222b}
		 $hex139= {24733132333d202230}
		 $hex140= {24733132343d202223}
		 $hex141= {24733132353d202228}
		 $hex142= {24733132363d202223}
		 $hex143= {24733132373d202229}
		 $hex144= {24733132383d202223}
		 $hex145= {24733132393d202221}
		 $hex146= {247331323d20222425}
		 $hex147= {24733133303d202229}
		 $hex148= {24733133313d202230}
		 $hex149= {24733133323d202223}
		 $hex150= {24733133333d202226}
		 $hex151= {24733133343d202228}
		 $hex152= {24733133353d202221}
		 $hex153= {24733133363d202225}
		 $hex154= {24733133373d202229}
		 $hex155= {24733133383d202227}
		 $hex156= {24733133393d202226}
		 $hex157= {247331333d20222425}
		 $hex158= {24733134303d202229}
		 $hex159= {24733134313d202223}
		 $hex160= {24733134323d202231}
		 $hex161= {24733134333d202221}
		 $hex162= {24733134343d202227}
		 $hex163= {24733134353d20223a}
		 $hex164= {24733134363d20222b}
		 $hex165= {24733134373d202221}
		 $hex166= {24733134383d202226}
		 $hex167= {24733134393d202231}
		 $hex168= {247331343d20222323}
		 $hex169= {24733135303d202221}
		 $hex170= {24733135313d202223}
		 $hex171= {24733135323d20222a}
		 $hex172= {24733135333d20222e}
		 $hex173= {24733135343d202221}
		 $hex174= {24733135353d202227}
		 $hex175= {24733135363d202221}
		 $hex176= {24733135373d202226}
		 $hex177= {24733135383d202221}
		 $hex178= {24733135393d202223}
		 $hex179= {247331353d20222425}
		 $hex180= {24733136303d202221}
		 $hex181= {24733136313d20222b}
		 $hex182= {24733136323d202223}
		 $hex183= {24733136333d202225}
		 $hex184= {24733136343d202227}
		 $hex185= {24733136353d202221}
		 $hex186= {24733136363d202225}
		 $hex187= {24733136373d202223}
		 $hex188= {24733136383d202221}
		 $hex189= {24733136393d20222b}
		 $hex190= {247331363d20222426}
		 $hex191= {24733137303d202226}
		 $hex192= {24733137313d202225}
		 $hex193= {24733137323d202221}
		 $hex194= {24733137333d202223}
		 $hex195= {24733137343d202223}
		 $hex196= {24733137353d202225}
		 $hex197= {24733137363d202228}
		 $hex198= {24733137373d202227}
		 $hex199= {24733137383d202227}
		 $hex200= {24733137393d202226}
		 $hex201= {247331373d20222124}
		 $hex202= {24733138303d202228}
		 $hex203= {24733138313d202221}
		 $hex204= {24733138323d202225}
		 $hex205= {24733138333d202221}
		 $hex206= {24733138343d202228}
		 $hex207= {24733138353d202223}
		 $hex208= {24733138363d202228}
		 $hex209= {24733138373d202228}
		 $hex210= {24733138383d202229}
		 $hex211= {24733138393d202226}
		 $hex212= {247331383d2022242a}
		 $hex213= {24733139303d202228}
		 $hex214= {24733139313d202231}
		 $hex215= {24733139323d20222a}
		 $hex216= {24733139333d20222a}
		 $hex217= {24733139343d202221}
		 $hex218= {24733139353d202221}
		 $hex219= {24733139363d202227}
		 $hex220= {24733139373d202229}
		 $hex221= {24733139383d202221}
		 $hex222= {24733139393d202231}
		 $hex223= {247331393d2022242a}
		 $hex224= {2473313d2022232326}
		 $hex225= {24733230303d202231}
		 $hex226= {24733230313d202228}
		 $hex227= {24733230323d202221}
		 $hex228= {24733230333d202221}
		 $hex229= {24733230343d202225}
		 $hex230= {24733230353d202229}
		 $hex231= {24733230363d202232}
		 $hex232= {24733230373d202223}
		 $hex233= {24733230383d202223}
		 $hex234= {24733230393d202225}
		 $hex235= {247332303d20222427}
		 $hex236= {24733231303d202221}
		 $hex237= {24733231313d202223}
		 $hex238= {24733231323d202225}
		 $hex239= {24733231333d20222a}
		 $hex240= {24733231343d202223}
		 $hex241= {24733231353d202223}
		 $hex242= {24733231363d202221}
		 $hex243= {24733231373d202223}
		 $hex244= {24733231383d202225}
		 $hex245= {24733231393d202221}
		 $hex246= {247332313d20222624}
		 $hex247= {24733232303d202221}
		 $hex248= {24733232313d202225}
		 $hex249= {24733232323d20222b}
		 $hex250= {24733232333d202225}
		 $hex251= {24733232343d202225}
		 $hex252= {24733232353d202221}
		 $hex253= {24733232363d202225}
		 $hex254= {24733232373d202223}
		 $hex255= {24733232383d202223}
		 $hex256= {24733232393d202221}
		 $hex257= {247332323d20222324}
		 $hex258= {24733233303d202229}
		 $hex259= {24733233313d202226}
		 $hex260= {24733233323d202225}
		 $hex261= {24733233333d202228}
		 $hex262= {24733233343d202228}
		 $hex263= {24733233353d202226}
		 $hex264= {24733233363d20222a}
		 $hex265= {24733233373d202227}
		 $hex266= {24733233383d202229}
		 $hex267= {24733233393d202223}
		 $hex268= {247332333d2022242c}
		 $hex269= {24733234303d202225}
		 $hex270= {24733234313d202232}
		 $hex271= {24733234323d202233}
		 $hex272= {24733234333d20222d}
		 $hex273= {24733234343d202221}
		 $hex274= {24733234353d202223}
		 $hex275= {24733234363d202223}
		 $hex276= {24733234373d202233}
		 $hex277= {24733234383d202226}
		 $hex278= {24733234393d202223}
		 $hex279= {247332343d2022242a}
		 $hex280= {24733235303d202221}
		 $hex281= {24733235313d202223}
		 $hex282= {24733235323d202226}
		 $hex283= {24733235333d20222b}
		 $hex284= {24733235343d202223}
		 $hex285= {24733235353d202233}
		 $hex286= {24733235363d202221}
		 $hex287= {24733235373d202225}
		 $hex288= {24733235383d202227}
		 $hex289= {24733235393d202223}
		 $hex290= {247332353d20222430}
		 $hex291= {24733236303d20222b}
		 $hex292= {24733236313d202225}
		 $hex293= {24733236323d202221}
		 $hex294= {24733236333d202225}
		 $hex295= {24733236343d202223}
		 $hex296= {24733236353d202227}
		 $hex297= {24733236363d20222f}
		 $hex298= {24733236373d202225}
		 $hex299= {24733236383d202221}
		 $hex300= {24733236393d202226}
		 $hex301= {247332363d20222430}
		 $hex302= {24733237303d202223}
		 $hex303= {24733237313d202221}
		 $hex304= {24733237323d202225}
		 $hex305= {24733237333d202227}
		 $hex306= {24733237343d202221}
		 $hex307= {24733237353d202221}
		 $hex308= {24733237363d202227}
		 $hex309= {24733237373d202225}
		 $hex310= {24733237383d202228}
		 $hex311= {24733237393d202226}
		 $hex312= {247332373d20222427}
		 $hex313= {24733238303d202225}
		 $hex314= {24733238313d202225}
		 $hex315= {24733238323d202234}
		 $hex316= {24733238333d202225}
		 $hex317= {24733238343d202227}
		 $hex318= {24733238353d202226}
		 $hex319= {24733238363d20222a}
		 $hex320= {24733238373d20222c}
		 $hex321= {24733238383d202221}
		 $hex322= {24733238393d202221}
		 $hex323= {247332383d20222323}
		 $hex324= {24733239303d202225}
		 $hex325= {24733239313d202221}
		 $hex326= {24733239323d20222a}
		 $hex327= {24733239333d202225}
		 $hex328= {24733239343d202229}
		 $hex329= {24733239353d20222a}
		 $hex330= {24733239363d20222b}
		 $hex331= {24733239373d202226}
		 $hex332= {24733239383d202221}
		 $hex333= {24733239393d20222a}
		 $hex334= {247332393d20222323}
		 $hex335= {2473323d2022212025}
		 $hex336= {24733330303d202227}
		 $hex337= {24733330313d202234}
		 $hex338= {24733330323d202225}
		 $hex339= {24733330333d202226}
		 $hex340= {24733330343d202221}
		 $hex341= {24733330353d202235}
		 $hex342= {24733330363d202221}
		 $hex343= {24733330373d202223}
		 $hex344= {24733330383d202221}
		 $hex345= {24733330393d202221}
		 $hex346= {247333303d20222425}
		 $hex347= {24733331303d202227}
		 $hex348= {24733331313d202226}
		 $hex349= {24733331323d202221}
		 $hex350= {24733331333d20222b}
		 $hex351= {24733331343d202225}
		 $hex352= {24733331353d20222b}
		 $hex353= {24733331363d202225}
		 $hex354= {24733331373d202226}
		 $hex355= {24733331383d202223}
		 $hex356= {24733331393d202225}
		 $hex357= {247333313d20222324}
		 $hex358= {24733332303d202223}
		 $hex359= {24733332313d20222b}
		 $hex360= {24733332323d202225}
		 $hex361= {24733332333d202228}
		 $hex362= {24733332343d202225}
		 $hex363= {24733332353d202226}
		 $hex364= {24733332363d20222f}
		 $hex365= {24733332373d202225}
		 $hex366= {24733332383d202223}
		 $hex367= {24733332393d202226}
		 $hex368= {247333323d20222124}
		 $hex369= {24733333303d202236}
		 $hex370= {24733333313d202227}
		 $hex371= {24733333323d20222b}
		 $hex372= {24733333333d20222b}
		 $hex373= {24733333343d20222c}
		 $hex374= {24733333353d20222c}
		 $hex375= {24733333363d202221}
		 $hex376= {24733333373d202221}
		 $hex377= {24733333383d202223}
		 $hex378= {24733333393d202225}
		 $hex379= {247333333d20222124}
		 $hex380= {24733334303d202236}
		 $hex381= {24733334313d202223}
		 $hex382= {24733334323d202223}
		 $hex383= {24733334333d202226}
		 $hex384= {24733334343d202225}
		 $hex385= {24733334353d202228}
		 $hex386= {24733334363d20222d}
		 $hex387= {24733334373d20222b}
		 $hex388= {24733334383d202240}
		 $hex389= {24733334393d202237}
		 $hex390= {247333343d20222124}
		 $hex391= {24733335303d20222c}
		 $hex392= {24733335313d202226}
		 $hex393= {24733335323d202223}
		 $hex394= {24733335333d202221}
		 $hex395= {24733335343d202221}
		 $hex396= {24733335353d20222b}
		 $hex397= {24733335363d202221}
		 $hex398= {24733335373d20222a}
		 $hex399= {24733335383d202225}
		 $hex400= {24733335393d202223}
		 $hex401= {247333353d20222427}
		 $hex402= {24733336303d202226}
		 $hex403= {24733336313d202225}
		 $hex404= {24733336323d202223}
		 $hex405= {24733336333d202225}
		 $hex406= {24733336343d20222e}
		 $hex407= {24733336353d20223e}
		 $hex408= {24733336363d202238}
		 $hex409= {24733336373d202229}
		 $hex410= {24733336383d20223a}
		 $hex411= {24733336393d202226}
		 $hex412= {247333363d20222324}
		 $hex413= {24733337303d202238}
		 $hex414= {24733337313d20222a}
		 $hex415= {24733337323d202238}
		 $hex416= {24733337333d202225}
		 $hex417= {24733337343d202229}
		 $hex418= {24733337353d202221}
		 $hex419= {24733337363d202238}
		 $hex420= {24733337373d202227}
		 $hex421= {24733337383d202221}
		 $hex422= {24733337393d202223}
		 $hex423= {247333373d20222423}
		 $hex424= {24733338303d202239}
		 $hex425= {24733338313d20222a}
		 $hex426= {24733338323d202239}
		 $hex427= {24733338333d202226}
		 $hex428= {24733338343d202239}
		 $hex429= {24733338353d202227}
		 $hex430= {24733338363d202223}
		 $hex431= {24733338373d202227}
		 $hex432= {24733338383d202239}
		 $hex433= {24733338393d202223}
		 $hex434= {247333383d20222427}
		 $hex435= {24733339303d202226}
		 $hex436= {24733339313d202225}
		 $hex437= {24733339323d20223e}
		 $hex438= {24733339333d20223b}
		 $hex439= {24733339343d202223}
		 $hex440= {24733339353d20223f}
		 $hex441= {24733339363d20225e}
		 $hex442= {24733339373d202241}
		 $hex443= {24733339383d20223e}
		 $hex444= {24733339393d20223d}
		 $hex445= {247333393d20222428}
		 $hex446= {2473333d202221252f}
		 $hex447= {24733430303d202241}
		 $hex448= {24733430313d202241}
		 $hex449= {24733430323d202241}
		 $hex450= {24733430333d20223d}
		 $hex451= {24733430343d202241}
		 $hex452= {24733430353d202241}
		 $hex453= {24733430363d20223d}
		 $hex454= {24733430373d202241}
		 $hex455= {24733430383d20223e}
		 $hex456= {24733430393d202241}
		 $hex457= {247334303d20222429}
		 $hex458= {24733431303d202241}
		 $hex459= {24733431313d202241}
		 $hex460= {24733431323d202241}
		 $hex461= {24733431333d202261}
		 $hex462= {24733431343d202242}
		 $hex463= {24733431353d202228}
		 $hex464= {24733431363d20223d}
		 $hex465= {24733431373d20222b}
		 $hex466= {24733431383d20223e}
		 $hex467= {24733431393d20223f}
		 $hex468= {247334313d2022242b}
		 $hex469= {24733432303d202242}
		 $hex470= {24733432313d202242}
		 $hex471= {24733432323d202240}
		 $hex472= {24733432333d202242}
		 $hex473= {24733432343d202242}
		 $hex474= {24733432353d202242}
		 $hex475= {24733432363d20223f}
		 $hex476= {24733432373d202242}
		 $hex477= {24733432383d20223b}
		 $hex478= {24733432393d202226}
		 $hex479= {247334323d20222431}
		 $hex480= {24733433303d202227}
		 $hex481= {24733433313d202242}
		 $hex482= {24733433323d20223f}
		 $hex483= {24733433333d20222a}
		 $hex484= {24733433343d20223e}
		 $hex485= {24733433353d202221}
		 $hex486= {24733433363d202240}
		 $hex487= {24733433373d20223e}
		 $hex488= {24733433383d202243}
		 $hex489= {24733433393d20223d}
		 $hex490= {247334333d20222426}
		 $hex491= {24733434303d202243}
		 $hex492= {24733434313d20223d}
		 $hex493= {24733434323d20223d}
		 $hex494= {24733434333d202243}
		 $hex495= {24733434343d202243}
		 $hex496= {24733434353d202263}
		 $hex497= {24733434363d202263}
		 $hex498= {24733434373d202263}
		 $hex499= {24733434383d202263}
		 $hex500= {24733434393d202263}
		 $hex501= {247334343d20222425}
		 $hex502= {24733435303d202263}
		 $hex503= {24733435313d202263}
		 $hex504= {24733435323d202263}
		 $hex505= {24733435333d202263}
		 $hex506= {24733435343d202263}
		 $hex507= {24733435353d202263}
		 $hex508= {24733435363d202263}
		 $hex509= {24733435373d202263}
		 $hex510= {24733435383d202263}
		 $hex511= {24733435393d202263}
		 $hex512= {247334353d20222324}
		 $hex513= {24733436303d202263}
		 $hex514= {24733436313d202263}
		 $hex515= {24733436323d202263}
		 $hex516= {24733436333d202263}
		 $hex517= {24733436343d202263}
		 $hex518= {24733436353d202263}
		 $hex519= {24733436363d202263}
		 $hex520= {24733436373d202263}
		 $hex521= {24733436383d202263}
		 $hex522= {24733436393d202263}
		 $hex523= {247334363d2022242b}
		 $hex524= {24733437303d202263}
		 $hex525= {24733437313d202263}
		 $hex526= {24733437323d202263}
		 $hex527= {24733437333d202263}
		 $hex528= {24733437343d202263}
		 $hex529= {24733437353d202263}
		 $hex530= {24733437363d202263}
		 $hex531= {24733437373d202263}
		 $hex532= {24733437383d202263}
		 $hex533= {24733437393d202263}
		 $hex534= {247334373d20222428}
		 $hex535= {24733438303d202263}
		 $hex536= {24733438313d202263}
		 $hex537= {24733438323d202263}
		 $hex538= {24733438333d202263}
		 $hex539= {24733438343d202263}
		 $hex540= {24733438353d202263}
		 $hex541= {24733438363d202263}
		 $hex542= {24733438373d202263}
		 $hex543= {24733438383d202263}
		 $hex544= {24733438393d202263}
		 $hex545= {247334383d2022242a}
		 $hex546= {24733439303d202263}
		 $hex547= {24733439313d202263}
		 $hex548= {24733439323d202263}
		 $hex549= {24733439333d202263}
		 $hex550= {24733439343d202263}
		 $hex551= {24733439353d202263}
		 $hex552= {24733439363d202263}
		 $hex553= {24733439373d202263}
		 $hex554= {24733439383d202263}
		 $hex555= {24733439393d202263}
		 $hex556= {247334393d20222324}
		 $hex557= {2473343d2022292421}
		 $hex558= {24733530303d202263}
		 $hex559= {24733530313d202263}
		 $hex560= {24733530323d202263}
		 $hex561= {24733530333d202263}
		 $hex562= {24733530343d202263}
		 $hex563= {24733530353d202263}
		 $hex564= {24733530363d202263}
		 $hex565= {24733530373d202263}
		 $hex566= {24733530383d202263}
		 $hex567= {24733530393d202263}
		 $hex568= {247335303d20222121}
		 $hex569= {24733531303d202263}
		 $hex570= {24733531313d202263}
		 $hex571= {24733531323d202263}
		 $hex572= {24733531333d202263}
		 $hex573= {24733531343d202263}
		 $hex574= {24733531353d202263}
		 $hex575= {24733531363d202263}
		 $hex576= {24733531373d202263}
		 $hex577= {24733531383d202263}
		 $hex578= {24733531393d202263}
		 $hex579= {247335313d20222428}
		 $hex580= {24733532303d202263}
		 $hex581= {24733532313d202263}
		 $hex582= {24733532323d202263}
		 $hex583= {24733532333d202263}
		 $hex584= {24733532343d202263}
		 $hex585= {24733532353d202263}
		 $hex586= {24733532363d202263}
		 $hex587= {24733532373d202263}
		 $hex588= {24733532383d202263}
		 $hex589= {24733532393d202263}
		 $hex590= {247335323d2022242b}
		 $hex591= {24733533303d202263}
		 $hex592= {24733533313d202263}
		 $hex593= {24733533323d202263}
		 $hex594= {24733533333d202263}
		 $hex595= {24733533343d202263}
		 $hex596= {24733533353d202263}
		 $hex597= {24733533363d202263}
		 $hex598= {24733533373d202263}
		 $hex599= {24733533383d202263}
		 $hex600= {24733533393d202263}
		 $hex601= {247335333d20222432}
		 $hex602= {24733534303d202263}
		 $hex603= {24733534313d202263}
		 $hex604= {24733534323d202263}
		 $hex605= {24733534333d202263}
		 $hex606= {24733534343d202263}
		 $hex607= {24733534353d202263}
		 $hex608= {24733534363d202263}
		 $hex609= {24733534373d202263}
		 $hex610= {24733534383d202263}
		 $hex611= {24733534393d202263}
		 $hex612= {247335343d20222429}
		 $hex613= {24733535303d202263}
		 $hex614= {24733535313d202263}
		 $hex615= {24733535323d202263}
		 $hex616= {24733535333d202263}
		 $hex617= {24733535343d202263}
		 $hex618= {24733535353d202263}
		 $hex619= {24733535363d202263}
		 $hex620= {24733535373d202263}
		 $hex621= {24733535383d202263}
		 $hex622= {24733535393d202263}
		 $hex623= {247335353d20222429}
		 $hex624= {24733536303d202263}
		 $hex625= {24733536313d202263}
		 $hex626= {24733536323d202263}
		 $hex627= {24733536333d20222d}
		 $hex628= {24733536343d202243}
		 $hex629= {24733536353d202263}
		 $hex630= {24733536363d202243}
		 $hex631= {24733536373d202263}
		 $hex632= {24733536383d20222f}
		 $hex633= {24733536393d20223f}
		 $hex634= {247335363d20222433}
		 $hex635= {24733537303d20223f}
		 $hex636= {24733537313d202264}
		 $hex637= {24733537323d202264}
		 $hex638= {24733537333d202225}
		 $hex639= {24733537343d202225}
		 $hex640= {24733537353d202260}
		 $hex641= {24733537363d202265}
		 $hex642= {24733537373d20223f}
		 $hex643= {24733537383d202245}
		 $hex644= {24733537393d202245}
		 $hex645= {247335373d20222426}
		 $hex646= {24733538303d202245}
		 $hex647= {24733538313d20223f}
		 $hex648= {24733538323d202245}
		 $hex649= {24733538333d202265}
		 $hex650= {24733538343d202245}
		 $hex651= {24733538353d202245}
		 $hex652= {24733538363d202225}
		 $hex653= {24733538373d20222e}
		 $hex654= {24733538383d202245}
		 $hex655= {24733538393d202221}
		 $hex656= {247335383d20222324}
		 $hex657= {24733539303d202227}
		 $hex658= {24733539313d20222d}
		 $hex659= {24733539323d202266}
		 $hex660= {24733539333d202266}
		 $hex661= {24733539343d202227}
		 $hex662= {24733539353d202247}
		 $hex663= {24733539363d202247}
		 $hex664= {24733539373d202247}
		 $hex665= {24733539383d202247}
		 $hex666= {24733539393d202247}
		 $hex667= {247335393d20222433}
		 $hex668= {2473353d2022292a29}
		 $hex669= {24733630303d202247}
		 $hex670= {24733630313d20227b}
		 $hex671= {24733630323d20222f}
		 $hex672= {24733630333d202248}
		 $hex673= {24733630343d202225}
		 $hex674= {24733630353d20222d}
		 $hex675= {24733630363d202248}
		 $hex676= {24733630373d202268}
		 $hex677= {24733630383d202268}
		 $hex678= {24733630393d20227b}
		 $hex679= {247336303d20222427}
		 $hex680= {24733631303d202268}
		 $hex681= {24733631313d202268}
		 $hex682= {24733631323d20223a}
		 $hex683= {24733631333d20222c}
		 $hex684= {24733631343d202249}
		 $hex685= {24733631353d20223a}
		 $hex686= {24733631363d20222a}
		 $hex687= {24733631373d20222f}
		 $hex688= {24733631383d20226b}
		 $hex689= {24733631393d20226b}
		 $hex690= {247336313d20222429}
		 $hex691= {24733632303d20227b}
		 $hex692= {24733632313d20226b}
		 $hex693= {24733632323d20227b}
		 $hex694= {24733632333d202221}
		 $hex695= {24733632343d20226c}
		 $hex696= {24733632353d202229}
		 $hex697= {24733632363d202226}
		 $hex698= {24733632373d20226c}
		 $hex699= {24733632383d20224c}
		 $hex700= {24733632393d20224c}
		 $hex701= {247336323d20222426}
		 $hex702= {24733633303d20224d}
		 $hex703= {24733633313d202227}
		 $hex704= {24733633323d20224e}
		 $hex705= {24733633333d20226e}
		 $hex706= {24733633343d20226e}
		 $hex707= {24733633353d20227b}
		 $hex708= {24733633363d20223d}
		 $hex709= {24733633373d20226e}
		 $hex710= {24733633383d20226e}
		 $hex711= {24733633393d20225e}
		 $hex712= {247336333d2022242b}
		 $hex713= {24733634303d20224e}
		 $hex714= {24733634313d20222b}
		 $hex715= {24733634323d20224f}
		 $hex716= {24733634333d20224f}
		 $hex717= {24733634343d20224f}
		 $hex718= {24733634353d202228}
		 $hex719= {24733634363d202250}
		 $hex720= {24733634373d20227e}
		 $hex721= {24733634383d202270}
		 $hex722= {24733634393d202270}
		 $hex723= {247336343d2022242c}
		 $hex724= {24733635303d202250}
		 $hex725= {24733635313d20227c}
		 $hex726= {24733635323d202250}
		 $hex727= {24733635333d202270}
		 $hex728= {24733635343d202221}
		 $hex729= {24733635353d20227d}
		 $hex730= {24733635363d20227b}
		 $hex731= {24733635373d202271}
		 $hex732= {24733635383d20227b}
		 $hex733= {24733635393d202271}
		 $hex734= {247336353d2022242b}
		 $hex735= {24733636303d202271}
		 $hex736= {24733636313d202272}
		 $hex737= {24733636323d202272}
		 $hex738= {24733636333d202272}
		 $hex739= {24733636343d20227b}
		 $hex740= {24733636353d20227e}
		 $hex741= {24733636363d202226}
		 $hex742= {24733636373d202253}
		 $hex743= {24733636383d202273}
		 $hex744= {24733636393d20227b}
		 $hex745= {247336363d2022242b}
		 $hex746= {24733637303d202273}
		 $hex747= {24733637313d202273}
		 $hex748= {24733637323d202273}
		 $hex749= {24733637333d202273}
		 $hex750= {24733637343d202274}
		 $hex751= {24733637353d20227b}
		 $hex752= {24733637363d20227d}
		 $hex753= {24733637373d20227b}
		 $hex754= {24733637383d20227d}
		 $hex755= {24733637393d20227d}
		 $hex756= {247336373d2022242f}
		 $hex757= {24733638303d20227e}
		 $hex758= {24733638313d202275}
		 $hex759= {24733638323d202276}
		 $hex760= {24733638333d202256}
		 $hex761= {24733638343d202276}
		 $hex762= {24733638353d202276}
		 $hex763= {24733638363d202276}
		 $hex764= {24733638373d20227b}
		 $hex765= {24733638383d20225b}
		 $hex766= {24733638393d20227c}
		 $hex767= {247336383d2022242b}
		 $hex768= {24733639303d202276}
		 $hex769= {24733639313d202277}
		 $hex770= {24733639323d202277}
		 $hex771= {24733639333d202257}
		 $hex772= {24733639343d202277}
		 $hex773= {24733639353d20227c}
		 $hex774= {24733639363d202277}
		 $hex775= {24733639373d20227c}
		 $hex776= {24733639383d20227e}
		 $hex777= {24733639393d20227c}
		 $hex778= {247336393d2022242d}
		 $hex779= {2473363d2022212024}
		 $hex780= {24733730303d20227c}
		 $hex781= {24733730313d20227e}
		 $hex782= {24733730323d20227d}
		 $hex783= {24733730333d202277}
		 $hex784= {24733730343d202278}
		 $hex785= {24733730353d202258}
		 $hex786= {24733730363d202278}
		 $hex787= {24733730373d202278}
		 $hex788= {24733730383d202278}
		 $hex789= {24733730393d202278}
		 $hex790= {247337303d2022242f}
		 $hex791= {24733731303d20227d}
		 $hex792= {24733731313d20227c}
		 $hex793= {24733731323d20227d}
		 $hex794= {24733731333d202278}
		 $hex795= {24733731343d202278}
		 $hex796= {24733731353d20227d}
		 $hex797= {24733731363d20227e}
		 $hex798= {24733731373d202278}
		 $hex799= {24733731383d202259}
		 $hex800= {24733731393d202279}
		 $hex801= {247337313d2022242c}
		 $hex802= {24733732303d202279}
		 $hex803= {24733732313d202279}
		 $hex804= {24733732323d202279}
		 $hex805= {24733732333d202279}
		 $hex806= {24733732343d202279}
		 $hex807= {24733732353d202279}
		 $hex808= {24733732363d20227d}
		 $hex809= {24733732373d20227e}
		 $hex810= {24733732383d20227e}
		 $hex811= {24733732393d20227b}
		 $hex812= {247337323d2022242b}
		 $hex813= {24733733303d20227d}
		 $hex814= {24733733313d20227c}
		 $hex815= {24733733323d20227d}
		 $hex816= {24733733333d202279}
		 $hex817= {24733733343d20227a}
		 $hex818= {24733733353d20227a}
		 $hex819= {24733733363d20227e}
		 $hex820= {24733733373d20227e}
		 $hex821= {24733733383d20227e}
		 $hex822= {24733733393d20227a}
		 $hex823= {247337333d2022242d}
		 $hex824= {24733734303d20227d}
		 $hex825= {24733734313d20227b}
		 $hex826= {24733734323d20225d}
		 $hex827= {24733734333d20227c}
		 $hex828= {24733734343d20227a}
		 $hex829= {24733734353d20227a}
		 $hex830= {24733734363d20227a}
		 $hex831= {24733734373d20227d}
		 $hex832= {24733734383d20227d}
		 $hex833= {24733734393d20227a}
		 $hex834= {247337343d2022242b}
		 $hex835= {24733735303d20227c}
		 $hex836= {247337353d20222423}
		 $hex837= {247337363d20222121}
		 $hex838= {247337373d2022242d}
		 $hex839= {247337383d2022242b}
		 $hex840= {247337393d2022242f}
		 $hex841= {2473373d2022242524}
		 $hex842= {247338303d20222437}
		 $hex843= {247338313d2022242d}
		 $hex844= {247338323d2022242d}
		 $hex845= {247338333d2022242f}
		 $hex846= {247338343d2022242f}
		 $hex847= {247338353d2022243d}
		 $hex848= {247338363d2022242d}
		 $hex849= {247338373d2022242f}
		 $hex850= {247338383d20222f2e}
		 $hex851= {247338393d20222127}
		 $hex852= {2473383d2022242428}
		 $hex853= {247339303d2022302e}
		 $hex854= {247339313d20223030}
		 $hex855= {247339323d20222529}
		 $hex856= {247339333d2022272b}
		 $hex857= {247339343d20222123}
		 $hex858= {247339353d2022282b}
		 $hex859= {247339363d20222328}
		 $hex860= {247339373d20222323}
		 $hex861= {247339383d20222628}
		 $hex862= {247339393d20222321}
		 $hex863= {2473393d2022242426}

	condition:
		107 of them
}
