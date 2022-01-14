
/*
   YARA Rule Set
   Author: resteex
   Identifier: Keybase 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Keybase {
	meta: 
		 description= "Keybase Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_03-22-55" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0025f47ccdc62cda4728a810fd55c259"
		 hash2= "0085fce371a1ede1b06abea9556da2d7"
		 hash3= "025c2edef433d0f01ceee62b20ca6b1e"
		 hash4= "0286b8ff44c5fe79518c6b1f0202f303"
		 hash5= "06621a0c8f57b92453c8f7bc14836e7f"
		 hash6= "06c721a25134d0abd4e8efe4148e4f17"
		 hash7= "06e316fbc014393ae5479e74e15b00e4"
		 hash8= "0916d5cd92b182d9171eeec4e5a307f8"
		 hash9= "0ae6fff5c49a4ef8cd07350bc4d86fb2"
		 hash10= "0b2609158107c0b4096e982f4bd1510e"
		 hash11= "0b8c53eae43b6e47a4fd2d771dfff286"
		 hash12= "0cb7519ed6356b43ae9be3cab4aac265"
		 hash13= "0d8229f74515a4197337930cadfa0fb6"
		 hash14= "0e439b0a13484c42d35fdc28a33ffd7c"
		 hash15= "10049b9a2517757b526f095350114f29"
		 hash16= "11773771da1755d96426433720379d87"
		 hash17= "12279b5f7dec39f2ece83ae30fc5c56c"
		 hash18= "127ce91fadb48409913c871ac8e34b61"
		 hash19= "136fe4f53740b169b86aa6d182b8a1cb"
		 hash20= "15f99806b4fa0265f96bfefb1f47aa77"
		 hash21= "1613116b93b5e41f359d8451a25b76bd"
		 hash22= "163b21b084d56d6e884c22f79e277776"
		 hash23= "19533d6bec8dfb16b306b92b32ae77fa"
		 hash24= "19d00ac1945c199efc59ba79618aa770"
		 hash25= "1adc95ffe3432fe2f9f36df6b5775018"
		 hash26= "1c08acf1984e4e73a248e21e653f2bee"
		 hash27= "1c41bc77091d0c93b80032b16bf5393c"
		 hash28= "1d1589ab6aad7b9002747843122d8993"
		 hash29= "1dac5cac5d95282e59a92bef826c7e01"
		 hash30= "1e67161e25f2da255747d68e31305164"
		 hash31= "1ec3205deb879d9c90b8c2cfbc3dc5b1"
		 hash32= "1fd445c1d4dc21794257e6152d78d788"
		 hash33= "2159e0ce01e71812fadb2394e91d6575"
		 hash34= "21bb689d9ba5bf5a8cfa0f8ad44d1dcf"
		 hash35= "22fdeac8c3a841ef2ed6c86f74415ef9"
		 hash36= "2330844ca11166d05f401687d61d626b"
		 hash37= "23497ced7b7d566582ab3a4f0978c830"
		 hash38= "235668789a15600b5570641e9d6e9d49"
		 hash39= "248b2cc5b0f2eab732874392e190529e"
		 hash40= "24ce69f2ad9cdbf756f2df6dd319473b"
		 hash41= "262ddd014ace4156db69423b22fcfcec"
		 hash42= "2a1f1f75f20917dbb78356b5c3e2b00a"
		 hash43= "2a89e4d883b26e3f29e962d21cc1f892"
		 hash44= "2be5dde66764faffb3deadd8137a86b7"
		 hash45= "2d4f7f797c225730453449da2a27fc35"
		 hash46= "2d9f0da50b6e6115bb3f26eea2c9f94d"
		 hash47= "2dbb412ca05ca0522eb18206f91b9b68"
		 hash48= "2e1d207b1d84495e7a8c8f3deee00940"
		 hash49= "2e820085ef625a2a70cebdabe2816c97"
		 hash50= "2eefd7bf3f65b2da3e858c5f1c791f7d"
		 hash51= "3073dbafbfb78052cd56870281d27099"
		 hash52= "312da215b1d65d7f3db5326fa6625645"
		 hash53= "32f82aeda7c02e120b8eac471f08609b"
		 hash54= "330f99521f28df61dc79f864cf8687d9"
		 hash55= "3369a089956df7a288a76d5ffcb01256"
		 hash56= "33d259e6b5d606894df71e46b9f3ca1f"
		 hash57= "34f16d8b52debce875babbc22f206bcb"
		 hash58= "35727b89990fb7f86413243f1a5d9e06"
		 hash59= "359653a99d7492747b23e7db3ce06f1b"
		 hash60= "35f049477ec93b5a3845154ebc5e70e5"
		 hash61= "375c38b4930a38a7aa8f89b7270e504b"
		 hash62= "382de4a09f853ffce7c02cc1ce7568ab"
		 hash63= "38d124b95c2b198f8a682db00a04c1c0"
		 hash64= "3b4d39cbccf84a11e0b7d3950c7922bd"
		 hash65= "3cab07eb40f0120eb3768fdb16ce5cd1"
		 hash66= "3cc7e765c18a8fb3a61d24ea48344e64"
		 hash67= "3d8a30d37db18b432d1306b6b3e90dd8"
		 hash68= "3dc28abf8dd21e3c2144b9a62bcfcff2"
		 hash69= "3e93047f14591c77e96c9f5886751e32"
		 hash70= "40c24aa1051b0ab23965d1a8bc625407"
		 hash71= "434247d3739f8dd33d3f851657a7395e"
		 hash72= "438625ce2058da74aa55baaae9837b67"
		 hash73= "4601560f41d81b34144e257fc6227dc5"
		 hash74= "46db1dc90dec12c831f04df3151512e7"
		 hash75= "47241b232e909b7a263d4229cf229b17"
		 hash76= "48e3106e5d11044ada08abf3bbc844b2"
		 hash77= "490bb7d587cb1a017be2062432250e1e"
		 hash78= "4a18f5a5c26efc227f9b9dfdfbfcc4b1"
		 hash79= "4a203099385e02b713afe70ad11a5424"
		 hash80= "4b4404eec443c0d3d8dd409559f2ba68"
		 hash81= "4ba453f09098d766b6980c472f8d954c"
		 hash82= "4bc4dfcc21c751cc5e822e461f841504"
		 hash83= "4c3a28e5edb3cd4cf787e818c028a977"
		 hash84= "4f2c46e6843f7403b267f9694539cb80"
		 hash85= "50cc47f5d4168801f6a8469e26701299"
		 hash86= "50eb8f9c1d45b25499d8699b4eb606bc"
		 hash87= "51b6fe2b1070d6d436df70a649eea0cd"
		 hash88= "553481457aeb500f36c7b8833c3bb45a"
		 hash89= "56208f5153e7ac500be13b3d829c51da"
		 hash90= "56a48b0add4192ef886e0032db4af699"
		 hash91= "5d042919671ebd8ef63cb54e64d8f257"
		 hash92= "5de2ef6a424ba2a504af48aa0d7cc358"
		 hash93= "5df390114ec902c0195dbc681a9439c5"
		 hash94= "5f21f6a3bbed984f9adda35a8562fc22"
		 hash95= "5f804dea3cd2a224193a912448d9b92a"
		 hash96= "627e8e1379b7b1ddbb7c38b8be9442de"
		 hash97= "62c8f27f3aa005c0da384c4b5e8baebb"
		 hash98= "6405e8c438292da75a0fbfa171bfbad1"
		 hash99= "6408e300b6d43179689d9798810c72e3"
		 hash100= "6427c98833c6cc728387d6b5beaf71bb"
		 hash101= "64bb0e61d7a4dcc4c8d2f461aa47de2c"
		 hash102= "6793e73474501ffe7b9d1b0f63d3de42"
		 hash103= "68aaff66c5f1c43bfe75c8e868b3b37e"
		 hash104= "6b4ef861fde33af4dfe65a9e06efb8b3"
		 hash105= "6bab396d859cf7877caea58e6bcb99ec"
		 hash106= "6c40711c3b670c9adb936c39eb92af0a"
		 hash107= "6ca4e1b9addc4f70a42f96ae9dc49ca9"
		 hash108= "6d70324d1d771c75b64c7402d9e181ee"
		 hash109= "6e3ceca8544e25a7509aea5deb1ee36e"
		 hash110= "70456057c20d2161c2dcf8a5d5a6a3a2"
		 hash111= "716afbf79ec3f163143dc91b459b50dc"
		 hash112= "71ac2eb1595cd74e37ad10e8080fccad"
		 hash113= "71ec599e8db00a6763a78b4e70f127ce"
		 hash114= "7223810710dd199393d5cc693589f331"
		 hash115= "722527d3a7566b06fb961cf199513b23"
		 hash116= "722a584ab1fc94a6c552e5188c0ed1f0"
		 hash117= "72edd56079e6fd30a646178bc5af1836"
		 hash118= "73f8c55df4e40b8100b7db414dd8d95e"
		 hash119= "73fcd8d1e7a236c748a044f182f4cfdc"
		 hash120= "7597a055c52e93538e035e0d3523dbad"
		 hash121= "75e0e30b4111db14ad6e33d5acd6a192"
		 hash122= "765d5ddbeee593262d3c2fd24c3a9129"
		 hash123= "7763fc5fb7e3025dd95f47ae8db6ebb9"
		 hash124= "781194c603b34af28f29716d4c6c9a61"
		 hash125= "7935966c946e27daabcf57cef744f663"
		 hash126= "7ab9e89d612951d753b7b56949ceb4e0"
		 hash127= "7d20309e3887f24eff6c54994dfe214b"
		 hash128= "7d66a6d540a9601eac3cc5f4a1b0be8e"
		 hash129= "7ddbd9e53ee07b2585dcc683664715ff"
		 hash130= "7eb91cd82392a9c0605d3c6a6ec790f8"
		 hash131= "7efb4301749b72ab0be1b580c3bc7a4b"
		 hash132= "7ff87b419dd0fcefac4751c90219bcff"
		 hash133= "8001b286f930bc44e5e9feea87b67ae0"
		 hash134= "807a3b24c3db0ed3443bbe05cdf60acf"
		 hash135= "81c488e4935db94569a4df415073f07d"
		 hash136= "83da66f033d73ece42f37946a9547bca"
		 hash137= "841a0c10284724df2f81c27490a5f885"
		 hash138= "8551c1d18ec56779434bcb21d2ec96d7"
		 hash139= "865fdc977542ee9d2c91850240e8a261"
		 hash140= "86d16a2a395008e103794036dcd1b02b"
		 hash141= "875c3cb85718c9c0fdd116737944dbac"
		 hash142= "8815912a400d1fe6caaa8050d96dc152"
		 hash143= "8e4baf639d7438b56dcbc350d498ed13"
		 hash144= "907b778538c0d85e7f54fbeed4f5bb05"
		 hash145= "91789eade7e19953a49e1f5ed71331cb"
		 hash146= "91acac64f299146bba49290e7c8d3bba"
		 hash147= "9226c8146bd9b88237e8f770fb007f16"
		 hash148= "9271bbe487d1c4782ce0d25905c6c8ba"
		 hash149= "93e739251a2297c42cf98d391e6bfcfa"
		 hash150= "9482a31844d2ca0191cd3d98c41c4645"
		 hash151= "94bbefb49b735af286f714653d07b6f5"
		 hash152= "94c5b914bd62aeb0277270985504793e"
		 hash153= "96ba6e66ce05f1cfd933238d5e8c7e9d"
		 hash154= "97f5379acded23175b45b297123d2690"
		 hash155= "9aefc5c72083d5a132b2bb577ce02d64"
		 hash156= "9b692e6cefa82bbca00b62af89c460b1"
		 hash157= "9c2592f60895cea91aa5d5c6f6cf119c"
		 hash158= "9de7a79f4c72fb9a384c4efad352bb4d"
		 hash159= "9ed5b41f64a6f635f8e7769396940dc4"
		 hash160= "9fe9c29fb594dcff115bdcbb9cd755a2"
		 hash161= "a0728536a9ac9092ce3f7b6e185c9058"
		 hash162= "a2427ec2e171fb5d266f3b12992a4f7e"
		 hash163= "a287aebf273d86b1ca9bdc648d9535b5"
		 hash164= "a2b0883752e5d4d1aa24a6f99a3afdb7"
		 hash165= "a31cde1b7f2304dfcdbb565c76611188"
		 hash166= "a3b93bf6d9082f5d00fba0184361464d"
		 hash167= "a3db0d97afc676cca7fe1f91e6692aea"
		 hash168= "a41b95c2bcc1b0b05e9e3daeb012ad8f"
		 hash169= "a5a1b45d9ec6fb65f263b8c2894e6539"
		 hash170= "a5ebe6f9b8bf2b6ff3eddced16e16bd3"
		 hash171= "a62e5074cac1e6693292a4d98f596bb9"
		 hash172= "a7145c598ef1bee7fa860200ccfa7ba5"
		 hash173= "a7552ad10f86bedc62e90b2f98d0c6aa"
		 hash174= "a88122995dcf666254b09c63afb34ee4"
		 hash175= "a90cb5fae1f41e0dc0ff71b012dd63e3"
		 hash176= "a96270e219b606cb1615e6d993e22c0a"
		 hash177= "aa71026ccf379412c45e8a06274904b7"
		 hash178= "ab0df8dc6fe006b5be75fe7ff65b6fec"
		 hash179= "ac5c41e92c1df0b0dde8a005e84015a4"
		 hash180= "adc8595164e60aaa7225e35fcd8265aa"
		 hash181= "adf15e25a779555912551899fe574578"
		 hash182= "ae5e56379c97571ce57c3e95848815af"
		 hash183= "ae68f1df7492087a86558ecc04e84992"
		 hash184= "aea88a9792e66bedf586aabff931ee31"
		 hash185= "afe182302369ee4b13f78c30bca444e9"
		 hash186= "b02a30dfe3ff99d36ae777240425a924"
		 hash187= "b06b4b650baff9aec768c81e50e549f1"
		 hash188= "b0eaaaf86ff1e2856a338500d8efbec5"
		 hash189= "b15f200e620e324fed14576655aec58f"
		 hash190= "b240082414bdeaf47e8f0d56729c9488"
		 hash191= "b462240790639e40ebbe61903a18e52c"
		 hash192= "b50f97bbd6338062ade159361bbf556b"
		 hash193= "b61770ea2d26efbb66b8382c4ca38d71"
		 hash194= "b85697343a74cda99ff18c7e0c4cd04a"
		 hash195= "b865c8524f4e0c2f4d1488999a745aa6"
		 hash196= "b93606bef3a57945b8af47c6c6556380"
		 hash197= "ba4b9ea95458b6c4be06b9aa9d078c81"
		 hash198= "bb68c0c946e85607032dc5bc0d52ee11"
		 hash199= "bc65b8235910edaa14f4c885a4242d13"
		 hash200= "bd2c79dfce6ede89a414d317a7bdf60e"
		 hash201= "bef652cc9c4647304aa96b7d31241e7a"
		 hash202= "c0c56453dc7f2004bf44af58bf84b541"
		 hash203= "c0cf20619a43af1ae2dfff97538b59c3"
		 hash204= "c1ea64a12aec08e44f30fe060de8c81c"
		 hash205= "c25d2c656a6a9f1d09c9a041684a333b"
		 hash206= "c3d93cbe405d6789ab6e24230f9bd550"
		 hash207= "c46a626e09b473f47a064630b2ea3882"
		 hash208= "c48b4a16f06704d559ff133b05a49958"
		 hash209= "c4fe6ae3a824e44224235277d81e1083"
		 hash210= "c5580be418499a3ac7633148d9cbd900"
		 hash211= "c7340edf2dc29fa0724bd4e4cbee9b1e"
		 hash212= "c7b6c3c4011ca53b72031aa605ad31a7"
		 hash213= "c85b8ad675eb1315f9896430d052eb77"
		 hash214= "c8a625908d8d20db50aacf51e456ff97"
		 hash215= "c8d4e6e155fc7325ac31387e018c9cc0"
		 hash216= "ca25eebcf443ff49407a902576f60113"
		 hash217= "cadb0b51374037529efa5c7146c56445"
		 hash218= "cbaaba6837354f577bc2b8a39e9fcd2e"
		 hash219= "cc3bd9a39f6d6ae9cb3c7f72c6f6b3d7"
		 hash220= "cc6bd8fd3d6773f16a3532c8568f3030"
		 hash221= "cfe2a5748cf6bb37cbbcadbd1564a29b"
		 hash222= "d048eb0a0dcda6291f482b0e6f3b896c"
		 hash223= "d112c343963e3c8d9db3d98c2cee408c"
		 hash224= "d16e16ce1e75c6401098598ebc6cc6e7"
		 hash225= "d1f7f34dc09de320d01ce024450eed21"
		 hash226= "d2f5ac1125893560f382ed756d8254dc"
		 hash227= "d551c45d0eb1435885f06e6e2e49236a"
		 hash228= "d6f39fe913e643754685623a3509710e"
		 hash229= "d7e6e42f2893583bdfaaef3b6b73b8b5"
		 hash230= "d7ed94b5c19f6d6fdd1a6a366843a65a"
		 hash231= "d88f82932a206a689060e729df46bafa"
		 hash232= "d8d802955df5136d9e2862008552afa7"
		 hash233= "d9fb840f6c117637a557f7990361fede"
		 hash234= "da2a62e264823c07ca8eee31dca0ec20"
		 hash235= "da3d06ddd705bc81caff734b947c64d9"
		 hash236= "dd655d126f33403e1d8af14d44f2f2c0"
		 hash237= "de5166f454531a4249c309e86d9443f9"
		 hash238= "e1a974cd5f55c6e35fc1e4365551f60b"
		 hash239= "e2562e803089f8f7b0816d424402c816"
		 hash240= "e2f0585ba2e437aa90921f2a70c4319d"
		 hash241= "e451dc9d2482c3d63b842cabb61b5d19"
		 hash242= "e50023b081d3006f3b2d3bfe6a3c2fd3"
		 hash243= "e855d0e0fbfab7b84fa98d7f1fe3577c"
		 hash244= "e8fa4d8f0ca02fb0f075f15f4fb2d842"
		 hash245= "e9fe7632a0fa3a9cc39c3e32f9475143"
		 hash246= "ebf194bdf40ab582488dc154a9013b05"
		 hash247= "ec5e58c62809699190b10c14e1985b1f"
		 hash248= "ed70c955d8e67bc94ee0f0ae95573ecb"
		 hash249= "ef11da093df255218dfa4aa4d34e2b94"
		 hash250= "f0fe846119c55a24e1f685c29c1c9821"
		 hash251= "f2665007be1099b5f005340dd9f44b67"
		 hash252= "f2820aae069a34d559b3ebbc34a9a695"
		 hash253= "f3400f446ffd61a9d095084436773d02"
		 hash254= "f52f1c23710eefd2552da368c4b3b295"
		 hash255= "f736d098c31084802a20af77637a1edc"
		 hash256= "f83a4472aed80a4cb02ce97e8889dea0"
		 hash257= "fa6f24a18ef772d9cdaa1d6cd1e24d1b"
		 hash258= "fb4c20fadbe2038805bab64dcdbb8ff4"
		 hash259= "fcea93eda07673489444ba10e4cc49c1"
		 hash260= "ff2bb6281c39ba613fe682a54358ce66"
		 hash261= "ff7487d6f07a985c7345617e2d475a70"

	strings:

	
 		 $s1= "$7s8~Ns" fullword wide
		 $s2= "$jD$ownloadercon$figdataba$se.sc$ript" fullword wide
		 $s3= "$jDow$nloader$configdat$abase.scr$ipt" fullword wide
		 $s4= "$po$st$.$ph$p$?$ty$pe$=$cl$ip$boa$rd&$mac$hine$nam$e=$" fullword wide
		 $s5= "$pos$t$.$p$hp$?$typ$e$=$pas$s$wo$rds&$mach$inen$ame$=$" fullword wide
		 $s6= "$pos$t$.$ph$p$?$ty$p$e$=$k$eys$tro$ke$s$&$mac$hi$ne$na$me$=$" fullword wide
		 $s7= "$pos$t.$p$hp$?$typ$e=$not$ific$a$tion$&$mac$h$in$e$n$a$m$e$=$" fullword wide
		 $s8= "{0269af5b-03d9-449d-a64f-9ee9eee24dd2}" fullword wide
		 $s9= "11a4057ed23bb`6d95e0115 6boTJ$Q]U,^V^3a@2cg" fullword wide
		 $s10= "1`a`ft30f0a0619;853o7l8495ab4.821qab" fullword wide
		 $s11= "1n92I_.n*^g|x{:2h01f99Ia.j*]gbxx:,h2" fullword wide
		 $s12= "{202a7ba0-a2e5-48a6-a568-6a0fa2de5cd5}" fullword wide
		 $s13= "2XKgW8CCxKbxKDiV8r.hRvElsZq6Utc4CA5lx" fullword wide
		 $s14= "348ZpQsCtrxeI9d+uPjqokLvRoLPfYRBJoe3m4PcOJs=" fullword wide
		 $s15= "4dr/^6;%Gev?1:ETy=4ev+^2{!F7(MwS-11SR" fullword wide
		 $s16= "{5c4de5df-cc4c-4fa8-851d-6943256ba688}" fullword wide
		 $s17= "{719de34a-5634-4393-b054-2ea4ab3e35bc}" fullword wide
		 $s18= "72e3e94=3`44821babf631fva5`WKqQ[V-Y" fullword wide
		 $s19= "93qzSObxo+WgrRIGevX6c5TrhjfyRQ0pcwknU3uptU4=" fullword wide
		 $s20= "9iMA8LEX6nwjRuE+U5AreJPr3nIrNnVaSnaiH1KmULc=" fullword wide
		 $s21= "{a9707044-d625-429a-86be-04257c4ac3bc}" fullword wide
		 $s22= "aa2f3154-59f8-4525-a929-20612413a416" fullword wide
		 $s23= "{b2ccd7ac-ee82-49ad-a9e5-ca3e761a0354}" fullword wide
		 $s24= "bindingNavigatorMoveFirstItem.Image" fullword wide
		 $s25= "bindingNavigatorMovePreviousItem.Image" fullword wide
		 $s26= "BL #k,Olmp28{]zu6mO^)=b%Ogmy27xTx~4dMi+" fullword wide
		 $s27= "bLO6FfT4b96rbEY8Eu.Xw4oDREZabO4VveMBp" fullword wide
		 $s28= "C6ksYcUmjyJbO2QKntippXkprDMUV8IyJckFmnf2amH" fullword wide
		 $s29= "{cf303ac8-65ff-47a1-bdad-88a2e45caad6}" fullword wide
		 $s30= "CmZ0nY9JPRe34M5hOXFDXFbn/tswWKXBdBdLK3DPzLY=" fullword wide
		 $s31= "....CoreCommonsrcclothClothCooker.cpp" fullword wide
		 $s32= "....CoreCommonsrcclothClothHierarchy.cpp" fullword wide
		 $s33= "....CoreCommonsrcclothClothMesh.cpp" fullword wide
		 $s34= "....CoreCommonsrcConvexHull.cpp" fullword wide
		 $s35= "cSst.AL/CpIDAlGh_0c`sx.JLmCwIGAtGk_(cb" fullword wide
		 $s36= "CwojnTXpXjst6NpsbA7aAWJ81f+jZ/vtPgBPtpsthn8=" fullword wide
		 $s37= "Cxd3t35XBiwFRcvHpb6QG/jXq+hiiU/kZnO9ckYG67o=" fullword wide
		 $s38= "DI_MPRECORD DI_MPSTEP DI_MPSTOP EN_MPBACK" fullword wide
		 $s39= "e4YRLLeRQnE5fnl1utvELXioriAv7CaMIYgxzhU" fullword wide
		 $s40= "e5gmdOVYxqSTSgTdNpKV5B8OvvxWJXZV9yos" fullword wide
		 $s41= "ebplqUsKEhQKpdmrfONF2PcZZWJnUJT0MOnsc" fullword wide
		 $s42= "edJ5qKYKg0nqIAMqTCAcPS+wk/9jvulvi++RdYzyLFo=" fullword wide
		 $s43= "eds0jDSXQxv0httSvgVbVCxmKqAVkfIJUXXq748W" fullword wide
		 $s44= "egGgklYGIgLQGhoPaGByl2piMHyLHtPszgCy0rl" fullword wide
		 $s45= "eHWuMUJgIi3YujXu1cJKTCNIzqZspe6Da0x" fullword wide
		 $s46= "eic;0w235gf=a19>c65;9833bed2cB93epc9" fullword wide
		 $s47= "eKLLbXGFUGzYiP1bhFJZ62zk4IOe449dUsRma" fullword wide
		 $s48= "elOGj81azTEoDz9mM5YBun2yPfasVOuIRLp" fullword wide
		 $s49= "ENp/LNy0qClYJ/zoRqtGc6YaGMaAkbeRSgGLHUJQomo=" fullword wide
		 $s50= "eoci32xSW4TgKhlVodrPZw35EpwwtiNFLBKo" fullword wide
		 $s51= "eVvzos0oFNL3oenpcyMd37DL3laiXdXVixZz" fullword wide
		 $s52= "{f37d932f-32c8-4b07-95b7-5c72d1474312}" fullword wide
		 $s53= "{fcded421-8ad6-4ebe-a4fc-e3874ad597ae}" fullword wide
		 $s54= "fCvLluWkCLgMCV8Xei9/OvT12iOJQZjG8mDJAUJxt3Q=" fullword wide
		 $s55= "{FEA94A50-E5C8-4edd-BE62-F738BC8C043E}" fullword wide
		 $s56= "fHmLMdUBgS6ZYR4usjrSQw0A+gRx9WoaO6XfIg9KVIM=" fullword wide
		 $s57= "FV6JePqQjjOQEAxnoz+3xmdgJpMFDRkCnh0Pzbx0GiQ=" fullword wide
		 $s58= "gW7afnYjl3t9VZbZGs.baahlFE5JPhmpVu1yk" fullword wide
		 $s59= "hGLsPuvgOqEMpSM+slFLWGRZmbgPBKKgfWkiBUWzXVI=" fullword wide
		 $s60= "HJ/IcW58jhMlbmMATBnag0VTbJ3IFmAAdpnQaM9FfTM=" fullword wide
		 $s61= "hP2NsJnDcgLPJnChZc7UJASAqXm2UtjjeV+aNb42a1/m9DNP4/wvzc7JrzQJ6es3" fullword wide
		 $s62= "http://108.175.156.78/~thaisupp/assets/" fullword wide
		 $s63= "http://108.175.156.78/~thaisupp/rack/" fullword wide
		 $s64= "http://108.175.156.78/~thaisupp/sense/" fullword wide
		 $s65= "http://108.175.156.78/~thaisupp/stress/" fullword wide
		 $s66= "http://108.175.156.78/~thaisupp/wack/" fullword wide
		 $s67= "http://accessoryinasia.com/keybase/" fullword wide
		 $s68= "http://aminedata.pe.hu/keybase/keybase/" fullword wide
		 $s69= "http://awilmelody.pe.hu/keybase/keybase/" fullword wide
		 $s70= "http://clashofclans-cheat.net/Admin/keybase/" fullword wide
		 $s71= "http://company777.wc.lt/keybase/keybase/" fullword wide
		 $s72= "http://destinyuband.esy.es/keybase/keybase/" fullword wide
		 $s73= "http://directexe.com/1e1bd78777c4b204/USB_Serial.exe" fullword wide
		 $s74= "http://elvira1983.zz.mu/keybase4/keybase/" fullword wide
		 $s75= "http://eventica.kg/wp-includes/css/keybase/" fullword wide
		 $s76= "http://ggdigduuzdgz.esy.es/keybase/keybase/" fullword wide
		 $s77= "http://keybase.ipservices-ltd.co.uk/" fullword wide
		 $s78= "http://keybasejasper.esy.es/keybase/keybase/" fullword wide
		 $s79= "http://keybasejasper.esy.es/logs/keybase/keybase/" fullword wide
		 $s80= "http://keybasepanel.hol.es/keybase/keybase/" fullword wide
		 $s81= "http://keystroke.zz.vc/keybase/keybase/" fullword wide
		 $s82= "http://mezilansakushmu.net/keybase/" fullword wide
		 $s83= "http://muzukashibrashinki.net/h55l/" fullword wide
		 $s84= "http://obamabigboy.esy.es/keybase/keybase/" fullword wide
		 $s85= "http://pepperdeybalms.com/keybasee/" fullword wide
		 $s86= "http://pindakaas1980.host22.com/Keybase/" fullword wide
		 $s87= "http://ressurectionplayerz.biz/mack/" fullword wide
		 $s88= "http://steelholdings.eu/dave/keybase/" fullword wide
		 $s89= "http://supportforpoors.zz.vc/unicorn/" fullword wide
		 $s90= "http://unicorndomain.pe.hu/unicorn/" fullword wide
		 $s91= "http://username14.esy.es/keybase/keybase/" fullword wide
		 $s92= "http://www.kyliewalksbase.com/keybase/" fullword wide
		 $s93= "http://www.polite.besaba.com/keybase/" fullword wide
		 $s94= "http://www.ressurectionplayerz.biz/mack/" fullword wide
		 $s95= "http://www.snowcoatsounds.com/keybase/" fullword wide
		 $s96= "http://www.tamwaytours.com/keybase/" fullword wide
		 $s97= "http://www.tempuri.org/DataSet1.xsd" fullword wide
		 $s98= "http://www.ugonna.besaba.com/keybase/" fullword wide
		 $s99= "http://xboxlivecodegenerator.info/facebook/keybase/" fullword wide
		 $s100= "IldM+jpQBfIDDggreXZ4cnORa+S/8++McF1geEwPNsg=" fullword wide
		 $s101= "]indo}sMiirosolt.NE^Frageworav2.:.50787csi.exe" fullword wide
		 $s102= "j0E2B0yCBYKM6nLaYV.7nLXbhPqXjkaGZ6dqx" fullword wide
		 $s103= "j8KMF+KcvurhRqeC3QPmwn5/ErYhLenf1ONPRjCOkac=" fullword wide
		 $s104= "jDownloaderconfigdatabase.script" fullword wide
		 $s105= "kfF52QqdFtOC0fz65oieulL2N/1lTm6MKlnv8Q4fZQc=" fullword wide
		 $s106= "KiRIfqn+1CWzQiRG6in4LX/Qcbu9VQ6Nf7ggoEzuZA0=" fullword wide
		 $s107= "KNVkjVZWMEInzCiOSgOJjMblu4F6IIwrI1Pek+vqsm0=" fullword wide
		 $s108= "KYqZDDkaxgOP9yS14LyEDMzYGXdHp6/MsC+sMUUVnpA=" fullword wide
		 $s109= "lTIiQbdpSZoHhfmnOMyMSSQ5InKJKD/DyplmaqiAJlY=" fullword wide
		 $s110= "mbESj2CRofh9wxSlxaxT5rXyJFCmXs6xyzJ" fullword wide
		 $s111= "MeineUnterlagen_Maerz_2015_10_03.exe" fullword wide
		 $s112= "MGQH6sVRvohMJ9WxJaOikcNGFicPGI5qPPfGhVpl+fo=" fullword wide
		 $s113= "Microsoft.NETFrameworkv2.0.50727vbc.exe" fullword wide
		 $s114= "mjBXmJYYp8sLFiJZCWuYLtQopx9KkQRtEW6ksYcUmjyJbO2QKntippXkp" fullword wide
		 $s115= "n/hoG6gqlIqlmz+eiEvINMwgYlMVRcGCvGBD5YY01Ck=" fullword wide
		 $s116= "NmT+KM8CETrrLIrYGp7R365BMWvN+fLl+vdm92tjh5M=" fullword wide
		 $s117= "nnnkkdiZ'(ll+l-./0l2kZk6im9JKLMNOPQRSTUVWXI" fullword wide
		 $s118= "Oj5D8kNqdZkwnskVOiJnrgUaJ/BRtgsoSt8LHp1ihP4=" fullword wide
		 $s119= "ONA0G0Ua/9r+OiPse+p7YnMdCBQdZPIdQd2KecScozU=" fullword wide
		 $s120= "OP5pBOMEfVXAQtsprw2gAVeGCvdkx76ionKO8BkYgjk=" fullword wide
		 $s121= "post.php?type=clipboard&machinename=" fullword wide
		 $s122= "post.php?type=keystrokes&machinename=" fullword wide
		 $s123= "post.php?type=notification&machinename=" fullword wide
		 $s124= "#po#st.#ph#p?#typ#e=p#assw#ords#&mach#inen#ame=#" fullword wide
		 $s125= "post.php?type=passwords&machinename=" fullword wide
		 $s126= "printPreviewToolStripMenuItem.Image" fullword wide
		 $s127= "q52YytCClwRt92O10aPvjiP6EsvrNvoLkhyYjy" fullword wide
		 $s128= "Q8heGp9ORwBtXOujyY/OhQ7unuxZvfUCagIezhPLUHA=" fullword wide
		 $s129= "qbcaMdssAY2hLwjRHZngQ9n3VPtUFbbLDV4n" fullword wide
		 $s130= "qDn475mQViANOZv3mULLgmhEdXBcdDVDYIl" fullword wide
		 $s131= "qHHALymgEWNrmE6kINhzjV9oSs0uagxTGgL" fullword wide
		 $s132= "qIs4atvXsa2gphidblgfqdiYXzanGOSkOLpvBwlI" fullword wide
		 $s133= "qnjyVB69XeoRspehzofGDXnayKNnvyBMniBc+lbD+Os=" fullword wide
		 $s134= "qqaaJjDqqW3BQ69dLRU9D7HTbuFwGthIkMGysfB" fullword wide
		 $s135= "qQfcTlqsdfqWd1NPWAZutoVKpu6oEji4Ge6p" fullword wide
		 $s136= "qqpugHpDtQkYC0zqWzZeCtaMHgLcFnejj8B0" fullword wide
		 $s137= "qS4FkhQ5tWsuX2BCw7kEBWowfWnFwEroWaud" fullword wide
		 $s138= "qsfgFXgDU7DdHISOEHEqIhlGAdDvK0OOIR39OS0l" fullword wide
		 $s139= "qtON8WpZdLSrc+sFu5c4+tAoKCE+Ix0P158IuLNUyjE=" fullword wide
		 $s140= "qvWQVEmnc7QW3xSDNZ42zNdm2XNMvQHDFSB" fullword wide
		 $s141= "qW56v7jgXDyCn3KNvfPwaqrgQzU9iqMAzxikJN" fullword wide
		 $s142= "qykHMWcZfi2K85KpklXBYCKMPY8SWMdYYnvHarS" fullword wide
		 $s143= "qzIZABTjHb79RKvPQW9DVgVhlmP7bXW00Kex" fullword wide
		 $s144= "rdWAty4fK5pdtUFsyfCFlaY7mBVVIOyEGFq" fullword wide
		 $s145= "re6ms92mvmGTsMFNRj0jPO4ZhMOSWtmvFCOCzTU" fullword wide
		 $s146= "rg1PYoyuBBmQNRNWkVL4bXXZTVunuc3RBPkATCW" fullword wide
		 $s147= "rIdGXO6crUOahQqJf8iDnHkvYtzPxT8YEXhj4" fullword wide
		 $s148= "rneGPCAsKJTq9wKtfaNxHgBLhtmXK2W6G3Ne" fullword wide
		 $s149= "r/nJiQwbqE5bKwU+YVpGr+bzt2of6DAPF1lamBRyrGo=" fullword wide
		 $s150= "rRFM05JRcFvzvNoUaxBN8t2xuIJAixVHYDPeK5" fullword wide
		 $s151= "rvRcjXKrEPbYkyYYfDpXGJdgfDGjMu1UgF9" fullword wide
		 $s152= "rVtxyZ7HRKY4HIKIoUsAJ4rRWvysQhpw3LP" fullword wide
		 $s153= "rWlSqRm3Yt4LikfkypoCcgkVui5oYfPVkbSysUsnNN5" fullword wide
		 $s154= "rYg0rXFFWoF11ykV7tocd6jNpSIYrGoqxXnqpikG" fullword wide
		 $s155= "S3yGNzjRULP9T8cTOIiKSCptbXvinnbvTwXczTw7Ykc=" fullword wide
		 $s156= "s+GJhVv_AVf_aF.ypha2QQ~]cVTazf}}.@pWa" fullword wide
		 $s157= "=size_t(Address)+NeededRam" fullword wide
		 $s158= ",S_KXKjG=3E_qG$uG*=MJQMB|L+:Ehq~$ND" fullword wide
		 $s159= "SoftwareDownloadManagerPasswords" fullword wide
		 $s160= "SoftwareMicrosoftWindowsCurrentVersion" fullword wide
		 $s161= "SoftwareMicrosoftWindowsCurrentVersionPoliciesSystem" fullword wide
		 $s162= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s163= "SoftwareMicrosoftWindows NTCurrentVersionWinlogon" fullword wide
		 $s164= "sqlDeleteCommand1.CommandDesignTimeVisible" fullword wide
		 $s165= "sqlDeleteCommand1.DesignTimeVisible" fullword wide
		 $s166= "sqlInsertCommand1.CommandDesignTimeVisible" fullword wide
		 $s167= "sqlInsertCommand1.DesignTimeVisible" fullword wide
		 $s168= "sqlSelectCommand1.CommandDesignTimeVisible" fullword wide
		 $s169= "sqlSelectCommand1.DesignTimeVisible" fullword wide
		 $s170= "sqlUpdateCommand1.CommandDesignTimeVisible" fullword wide
		 $s171= "sqlUpdateCommand1.DesignTimeVisible" fullword wide
		 $s172= "SYSTEMCurrentControlSetControlNlsLanguage" fullword wide
		 $s173= "System.Security.Cryptography.AesManaged" fullword wide
		 $s174= "System.Security.Cryptography.DESCryptoServiceProvider" fullword wide
		 $s175= "System.Security.Cryptography.RijndaelManaged" fullword wide
		 $s176= "tgh1CpUOixaCWoS0fMkxCsvh08yPR8mgilf" fullword wide
		 $s177= "thSeGAE4Uv9ntJLFWw4izMl8KxHovfIbvTmDL" fullword wide
		 $s178= "tLsCQLep5TJaazxpVgUhhtLsCQLep5TJaazxpVgUhheOUP6MsDNWeMRveSHtFjW" fullword wide
		 $s179= "tNdcuhmDIEABLmwz7dPm9ffqeAVwKGvAE3D" fullword wide
		 $s180= "tPXCUgLC2YLeXHRE5n7HCePHX8utMVjPnHLX" fullword wide
		 $s181= "tuzaL3LxQtj2oSMDFZoSmNyjBCrSSLzGlfIA" fullword wide
		 $s182= "UC1TJCjhntb9jehEvq3IIna/5CIe4fKzyGc5/KCPMLw=" fullword wide
		 $s183= "U_i=V`j>Wak?Xbl@YcmAZdnB[eoCfpD]gq" fullword wide
		 $s184= "Up3i8liyZI5Rpu684iiwHr/zoVbStt5Ej6IwQRoCGLo=" fullword wide
		 $s185= "urn:schemas-microsoft-com:xml-diffgram-v1" fullword wide
		 $s186= "uV0hEdnNnu8wIyaMWJRoQtwqImLtWpqGfE7/b3r/oFA=" fullword wide
		 $s187= "w7uyzsZvKOXMWxwHMY2P9dHSrUFj2yPDsaphd" fullword wide
		 $s188= "wFWDC8FczONDSxWYhiXdQRyeBJbCn4H3aups" fullword wide
		 $s189= "WinnowsGicroyoft.DETFxamewerkv8.0.5:727ivtrey.exe" fullword wide
		 $s190= "wjwEUO4FzIEJuEVfQwYRNV4Na1jML9tVsesRPt" fullword wide
		 $s191= "wLlSMvbdW4HoTMBBtToaNxurxsXVUbNH3BKbv6U" fullword wide
		 $s192= "wLNKaYO5suHXNfGwEhvAzmTv0RMhIcudHp1Eq" fullword wide
		 $s193= ":{+wmPUJ5XwX" fullword wide
		 $s194= "wowNjAoz0PKbdKq9QyDt8CuptCKqdNiSj8Tzx" fullword wide
		 $s195= "wTaLjKfI464dQWR83OfDyenaZXEXoKHpjNonv3" fullword wide
		 $s196= "wtIsIpn2oOcuwC7W6zGmcZooHHYqFwuNhoJl0" fullword wide
		 $s197= "wtWbDwGdLgKuzBCgCDIvXCPxGV5Ae3DYAVSLb" fullword wide
		 $s198= "ww8ngyo9KqkBPgDEGiLuLyrmDbGXhGEZhjmhiQ" fullword wide
		 $s199= "XW+YEwY7cRv1DNSX9zGIlxbALpOshPYljB3ahBssBg8=" fullword wide
		 $s200= "y3wuIylj2oEasjAWHJI1XnyeEwqcslWVdR6keLsmOxg=" fullword wide
		 $s201= "yjV7gixLaW1oM665aJ.ChCgHn3n7lSWpqA8JE" fullword wide
		 $s202= "YmkA1/OSPl6qATNj5hUO/nUFzMWr7xAQDxhF6NBz4BU=" fullword wide
		 $s203= "YuNSkoYuS0KZCceLuhpJqABF0AiIQTYtmc2KNUrbp8o=" fullword wide
		 $s204= "zU16Q+/ZZm1rSo8p5ZBDOEaGuLVk/G1EkGsPe4x66vY=" fullword wide
		 $a1= "$po$st$.$ph$p$?$ty$pe$=$cl$ip$boa$rd&$mac$hine$nam$e=$" fullword ascii
		 $a2= "$pos$t$.$p$hp$?$typ$e$=$pas$s$wo$rds&$mach$inen$ame$=$" fullword ascii
		 $a3= "$pos$t$.$ph$p$?$ty$p$e$=$k$eys$tro$ke$s$&$mac$hi$ne$na$me$=$" fullword ascii
		 $a4= "$pos$t.$p$hp$?$typ$e=$not$ific$a$tion$&$mac$h$in$e$n$a$m$e$=$" fullword ascii
		 $a5= "hP2NsJnDcgLPJnChZc7UJASAqXm2UtjjeV+aNb42a1/m9DNP4/wvzc7JrzQJ6es3" fullword ascii
		 $a6= "http://directexe.com/1e1bd78777c4b204/USB_Serial.exe" fullword ascii
		 $a7= "http://xboxlivecodegenerator.info/facebook/keybase/" fullword ascii
		 $a8= "]indo}sMiirosolt.NE^Frageworav2.:.50787csi.exe" fullword ascii
		 $a9= "mjBXmJYYp8sLFiJZCWuYLtQopx9KkQRtEW6ksYcUmjyJbO2QKntippXkp" fullword ascii
		 $a10= "SoftwareMicrosoftWindowsCurrentVersionPoliciesSystem" fullword ascii
		 $a11= "SoftwareMicrosoftWindows NTCurrentVersionWinlogon" fullword ascii
		 $a12= "System.Security.Cryptography.DESCryptoServiceProvider" fullword ascii
		 $a13= "tLsCQLep5TJaazxpVgUhhtLsCQLep5TJaazxpVgUhheOUP6MsDNWeMRveSHtFjW" fullword ascii
		 $a14= "WinnowsGicroyoft.DETFxamewerkv8.0.5:727ivtrey.exe" fullword ascii

		 $hex1= {246131303d2022536f}
		 $hex2= {246131313d2022536f}
		 $hex3= {246131323d20225379}
		 $hex4= {246131333d2022744c}
		 $hex5= {246131343d20225769}
		 $hex6= {2461313d202224706f}
		 $hex7= {2461323d202224706f}
		 $hex8= {2461333d202224706f}
		 $hex9= {2461343d202224706f}
		 $hex10= {2461353d2022685032}
		 $hex11= {2461363d2022687474}
		 $hex12= {2461373d2022687474}
		 $hex13= {2461383d20225d696e}
		 $hex14= {2461393d20226d6a42}
		 $hex15= {24733130303d202249}
		 $hex16= {24733130313d20225d}
		 $hex17= {24733130323d20226a}
		 $hex18= {24733130333d20226a}
		 $hex19= {24733130343d20226a}
		 $hex20= {24733130353d20226b}
		 $hex21= {24733130363d20224b}
		 $hex22= {24733130373d20224b}
		 $hex23= {24733130383d20224b}
		 $hex24= {24733130393d20226c}
		 $hex25= {247331303d20223160}
		 $hex26= {24733131303d20226d}
		 $hex27= {24733131313d20224d}
		 $hex28= {24733131323d20224d}
		 $hex29= {24733131333d20224d}
		 $hex30= {24733131343d20226d}
		 $hex31= {24733131353d20226e}
		 $hex32= {24733131363d20224e}
		 $hex33= {24733131373d20226e}
		 $hex34= {24733131383d20224f}
		 $hex35= {24733131393d20224f}
		 $hex36= {247331313d2022316e}
		 $hex37= {24733132303d20224f}
		 $hex38= {24733132313d202270}
		 $hex39= {24733132323d202270}
		 $hex40= {24733132333d202270}
		 $hex41= {24733132343d202223}
		 $hex42= {24733132353d202270}
		 $hex43= {24733132363d202270}
		 $hex44= {24733132373d202271}
		 $hex45= {24733132383d202251}
		 $hex46= {24733132393d202271}
		 $hex47= {247331323d20227b32}
		 $hex48= {24733133303d202271}
		 $hex49= {24733133313d202271}
		 $hex50= {24733133323d202271}
		 $hex51= {24733133333d202271}
		 $hex52= {24733133343d202271}
		 $hex53= {24733133353d202271}
		 $hex54= {24733133363d202271}
		 $hex55= {24733133373d202271}
		 $hex56= {24733133383d202271}
		 $hex57= {24733133393d202271}
		 $hex58= {247331333d20223258}
		 $hex59= {24733134303d202271}
		 $hex60= {24733134313d202271}
		 $hex61= {24733134323d202271}
		 $hex62= {24733134333d202271}
		 $hex63= {24733134343d202272}
		 $hex64= {24733134353d202272}
		 $hex65= {24733134363d202272}
		 $hex66= {24733134373d202272}
		 $hex67= {24733134383d202272}
		 $hex68= {24733134393d202272}
		 $hex69= {247331343d20223334}
		 $hex70= {24733135303d202272}
		 $hex71= {24733135313d202272}
		 $hex72= {24733135323d202272}
		 $hex73= {24733135333d202272}
		 $hex74= {24733135343d202272}
		 $hex75= {24733135353d202253}
		 $hex76= {24733135363d202273}
		 $hex77= {24733135373d20223d}
		 $hex78= {24733135383d20222c}
		 $hex79= {24733135393d202253}
		 $hex80= {247331353d20223464}
		 $hex81= {24733136303d202253}
		 $hex82= {24733136313d202253}
		 $hex83= {24733136323d202253}
		 $hex84= {24733136333d202253}
		 $hex85= {24733136343d202273}
		 $hex86= {24733136353d202273}
		 $hex87= {24733136363d202273}
		 $hex88= {24733136373d202273}
		 $hex89= {24733136383d202273}
		 $hex90= {24733136393d202273}
		 $hex91= {247331363d20227b35}
		 $hex92= {24733137303d202273}
		 $hex93= {24733137313d202273}
		 $hex94= {24733137323d202253}
		 $hex95= {24733137333d202253}
		 $hex96= {24733137343d202253}
		 $hex97= {24733137353d202253}
		 $hex98= {24733137363d202274}
		 $hex99= {24733137373d202274}
		 $hex100= {24733137383d202274}
		 $hex101= {24733137393d202274}
		 $hex102= {247331373d20227b37}
		 $hex103= {24733138303d202274}
		 $hex104= {24733138313d202274}
		 $hex105= {24733138323d202255}
		 $hex106= {24733138333d202255}
		 $hex107= {24733138343d202255}
		 $hex108= {24733138353d202275}
		 $hex109= {24733138363d202275}
		 $hex110= {24733138373d202277}
		 $hex111= {24733138383d202277}
		 $hex112= {24733138393d202257}
		 $hex113= {247331383d20223732}
		 $hex114= {24733139303d202277}
		 $hex115= {24733139313d202277}
		 $hex116= {24733139323d202277}
		 $hex117= {24733139333d20223a}
		 $hex118= {24733139343d202277}
		 $hex119= {24733139353d202277}
		 $hex120= {24733139363d202277}
		 $hex121= {24733139373d202277}
		 $hex122= {24733139383d202277}
		 $hex123= {24733139393d202258}
		 $hex124= {247331393d20223933}
		 $hex125= {2473313d2022243773}
		 $hex126= {24733230303d202279}
		 $hex127= {24733230313d202279}
		 $hex128= {24733230323d202259}
		 $hex129= {24733230333d202259}
		 $hex130= {24733230343d20227a}
		 $hex131= {247332303d20223969}
		 $hex132= {247332313d20227b61}
		 $hex133= {247332323d20226161}
		 $hex134= {247332333d20227b62}
		 $hex135= {247332343d20226269}
		 $hex136= {247332353d20226269}
		 $hex137= {247332363d2022424c}
		 $hex138= {247332373d2022624c}
		 $hex139= {247332383d20224336}
		 $hex140= {247332393d20227b63}
		 $hex141= {2473323d2022246a44}
		 $hex142= {247333303d2022436d}
		 $hex143= {247333313d20222e2e}
		 $hex144= {247333323d20222e2e}
		 $hex145= {247333333d20222e2e}
		 $hex146= {247333343d20222e2e}
		 $hex147= {247333353d20226353}
		 $hex148= {247333363d20224377}
		 $hex149= {247333373d20224378}
		 $hex150= {247333383d20224449}
		 $hex151= {247333393d20226534}
		 $hex152= {2473333d2022246a44}
		 $hex153= {247334303d20226535}
		 $hex154= {247334313d20226562}
		 $hex155= {247334323d20226564}
		 $hex156= {247334333d20226564}
		 $hex157= {247334343d20226567}
		 $hex158= {247334353d20226548}
		 $hex159= {247334363d20226569}
		 $hex160= {247334373d2022654b}
		 $hex161= {247334383d2022656c}
		 $hex162= {247334393d2022454e}
		 $hex163= {2473343d202224706f}
		 $hex164= {247335303d2022656f}
		 $hex165= {247335313d20226556}
		 $hex166= {247335323d20227b66}
		 $hex167= {247335333d20227b66}
		 $hex168= {247335343d20226643}
		 $hex169= {247335353d20227b46}
		 $hex170= {247335363d20226648}
		 $hex171= {247335373d20224656}
		 $hex172= {247335383d20226757}
		 $hex173= {247335393d20226847}
		 $hex174= {2473353d202224706f}
		 $hex175= {247336303d2022484a}
		 $hex176= {247336313d20226850}
		 $hex177= {247336323d20226874}
		 $hex178= {247336333d20226874}
		 $hex179= {247336343d20226874}
		 $hex180= {247336353d20226874}
		 $hex181= {247336363d20226874}
		 $hex182= {247336373d20226874}
		 $hex183= {247336383d20226874}
		 $hex184= {247336393d20226874}
		 $hex185= {2473363d202224706f}
		 $hex186= {247337303d20226874}
		 $hex187= {247337313d20226874}
		 $hex188= {247337323d20226874}
		 $hex189= {247337333d20226874}
		 $hex190= {247337343d20226874}
		 $hex191= {247337353d20226874}
		 $hex192= {247337363d20226874}
		 $hex193= {247337373d20226874}
		 $hex194= {247337383d20226874}
		 $hex195= {247337393d20226874}
		 $hex196= {2473373d202224706f}
		 $hex197= {247338303d20226874}
		 $hex198= {247338313d20226874}
		 $hex199= {247338323d20226874}
		 $hex200= {247338333d20226874}
		 $hex201= {247338343d20226874}
		 $hex202= {247338353d20226874}
		 $hex203= {247338363d20226874}
		 $hex204= {247338373d20226874}
		 $hex205= {247338383d20226874}
		 $hex206= {247338393d20226874}
		 $hex207= {2473383d20227b3032}
		 $hex208= {247339303d20226874}
		 $hex209= {247339313d20226874}
		 $hex210= {247339323d20226874}
		 $hex211= {247339333d20226874}
		 $hex212= {247339343d20226874}
		 $hex213= {247339353d20226874}
		 $hex214= {247339363d20226874}
		 $hex215= {247339373d20226874}
		 $hex216= {247339383d20226874}
		 $hex217= {247339393d20226874}
		 $hex218= {2473393d2022313161}

	condition:
		27 of them
}
