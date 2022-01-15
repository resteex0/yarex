
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ohagi 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ohagi {
	meta: 
		 description= "Ohagi Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-16-13" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "02ef06286c4058691b56a25991687c27"
		 hash2= "03a3c78b1d81bcf559ded1b148711584"
		 hash3= "054896d9b18218a67ceb0c94518f6d19"
		 hash4= "06917e811283f4e9f57d68d60ea7dfda"
		 hash5= "0750c6f47fe6da3d9a981e5fbed9ea95"
		 hash6= "08e0cbdfd664824da9d7ff7556be9dbe"
		 hash7= "0918622fc2e852cef5add3bd21bed938"
		 hash8= "094ad203acbc5ff83d7701d8c81238a1"
		 hash9= "09d3f508c61a04b103abf14251881e04"
		 hash10= "09d6116edcab4f838f861afb635dd89d"
		 hash11= "0c6cda6776e8013f51985a32a7134943"
		 hash12= "0d262531087867f36b4d15f921b2fbbf"
		 hash13= "0d6afe7b68a816803b13abd39c2bae08"
		 hash14= "0e3bd8ee3a25b94640cc904f7574b9cc"
		 hash15= "0f7a499d60469275814463f1048d89c2"
		 hash16= "10d58845d43fa3b1adbdc1b42c0c42cd"
		 hash17= "111fd1a5ff5fbafaca60b197c5ab8ff1"
		 hash18= "1120e819c802900ec014171fbddba097"
		 hash19= "138403da4bdd0f610d87a5e58dea34d5"
		 hash20= "13fd97f6be4010d379bb1bfe3d5c7bfe"
		 hash21= "14ee45c665165b2cd21a6ab93628d6f8"
		 hash22= "153a9c43a72b11fecae50634057fc643"
		 hash23= "177ca08e9a9b67454b92fa0acbf5bcfc"
		 hash24= "1a1c49af8a9b6cee61dc1de719b1f088"
		 hash25= "1a8a2db2d4cf0ef368172bdbb6943a7a"
		 hash26= "1c42a62d238a2fa94bb617c9b7805a77"
		 hash27= "1d2ffae41f98b2310d5dada1f613ecf7"
		 hash28= "1db4dbce35cf0b409b2a48fbec2bbc9d"
		 hash29= "1e99bb0044788d154d188921bc59aedf"
		 hash30= "1f07ff7570c084826afce60b312639bd"
		 hash31= "1fca782b46e54499de8509467198e1c2"
		 hash32= "2127d494b939335fb4f709025b02abbe"
		 hash33= "2131bbf18191d8509ff0e90acb86830c"
		 hash34= "22809f40f60f7d3aac71002383a7a2a1"
		 hash35= "22ca8f78439b6bd6e34fd147c65da373"
		 hash36= "234207ad33f976080f00f64b7e7edec8"
		 hash37= "2477e9a5cf7b3de7bc97a46cbab1db93"
		 hash38= "24e8b6c994007975c5d028854b1b37d5"
		 hash39= "24fdbd1cc0bbda0700fb35721d009c71"
		 hash40= "251825122f09daeaae1c92f9c09f6d65"
		 hash41= "254f14c9daf43b4b514e12cfa60c8c17"
		 hash42= "2615a45d59ac81dea1fd468fe93e168c"
		 hash43= "26c5f8832ecb4d270e3849fb12baddc4"
		 hash44= "27e044689bb05bbf8bbd9b7c03834493"
		 hash45= "2978b2f3e03ffc78814c900a0098f1ee"
		 hash46= "297c0e27baca94af6472922e1ec5d270"
		 hash47= "2b4a7d51e7af0d92b4fa3bd3436f4c4a"
		 hash48= "2ba6ec0383b8adc8d3f01d97c8a68b68"
		 hash49= "2bede99e96c76127f1ce0c63dea14c4d"
		 hash50= "2c56d87d7e66c591da20a41c7e49ce4e"
		 hash51= "2cb32fc4536e9705ad575e703cac278e"
		 hash52= "2fc4b9582bb42bf55dd7d5a8d8aeb4bd"
		 hash53= "30cc90099adc064508497bbe8679731e"
		 hash54= "3131a9b3d8b9c06ed3ee7931a9a52708"
		 hash55= "313eabc5fe4f12bdd9b5b3bd3990cb4a"
		 hash56= "3312dd0fffd1735acf498276c3da766e"
		 hash57= "34f928e8aa083184f1ec55c8c344f67b"
		 hash58= "36fe9f727f13aa5fb2bb93dfae8a8cf3"
		 hash59= "379cc60b08a76b17d7d0d71d58e10e8c"
		 hash60= "3835a6b829e9983938508e147f63fdba"
		 hash61= "391ee8d59e1c75351cc24e1102c5fe67"
		 hash62= "39a960ecd5b833fac61b95dc43d721ec"
		 hash63= "39e2d0033a1c6d9933dd2f5aa0f89df1"
		 hash64= "3a18254acd48c97aa82116b93e0e6725"
		 hash65= "3ad5592a50c0fb9dfbc4d656b3112cbd"
		 hash66= "3b55a8c0479d9420c11a9342432454da"
		 hash67= "3c05f5e68de982e2782229531bf5ad6b"
		 hash68= "3dad46bc5bb170269199bf2c8fd30fe5"
		 hash69= "3e003260f898a08c11f471512feadf1b"
		 hash70= "402ba831d79bbf01c36de62456203e8b"
		 hash71= "42c516fc85e32fc9db31b642c67df8a0"
		 hash72= "4301f434cfec0f6aa010b93cf7434423"
		 hash73= "45209baf0cd66418af83e37133ecec86"
		 hash74= "46b160b3615f8fac51ba07fb45176de9"
		 hash75= "46d7f54de2422324966a4fcf88039835"
		 hash76= "4ad78a75b8f598b8846a9e824d24f930"
		 hash77= "4b1160d1764950e2160c0652f1f672ba"
		 hash78= "4bc3a0ccdd87d1b40eb16352afd8ed41"
		 hash79= "4e1911a3cb154e8146f430dad9b8a717"
		 hash80= "51187b0979964b6e29f61cd5bc35925b"
		 hash81= "51e60fcba86716728aaa5a0f2058eb22"
		 hash82= "524382543172fd6e6cb15493beed2eec"
		 hash83= "53ac26a11a079bb95fdafe35746b5f63"
		 hash84= "53da223b934bd8b9d823ec6da31c8422"
		 hash85= "551900f6882dc6547170bd0492929603"
		 hash86= "56312cf41bc1362ef20ea686a75a1c84"
		 hash87= "56dd54276dc7d3b82ebb25a546893a3f"
		 hash88= "593b6f8d4ff306d630e24ce975ed9307"
		 hash89= "59cae922e3f353cb9c13dfdc0411d729"
		 hash90= "5b027822e4628b2f2bcedda58c79b2f0"
		 hash91= "5d82f5186a7da91efdcdbddf18b913a5"
		 hash92= "5ddb72b29eebddd42624442eba970da2"
		 hash93= "5ecfc5dacde07682f2516a100762ace4"
		 hash94= "5ff36ff1a946be5439758f1680359b56"
		 hash95= "61cb39dcab2a682235e1632d050ae5e6"
		 hash96= "62ce4ff0b381f4d323e91b9c76990e4c"
		 hash97= "63947266a962a1b607baeada22676b43"
		 hash98= "6407eb45f401ffeb8238f0333272351f"
		 hash99= "65ec3a68df322df501b177003290f589"
		 hash100= "664229c9b3e05fb616163eafdcfd7b48"
		 hash101= "6661695591d88b8fd81c9771c52061ac"
		 hash102= "6682238c1551f944cd03ff1bc35cb20b"
		 hash103= "6805b2e18960fd163cfe5f4b5bdcd7fc"
		 hash104= "681dbeeaf0c56b5581d6cc63a8fe7243"
		 hash105= "697a0f57792bf9f7f83e510603e9139e"
		 hash106= "6ba9965451669d3f2ea7cf87e4a457a2"
		 hash107= "6d0f012368b3bcb2a3bab6e23a34b008"
		 hash108= "6e6719ac152751f3bf585a77330a199c"
		 hash109= "6e92c62a77e8471481421b8fd986c262"
		 hash110= "6ea3d36378e8ef96148e68fab9c0221c"
		 hash111= "70bb2e5d76094253c694818ab9b3962a"
		 hash112= "735c57cbd9cedf368ca3c73db3eac476"
		 hash113= "74a0a71e161dd587a800b512056e4200"
		 hash114= "752849645cb250d6dc1fb9a2377f44f1"
		 hash115= "7689a4ec817e277c4f42eb21fef983d9"
		 hash116= "77fcf01cdd2d84871ff0d37249632965"
		 hash117= "780566e56605ba9dd73f069f63b8ac3e"
		 hash118= "799c9289d8437b1ab3fc6a7507a11acf"
		 hash119= "7b61beb3da1208b413c7403500703d72"
		 hash120= "7dcf732fe31d8232834609e5fb6c325a"
		 hash121= "7dd82d02fa36e568006ed0436fa85218"
		 hash122= "7e1a0c88ca4916fb2dd281bce6742223"
		 hash123= "84d8be43e0584a8153661e57f9a3d3b4"
		 hash124= "854379e4c380a26d643d4594da0c3e42"
		 hash125= "85ecd60c567736cb7ba9e4d09ef4cac2"
		 hash126= "86b76b96b636045cd2e5cb4640cc60a8"
		 hash127= "86d5fc0dcde607236c28786746866757"
		 hash128= "86d629951c24f5d49a96c526025059c7"
		 hash129= "86d7d4b86442e82b20faa3c37e1e5496"
		 hash130= "87124d2b48a1ec8aa8afff4e7332f81d"
		 hash131= "88a0553e1ec620c860a45812127d7829"
		 hash132= "89ec7ca8c34997eef2fb2e92df10d8a6"
		 hash133= "8b112875f39436264c631fbbb81bcce9"
		 hash134= "8b89858c16418ce639e62ec8c2373e0f"
		 hash135= "8e4bba7ba8103c78246de92d4d7696de"
		 hash136= "8f35af17bb39e9b53e638df2ac338283"
		 hash137= "8f65758a40e9a78470e2105394a8be46"
		 hash138= "90bb051af6f026d9be8f27f069f4b61f"
		 hash139= "90e4ef8013e548170bc84429be162e77"
		 hash140= "9179d6e21c44cea2d7189ec2188cf1df"
		 hash141= "969ca6bb5e09f347e6ada124a158c272"
		 hash142= "970b87cd007ec1b3d027063e08a1b918"
		 hash143= "99b9d9e025056d2334c0a1960a96f854"
		 hash144= "99cd2e1abf989fe5c62e3feb66b9cbb3"
		 hash145= "9a4b82644c8776cf886ae3a91ef4343c"
		 hash146= "9bea7af2532af88653e9feadc6feba89"
		 hash147= "9c9a3b0661d7a74546e52fc569cd4105"
		 hash148= "9f7e193f0246bfddfcbe4db107124918"
		 hash149= "9f8cc9331e80750a6c35ede078b23723"
		 hash150= "a1dd0970f60410b03fc16cbe3bada9b9"
		 hash151= "a29287be620d51ccb0955798065682ef"
		 hash152= "a2fd0d744d57c81d079dec4994a7dea3"
		 hash153= "a3bdf29891596b1ccce1be9a941b42aa"
		 hash154= "a3e0208cc28a1aa23fa1ea9addc65624"
		 hash155= "a795a396aed7ce21cf7120d3ccdb7814"
		 hash156= "a88f904b721362c43d3fa9d71f7caddc"
		 hash157= "ac69fd4d4a97d5a17598a45a55a6d6f4"
		 hash158= "acb947096aa40cc99380e0f506396a05"
		 hash159= "acf7437ac24b24381bf1148a9c647728"
		 hash160= "addf234f6aaf0d032ac9000646b1270d"
		 hash161= "af48ddc2d3bcf4e58dda56ed121bbc87"
		 hash162= "b0e17b939f5041574d4bf190976a0cef"
		 hash163= "b226eb2b9094763ea203e4820ce63aff"
		 hash164= "b2ea4fcf35e70561ea819544a3fa680d"
		 hash165= "b2f1cc6def932406386da4aa9d47090e"
		 hash166= "b75f793c472e2308c39eb199056dd431"
		 hash167= "b7f2d1bf1a30f6b1325bfe7e13f4582a"
		 hash168= "ba05b379fd9f864b806095645dabe98b"
		 hash169= "ba4d9b3ea9644ed016f1a61350eb6ad1"
		 hash170= "ba69c402d3b3e5030a860ab47e265daf"
		 hash171= "bae932af8c6e7244b709e3c4136dc089"
		 hash172= "bb8e8a87a878d5f2fbc7d9438a96cd1c"
		 hash173= "be72488ee9634338be8563c913bb797a"
		 hash174= "bf92881f4c1d8bc11343dde77cab5113"
		 hash175= "bff339994c133f4cf7c7ebb21bf6cef2"
		 hash176= "c07445d30c173f271b337c5654975d65"
		 hash177= "c0b80beb8a4d892052ac214358423260"
		 hash178= "c3565e8abaa16778e744169169676400"
		 hash179= "c371c576484edfcdeb64b5e98c63727d"
		 hash180= "c4a0bfa7e58e55b5e43c55784e08cef3"
		 hash181= "c5095bcb2ab44a3d1163417bdf1c73fa"
		 hash182= "c65ff4f2ef54cd63c1bc12f9b7a3ed54"
		 hash183= "c7276327e5fdf6c6c7124d80b0478d1f"
		 hash184= "c7dcf7d40ac57a487482139cc0182ad6"
		 hash185= "c8b351fe700e630cb3a0c12867ba99ce"
		 hash186= "c9131a1e2b0bbec94c050bf613f602ce"
		 hash187= "c9426198d2f99b3d24d6be0f94ca6a5e"
		 hash188= "cad5e486bf081d507dc7ae77387cf4c1"
		 hash189= "cb70169a598a766a1df36e30ea3e3848"
		 hash190= "cd0de16d6b3a16bcc0481082a9a54ef0"
		 hash191= "cda520424b0c6fde39489620f984fa7b"
		 hash192= "cec06351738d3491394c1898242c3d82"
		 hash193= "cf0d4896d664e82c4b427e16e5dec88e"
		 hash194= "cf995b5fa7b1aad82a6a866521d6600f"
		 hash195= "cffee9499e3b8b8e41066772c854c8ef"
		 hash196= "d226916943b1448658bc3b31a9cbd499"
		 hash197= "d2e0ede24d4f89a4de42e9c2d16f2ad2"
		 hash198= "d31af5f54922e9623573245fa5014aec"
		 hash199= "d57f13fce69115d1f5ebe8b670afd72a"
		 hash200= "d582b4abe48b7d448c1b46a085187565"
		 hash201= "d5a2670bdb777172809e1bc837ad813b"
		 hash202= "d61c7d55575aaf5829e656cac4f32049"
		 hash203= "d71581e363af59adcd1791246d7ed031"
		 hash204= "da1c340ab0a8f8d66696dd54215f392d"
		 hash205= "dacb5b2a67398117c006fbbba52bcc6d"
		 hash206= "db04b42d820fe9585096381eca8de55c"
		 hash207= "dbe5d186d9e108f549a4c355b233de08"
		 hash208= "dc97e07bd34007dfd7402e8b5808922a"
		 hash209= "dfdb9f52c841507756570c5602f1042c"
		 hash210= "e0411f6d4e6dec4ec98ddfd3c9832f2f"
		 hash211= "e04f59d9ad2ef5089f260cc7533b20f3"
		 hash212= "e075b26ab6fdf3c1a2d20d6a7f97e27f"
		 hash213= "e199457e74bae16337314d68d7c016d8"
		 hash214= "e2958f4030f3128e914a2bf51f18424a"
		 hash215= "e396df842ac0cc0278a8b59b6ac85bb1"
		 hash216= "e61b1c1bc130d3cb1ba55f0df09a3628"
		 hash217= "e6a110b929a4b1d483d939feac4a50c5"
		 hash218= "e6bc6d1dc728ec1727eae5ec54c37247"
		 hash219= "e70b225ba553415cff040e51c8bd9698"
		 hash220= "e749b63c82386fac889b7bd567aadb0a"
		 hash221= "e7dbc374fb4d7d163884d0605bea35c5"
		 hash222= "ea0b4cd8277c10db0f96fcc1e989335c"
		 hash223= "eae1180e794a31a0a43c606336130a2f"
		 hash224= "ed845061d49df860f1efcfc63174c620"
		 hash225= "eda5dbbc0c928245f7443a1fb47e7a38"
		 hash226= "edab9098542db74c8931581cfe17bed1"
		 hash227= "edf5d9cdcecfab5b0054978b236a1cfa"
		 hash228= "ee74b2f765daab593803c35396453c68"
		 hash229= "ee866085a219e49adbd122c7f2803002"
		 hash230= "eee73217dbf0328c4626608c7e4943a5"
		 hash231= "f02dfaf021eb02f666afa306cf8c8624"
		 hash232= "f0cf4b66c8c768a222915e4576e7fc64"
		 hash233= "f1d5ba4ee4def756b5b7936fb11be8eb"
		 hash234= "f5408088e5bb3d509a29d298f0978cf8"
		 hash235= "f6bc93bbe3ae3db494ae6d90003ba74f"
		 hash236= "f85dc0aa76c7f32614c97ea2911a37a5"
		 hash237= "f9ccceec6005cafef6c7f9be0042b834"
		 hash238= "fa0d7312f3ed0d618ad3c9d28687e764"
		 hash239= "fabf750e632a327dc757b66049c755fb"
		 hash240= "fcbaec3f2f28ab228f000edceef831d5"
		 hash241= "feb34e32313acfcb9c2ee42a429aedd6"
		 hash242= "febb1537154d6ecb5fa180d27c19a6ff"
		 hash243= "febb5e6443d0ce3b88e211b5b2c9a9de"
		 hash244= "ff27a6bf7bd60488ee1b34e4e22b7dec"

	strings:

	
 		 $s1= "CurrentHorizontalResolution" fullword wide
		 $s2= "CurrentVerticalResolution" fullword wide

		 $hex1= {2473313d2022437572}
		 $hex2= {2473323d2022437572}

	condition:
		1 of them
}
