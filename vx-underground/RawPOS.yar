
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_RawPOS 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_RawPOS {
	meta: 
		 description= "vx_underground2_RawPOS Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-14-56" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0a06948f0eb5866216759ec69b315ced"
		 hash2= "0b4b25c328af1fa348b8288043c704b7"
		 hash3= "0c67494a4019264bceca488253610ef0"
		 hash4= "19623ea25524a22c70a9b78059eba701"
		 hash5= "19667585d8c93acce52e5b12c9479372"
		 hash6= "1b92ffc6e0322af3b818de6e3ee6daf0"
		 hash7= "20c9388f45ff2d31754812a457ffbb0c"
		 hash8= "27d5c5f6f7b921c89ffb860d7e170b29"
		 hash9= "2a086cb9f1247ce3699ade3ed70d7200"
		 hash10= "363ed92eab0fda8a8d7c0a1c6652cd2a"
		 hash11= "3ba5dafea1c447a2379811996f986006"
		 hash12= "3d0a57c178977781848533cb3038a087"
		 hash13= "3dd47d9ead4dad89b0b30423e6ad9e70"
		 hash14= "3e19ef9c9a217d242787a896cc4a5b03"
		 hash15= "3f66583c8f67e7c255598d9d68394059"
		 hash16= "402c8cdb483b1e3e51a7f1e4749f9625"
		 hash17= "4183e7fc2d9741c6039ba6eb357f57c3"
		 hash18= "4732a7ab8c236a0e691c6341c2257a85"
		 hash19= "4b254b90f61d82194672b0ce55b020da"
		 hash20= "52fd283903f0e44e3da3233f7ad894a9"
		 hash21= "55d826f15bd373dc51db8334290ece61"
		 hash22= "5fa64cfcab7f4e95d6a55c2185a0515d"
		 hash23= "63b7cad5307a1927e16d7cd096b81831"
		 hash24= "65375c1eb4683cbd2a868f99ac983b03"
		 hash25= "65c44501369650db625043da125a4f0e"
		 hash26= "6868d9e1570760dc4e5a9d02b38870d6"
		 hash27= "6941d6a79b4180dfc7b98224957bd696"
		 hash28= "6c6de1c1e8e15574cb7e40cc7cc54536"
		 hash29= "72cc7aa7a7926294208a91877ce40071"
		 hash30= "7b61acc924ba4e5afa32e76afefe1e86"
		 hash31= "82c3075f10aabab0f22ffc084b3c2213"
		 hash32= "8730853cda9734a11ce6b38e69c17d74"
		 hash33= "894a2139b5a5de1f83489e861541934e"
		 hash34= "8ee82123dbc2a159544d422d96f9c4dc"
		 hash35= "9188fda3acf2816892ff3bdca9db1052"
		 hash36= "91c40ca8c3aefa23e12755836220dfad"
		 hash37= "9363dbed450b32a3e0b22d144232813f"
		 hash38= "93c22be9e17616512925b5077be4dace"
		 hash39= "95656134e77892bd2846a7d28b0fa782"
		 hash40= "9a72209dfc9cc8f41931f2c13b5d49db"
		 hash41= "9aaaf6e0fb591dba6513c1ce94d3e388"
		 hash42= "9cbfd014a8ab19d3a3c02d4bda3c4938"
		 hash43= "9e810f17a0071d504e369e933b6620ca"
		 hash44= "a026b7d302a913ac26fcb698a39a3a18"
		 hash45= "a3090fbfb7f5708f669b43ed3db9b3a2"
		 hash46= "a3c0c081c4410b8ee1b68f0010ac3e45"
		 hash47= "a76663f45740226afddcf610d661bd65"
		 hash48= "a9109c829b55a35f16e1779ed0cb33b4"
		 hash49= "ad262adc6ecb23804d529329fbb6a9f5"
		 hash50= "ae58da80510f289dc02704c97fe6d0fc"
		 hash51= "b19bbee694a58ee1b9a1ba1ec85154b5"
		 hash52= "b4f28e51ec62712951ee6292936768c8"
		 hash53= "b50dad9c5f5606c2a915a807b7f3f91d"
		 hash54= "ba9b109d929a643c831867cbc7459c4d"
		 hash55= "bd6c56097e107d12102c0df1136a96d1"
		 hash56= "bfb0eb8aacbf380cba9beb635557178a"
		 hash57= "bfe3aeae1eaca59acc145cd53d40a9da"
		 hash58= "c2c99bb4b9268a3774067fa39eaf969b"
		 hash59= "c95a12932b1bfc85270f3fedc9d7b146"
		 hash60= "cbf7007c12a5ba47cc98f15e912a0a31"
		 hash61= "ce0c7282e9116e1c46ee535c976e676e"
		 hash62= "d2e6a11be15ead0e00a24141f1f7269c"
		 hash63= "dca22c56d715aab5dc4ac708019cc763"
		 hash64= "f1a7e29bdb30bcd6e324f1c81022de5a"
		 hash65= "f61d32d3d0a4fe51905e9e7cc96dae40"
		 hash66= "fdbd709d1f72e5ac9983ff207e43be49"

	strings:

	
 		 $a1= "([0-9]{15,16}=(0[7-9]|1[0-5])((0[1-9])|(1[0-2]))[0-9]{8,30})" fullword ascii
		 $a2= "SoftwareMicrosoftWindowsCurrentVersionExplorerShell Folders" fullword ascii
		 $a3= "usage: Win32::GetProductInfo($major,$minor,$spmajor,$spminor)" fullword ascii

		 $hex1= {2461313d2022285b30}
		 $hex2= {2461323d2022536f66}
		 $hex3= {2461333d2022757361}

	condition:
		2 of them
}
