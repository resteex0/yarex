
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Emdivi 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Emdivi {
	meta: 
		 description= "vx_underground2_Emdivi Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-55-42" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "05edc5d5bd9bda9ac8a75392b4231146"
		 hash2= "2a2abdc4a301b73eb0f2ab01cc3450bf"
		 hash3= "2d5637c5019017d122c029a98aa9ad02"
		 hash4= "2f2bb56fc759213a6377b0b885cabc4e"
		 hash5= "327d0e8cd56421e6cf76c00446b47532"
		 hash6= "32fe3b8335b2882d0ff48293a8ee0026"
		 hash7= "3b2b36edbf2934c7a872e32c5bfcde2a"
		 hash8= "3bdb9ab7caa2a9285b4ed04fe1c4753b"
		 hash9= "3e88e2f55f1d6db8a734c62a832ba062"
		 hash10= "3f4c0b73cf13ffc0544085639745a9d2"
		 hash11= "4be4ebe1db4ea1be2f293037eb7f8b0f"
		 hash12= "5b41fe8d645d2e1245748c176bd82960"
		 hash13= "663402aca911da01f6719c3ee483fb16"
		 hash14= "6701efb6306fb3919cde58b82d42712d"
		 hash15= "72ffb562c6a0e59d3d5a04172362838b"
		 hash16= "875c595fd3e1e18db1152ed8adfa9ea6"
		 hash17= "8bf944283987de847851d3d2279b8cf8"
		 hash18= "953d8d1ccb415f0999fe7bcb91cdda24"
		 hash19= "a01c73da8fbafeae8a76f71d066aa135"
		 hash20= "a64bb1ed1f8210ef13fe686621161699"
		 hash21= "a8e3defc8184708bc0a66a96a686bd50"
		 hash22= "ae345f9833ac621cf497141b08ad34c2"
		 hash23= "b19d9aa5bcede2aa8648b85308ede71c"
		 hash24= "b4b1e15c0d92706ed813e0f3f71287d3"
		 hash25= "b56aa4a6e4cde2a7126c8d91cb728db4"
		 hash26= "b582d899d519aaa8bb5a5c8b13bc6f76"
		 hash27= "bb61f74c44abc408857d8721c323eae4"
		 hash28= "c248bd02cf6468cb97a34b149701ec94"
		 hash29= "c45705a2f204ef3ca9321735790b88be"
		 hash30= "cf8b4d2fbd7622881b13b96d6467cdab"
		 hash31= "d78ec13e14cec4d6a7ed0998e1c69cc2"
		 hash32= "db7252dcd67affc4674c57d67c13c4f0"
		 hash33= "dccc63cd649b439d31afd0674bcab1a1"
		 hash34= "ded8f3787f634a188880845f3cd28fe0"
		 hash35= "e4fc0ce4d1fd8c91eed4748721f279a8"
		 hash36= "e5653a4bca1239b095509438a3040244"
		 hash37= "f60cdde57bd9ca9412c32a08ef068abc"
		 hash38= "fa0c1790668cfb7733dcfb3561359910"
		 hash39= "fc6f9b6c7402d1018f69f3f665f81c28"
		 hash40= "fcc4820790d8bf2c0cd654b594b791e1"

	strings:

	
 		 $s1= "Content-Type: application/x-www-form-urlencoded" fullword wide
		 $s2= "DocumentSummaryInformation" fullword wide
		 $s3= "INTERNET_OPEN_TYPE_PRECONFIG" fullword wide
		 $s4= "MozillaFirefoxProfiles" fullword wide
		 $s5= "SoftwareMicrosoftInternet Explorer" fullword wide
		 $s6= "SoftwareMicrosoftWindowsCurrentVersion" fullword wide
		 $s7= "__tmp_rar_sfx_access_check_%u" fullword wide
		 $a1= "5O9X8PJDXUQRF/TE36IY4W+j8YArWtzJTopYJU5j0+azFInvW/YY9q/tJpEwo5Sn" fullword ascii
		 $a2= "7WuEnwKE3vXYS/zGgbNIF+8KfWa/ar4scxVX9rq8nqZjaE9/3JPYtQjGXRr7NIWx" fullword ascii
		 $a3= "97316/CDz8CL9+dZRCZa9UEhk+rJumk7zLedJ/qjsKcn0Z0Gb/PXdh/lJYbkSAq5" fullword ascii
		 $a4= "dUH/wh1P84aWfZWjQDrCP2c5/Eh3wcyupm7jN00ehw+PWXKNZNJe4MeT8e/gTEf4" fullword ascii
		 $a5= "gp/MPtjR3ShB5MOR/BkFu8oGRBzwEM+EcWcDT8wv98hnLOk3LbaWH1mAVZCsTsbg" fullword ascii
		 $a6= "Hf/NW+OzWnYz0LqMgGZnIqqNgUyfag+qHEJvE8cRA++KvWB+I8taYmcO/lIR21fH" fullword ascii
		 $a7= "hij/3+VOIuUZj3HSekrls4oewVo8Uuon+8/N2TCFTQEfJdaX8ydIZ0tz+bpMxCGz" fullword ascii
		 $a8= "iGsmqpDjMq0QCygaRArwpf69b/wvsTify1UfXRTMbJ3f0+qgAekmjES5y6BeMhKH" fullword ascii
		 $a9= "J/1RkgrpQfD0CGLfMaV30/e5iZNkWKWdZeUg3HvPfBwHDlHuRTHJa6gJxgAcv/gE" fullword ascii
		 $a10= "kdg6A1uDhP4zHC/FyzrewNwL7wlDbsBOxg2Q83SkFSQzcmqakvfvUqbElAqGUfDy" fullword ascii
		 $a11= "PQxukVJkS0ZwsT+BGd6hfVRXM918+wqUB9VSRW3AhgKluZpzt/FSYSizuyZ8QAmX" fullword ascii
		 $a12= "uIHKOyju7Py2EilEUeyRfqI+SedPgZQACemaHA2bGcof07HYUW+f9Daq6WrpK3zv" fullword ascii
		 $a13= "vNb54X9Qx3A/xMGwSSlZN83jXF1gQXxoXHxu1bafmbFiQXujfL162LaBma/cFAb3" fullword ascii
		 $a14= "ZNFtX8AH9/kBn7yYpDUicDJNGz5yXGZqbMBnaPMxQNRTwdoL1iB8u/nQXIGJI/Ud" fullword ascii

		 $hex1= {246131303d20226b64}
		 $hex2= {246131313d20225051}
		 $hex3= {246131323d20227549}
		 $hex4= {246131333d2022764e}
		 $hex5= {246131343d20225a4e}
		 $hex6= {2461313d2022354f39}
		 $hex7= {2461323d2022375775}
		 $hex8= {2461333d2022393733}
		 $hex9= {2461343d2022645548}
		 $hex10= {2461353d202267702f}
		 $hex11= {2461363d202248662f}
		 $hex12= {2461373d202268696a}
		 $hex13= {2461383d2022694773}
		 $hex14= {2461393d20224a2f31}
		 $hex15= {2473313d2022436f6e}
		 $hex16= {2473323d2022446f63}
		 $hex17= {2473333d2022494e54}
		 $hex18= {2473343d20224d6f7a}
		 $hex19= {2473353d2022536f66}
		 $hex20= {2473363d2022536f66}
		 $hex21= {2473373d20225f5f74}

	condition:
		14 of them
}
