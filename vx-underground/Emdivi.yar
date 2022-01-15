
/*
   YARA Rule Set
   Author: resteex
   Identifier: Emdivi 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Emdivi {
	meta: 
		 description= "Emdivi Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-03-33" 
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

		 $hex1= {2473313d2022436f6e}
		 $hex2= {2473323d2022446f63}
		 $hex3= {2473333d2022494e54}
		 $hex4= {2473343d20224d6f7a}
		 $hex5= {2473353d2022536f66}
		 $hex6= {2473363d2022536f66}
		 $hex7= {2473373d20225f5f74}

	condition:
		4 of them
}
