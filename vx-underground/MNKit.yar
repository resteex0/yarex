
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_MNKit 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_MNKit {
	meta: 
		 description= "vx_underground2_MNKit Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-11-35" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "029f5d4a53a19986c26aee69d4e8c994"
		 hash2= "0580329f552f2b52c104c9091cfd059d"
		 hash3= "0a3d35c528e2ff5758a3192d88467d46"
		 hash4= "152c4167ee0e6272c8c5d351e7f04278"
		 hash5= "16b3303333f0ef690ea9b5cad31971f8"
		 hash6= "190b6d19b3d2088acbd56323dbd98973"
		 hash7= "19a0d40e4de4df7b384938eb9fda3349"
		 hash8= "1e25bd6967bf5512f0a3ae8ed65d8ebc"
		 hash9= "2088fc9f7e00630159eb2bab01ac409e"
		 hash10= "21d0bf9804a59878f3d7ad3f0d46f201"
		 hash11= "24b6088b65b1f67cf04dfadd4719f807"
		 hash12= "2513e1691a6eb41d216540ed2fda9d0d"
		 hash13= "2906f580aa3a1425d1216cd783cb06ef"
		 hash14= "2a9c7d769a3fb93cbb79ad4668eeb183"
		 hash15= "2bd2a71082b60a9bdd9b8a3c33b581dc"
		 hash16= "2e287c764e85d39d9bb0f39c300a5b83"
		 hash17= "3014c77cb64367b92172824834e72db7"
		 hash18= "34787026af067dc71a6a7d140cda4e31"
		 hash19= "3d93c4d3c811b0080cec1c7402f48693"
		 hash20= "429f36d9eabfa89f9803f048f0fc14eb"
		 hash21= "44ffac9e6f5313b2f1b882f24951ae87"
		 hash22= "45782441c73fa949495ffafdb8f9bb62"
		 hash23= "4edda0e2a8a415272f475f3af4d17dc1"
		 hash24= "56d3cab0f77bc6b277869e37d47b4d8a"
		 hash25= "5c986d32add37bc11bd8f89c3d38df9b"
		 hash26= "5d16e305ef6dc2db9c0ff1b498277e8c"
		 hash27= "62d2cdce3736dc5d9a2f036d27ffc780"
		 hash28= "6c1a7e148fe3b31329373b8479fa5ff7"
		 hash29= "6d9091def6fbf3ead3136eaa1861113c"
		 hash30= "740d347f595983b88d8c4b415e900388"
		 hash31= "7d808f496a8e66adfa6af76838f1c3a4"
		 hash32= "820a56152a57011d6b6a63b7747df9be"
		 hash33= "85808dfd61b221d42b938742eb772814"
		 hash34= "86088922528b4d0a5493046527b29822"
		 hash35= "89cabde2d1f63ca3a3ee7f53a850dfce"
		 hash36= "8dccf27a412c915eb0a2c0e2a2a809c2"
		 hash37= "8ef1267f068df5411578efebeac8a485"
		 hash38= "97eb98d6284c41406b464dc63844e820"
		 hash39= "9985b1ab655f26e8a05f8402ad0ea300"
		 hash40= "9b304ad673ea2edb8269c39f2feb0c44"
		 hash41= "a0aa06a2c2ba23d939892174c922b32a"
		 hash42= "a917af3799703bf151b0231797c7a3dd"
		 hash43= "aa5a1cd27c964bc229156a521fbd6a4b"
		 hash44= "ad55ff065ca5f1a525724b4afad1a540"
		 hash45= "adcea7dd7a0a36b76c0fcfb677b584b5"
		 hash46= "b44d492a5d772ae964d2e791507cbd24"
		 hash47= "ba49440893b77454c64430c0b9354a73"
		 hash48= "bb09d15aae8814c5df37ff8ffd827ee3"
		 hash49= "be16e09a595f1144c9e243145eaf7f84"
		 hash50= "c3004ba06e99ba0358b5bccdc9fdea4d"
		 hash51= "cb0f926b00981dbc2d1b92e91760e017"
		 hash52= "cca7536d0bd36dd1fa5560dbfafc8d6c"
		 hash53= "cd353d8e51333fda629c3e9956cc0fe3"
		 hash54= "d22b663cddb92496b6b130262abf2ff5"
		 hash55= "d64af64d08c071fb759271bb749e6e24"
		 hash56= "d7acb743b4442cea1915ff452544083a"
		 hash57= "d9d7410e7034764b9fdc9258a28390a8"
		 hash58= "dad5fca029351bde31de9fff3541fdf5"
		 hash59= "e5de2bc9bc0a7f66419768ef74b2d49b"
		 hash60= "e680b0b3e1679d64044795ea9800d52e"
		 hash61= "e9da32278554c9656857365ca0ef6d0d"
		 hash62= "ea2bfb01e708ae3b96b5b2a8200f2bda"
		 hash63= "ea32064f5394fb337a7088163f496ec8"
		 hash64= "edf3029f6dc973321c6fc0e39998f253"
		 hash65= "efc847ac17603a4c83d4b4a816bf75c7"
		 hash66= "f4572c1ab751929fc2dd88b344fe8f7e"
		 hash67= "f85271d8439e4cae865243b07980dc21"

	strings:

	
 		 $s1= "%4d-%02d-%02d-%02d-%02d-%02d-%03d" fullword wide
		 $s2= "C:My Documentswinword8.doc" fullword wide
		 $s3= "CryptProtectMemory failed" fullword wide
		 $s4= "CryptUnprotectMemory failed" fullword wide
		 $s5= "DocumentSummaryInformation" fullword wide
		 $s6= "%ProgramFiles%Internet Exploreriexplore.exe" fullword wide
		 $s7= "SeCreateSymbolicLinkPrivilege" fullword wide
		 $s8= "SOFTWAREMicrosoftWindows" fullword wide
		 $s9= "SoftwareMicrosoftWindowsCurrentVersion" fullword wide
		 $s10= "SOFTWAREMicrosoftWindowsDbxUpdateBT" fullword wide
		 $s11= "__tmp_rar_sfx_access_check_%u" fullword wide
		 $a1= "??0830?464:0*)&,.-%(!/+$3>" fullword ascii
		 $a2= "AINFBF@GNBCLMNOPQRQ UZZZ^YT^U_`aba9ekjhcmdcba`xyrstuvu%ywv|~yp" fullword ascii
		 $a3= ">B@@BFDDFJHHJNLLNRPPRVTTVZXXZ^\\^b``bfddfxizk|m~oPqRsTuVwXyZ{}^" fullword ascii
		 $a4= "BDEpAHI|MLMxIPQdUTU`QXYl]]hY`aTedePahimlmXipqDutu@qxyL}|}Hy" fullword ascii
		 $a5= "Content-Location: file:///C:/23456789/Doc1.files/filelist.xml" fullword ascii
		 $a6= "Content-Location: file:///C:/23456789/Doc1.files/ocxstg001.mso" fullword ascii
		 $a7= "DHLDTDBCAGMST]OKTXTDTRSQW]CDM_[dhldtdbcagmst}oktx|tdtrsqw}cdm" fullword ascii
		 $a8= "=>?HABALEFAHIJKLMNNPQRSTUVUHYZ[]^_aabc4efohijkdmno7g" fullword ascii
		 $a9= "lXxsaVtwjTpkwKlnpAhc}Ldf~J`ZBv]DtXQIzTVraPIo|LMhzHAeqDEfw@9" fullword ascii
		 $a10= "sHT`b[_YY^_SQQQZVWZJHFILFOAI@LKDHQG4/47)35-=8#>=%:?6%=6':2$6:" fullword ascii

		 $hex1= {246131303d20227348}
		 $hex2= {2461313d20223f3f30}
		 $hex3= {2461323d202241494e}
		 $hex4= {2461333d20223e4240}
		 $hex5= {2461343d2022424445}
		 $hex6= {2461353d2022436f6e}
		 $hex7= {2461363d2022436f6e}
		 $hex8= {2461373d202244484c}
		 $hex9= {2461383d20223d3e3f}
		 $hex10= {2461393d20226c5878}
		 $hex11= {247331303d2022534f}
		 $hex12= {247331313d20225f5f}
		 $hex13= {2473313d2022253464}
		 $hex14= {2473323d2022433a4d}
		 $hex15= {2473333d2022437279}
		 $hex16= {2473343d2022437279}
		 $hex17= {2473353d2022446f63}
		 $hex18= {2473363d2022255072}
		 $hex19= {2473373d2022536543}
		 $hex20= {2473383d2022534f46}
		 $hex21= {2473393d2022536f66}

	condition:
		14 of them
}
