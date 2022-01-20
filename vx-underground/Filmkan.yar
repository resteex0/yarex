
/*
   YARA Rule Set
   Author: resteex
   Identifier: Filmkan 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Filmkan {
	meta: 
		 description= "Filmkan Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_11-04-49" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0151353527d2f2304cff0c342138e5b4"
		 hash2= "02c2e008fa40fcbb14c04b9f46c77126"
		 hash3= "0eb7b5bd571406f0ee3a021d856552b3"
		 hash4= "17c0a0c756926bf02c22d691a3460502"
		 hash5= "196014fd76b45711a12c5345e8ab5268"
		 hash6= "1cbeb76c06cf436d09bcf8fb5332d739"
		 hash7= "23cd608423880181c42999e1f25a81eb"
		 hash8= "26b38dcd249dc8921fbaa9f59af6953a"
		 hash9= "2785158c39da53111127714f374029ec"
		 hash10= "2c6c17acc4b8c68300c7ef965dd12620"
		 hash11= "2db41c19ece0353dc579e5b02e5ed5b2"
		 hash12= "3add3a6856f1016459cc50450a0d34b3"
		 hash13= "3e4ef64664b5310843fd818e87c321b5"
		 hash14= "404bd473b0952342dbf343f1391a02e4"
		 hash15= "4185566ac7824f025288068b7d5fd0a3"
		 hash16= "4b68e58c37b5d49fe9238dd34ae81bef"
		 hash17= "4d561c071fdfd74e6e99effc3b06fbfe"
		 hash18= "500e6a509685b793a15faa2ef565dec5"
		 hash19= "5970de78b4afe95d23559f0032cabbc5"
		 hash20= "661b975955f4334d41bf7c8ddf87b2ec"
		 hash21= "772e18025162752813389762666d5745"
		 hash22= "777fa70ea85f437a6352ce4d595286fd"
		 hash23= "806a1b2280fcbf2fa98ba8810c273252"
		 hash24= "82e00f58d4eb6ce623912d04b71b22e4"
		 hash25= "876788702048fd2682fe112514a282f8"
		 hash26= "a443d1a1f2ca7d6da4ae6295ae8701b2"
		 hash27= "a446aaa7f7ec32229c313eb7a916b8e9"
		 hash28= "a5b7ac664d22f2b874af3fbe2c01e793"
		 hash29= "a9fe441c7dd48ce0ee765793eb5d8457"
		 hash30= "b4e4f042aa4be598513cacb2b0d6c465"
		 hash31= "c35e2c4f8dea24b968276302d40ee11e"
		 hash32= "cff0bc04c620b913c89dec802ae3501a"
		 hash33= "d74f16dba6359f7b3dd2b7e85afba313"
		 hash34= "d9a0fc4bbeaffe68d119551176f03788"
		 hash35= "dca2b62d63b31c28779bdf6f1f7210d9"
		 hash36= "e27c847d1a8c705f1151499888378b15"
		 hash37= "e3d99e5a5adc0646c766c451ddc6a97e"
		 hash38= "ef22d6866d58eaec598c4c86ff14e0fb"
		 hash39= "efa6a49d8b508cb1b750de83735fb1f4"
		 hash40= "efd9a593369bd1e6743f8e0a722b6d39"
		 hash41= "f41efd7c8a70b1f99b2283bef81d9bab"
		 hash42= "fb5bee7e0fdfe805a2ef36401a75ad9a"
		 hash43= "fb890d1e69616f880ac4ae9cf54b9de7"
		 hash44= "fd088e63a46f78d6ec59188970dc353d"

	strings:

	
 		 $a1= "SOFTWAREMicrosoftWindowsCurrentVersionExplorerShell Folders" fullword ascii
		 $a2= "Y]x)_atN^`u[^`uc_awc`bxc`cxcacycbezccezdcf{ddg|ddg|deh}dfi~dgj" fullword ascii

		 $hex1= {2461313d2022534f46}
		 $hex2= {2461323d2022595d78}

	condition:
		1 of them
}
