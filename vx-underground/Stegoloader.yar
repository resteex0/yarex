
/*
   YARA Rule Set
   Author: resteex
   Identifier: Stegoloader 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Stegoloader {
	meta: 
		 description= "Stegoloader Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-19-02" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "02e47d668bce0b7deb6c9208d22d148a"
		 hash2= "0c3bd774d8fb3bbb4e62a203b8e2aa76"
		 hash3= "1a035c679d5636a702e6a39cc0ba2153"
		 hash4= "266e1e6ee6259901feb0546f5a6f96e8"
		 hash5= "2ecc11a74354b6731ee77662072cd8c5"
		 hash6= "4598cddad40091326f2f35ab53522180"
		 hash7= "4ffc3983146d76dd76060f728f3db40e"
		 hash8= "71afcffe1bdc68bb18c3ba6a3b10f832"
		 hash9= "8afd74209101185e1fc2e444673f871b"
		 hash10= "8b5607a780fcbd370320ce1db8e8a026"
		 hash11= "98c6c2b55d3d76441d996ebe1b86743b"
		 hash12= "9d999629df3cb1a0789c4cc8ddde16b3"
		 hash13= "a2cc7fc2534cfa299042a219924b862e"
		 hash14= "a5edd466b51884136623c864bbd78a9d"
		 hash15= "a5ee3322263a199c86c53a24665bf9c5"
		 hash16= "d04b13bb1d237f11e55c748d8915a16d"
		 hash17= "d88dbbd008786f880a64a756b27cce46"
		 hash18= "dae1884cae15bc336fdbf29b2368be7f"
		 hash19= "ea6249149f34811aacd9c7ae98518a05"

	strings:

	
 		 $s1= "6.3.9600.16384 (winblue_rtm.130821-1623)" fullword wide
		 $s2= "SOFTWAREMicrosoft.NETFramework" fullword wide
		 $s3= "X:q3xrNMoQBEH0ggeNv8eFiMcFXn2mu.htm" fullword wide
		 $s4= "Z:SQfOQe61R8YmeV7bXB2H.iso" fullword wide

		 $hex1= {2473313d2022362e33}
		 $hex2= {2473323d2022534f46}
		 $hex3= {2473333d2022583a71}
		 $hex4= {2473343d20225a3a53}

	condition:
		2 of them
}
