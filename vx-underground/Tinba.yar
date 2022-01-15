
/*
   YARA Rule Set
   Author: resteex
   Identifier: Tinba 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Tinba {
	meta: 
		 description= "Tinba Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-19-07" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "04a9c0fb139c55b2a491c6594f2c314b"
		 hash2= "082ece4939954ae3aa1924487a34644d"
		 hash3= "0867fcfad285e8f898bb0202c8f81905"
		 hash4= "0bbdf45559aaf39d8edd79aa0944598c"
		 hash5= "0dad3f4578ffd57c947903ca913ddbd0"
		 hash6= "192ba27f713be95a97e5beea5e5244ae"
		 hash7= "1aee62469f457b1ec2aa7c5bd5edee20"
		 hash8= "20bbaf30652487a018f47ce6a859d0a5"
		 hash9= "3d1c468d180af360849afc55ee9bb1ee"
		 hash10= "3ef401639cbe68c34f328bd03ebd793e"
		 hash11= "6b1c57d6e0a9701c2daa157c10d21a74"
		 hash12= "804c7b5bda551bd333a45ed02793d208"
		 hash13= "8fa2f888b934eca5cd06e6f6e55c117d"
		 hash14= "922ed38bb7d6aa1de8f6ba7f1fed8212"
		 hash15= "bcc74a74859f29c9bfedae54b5972a92"
		 hash16= "c81f37e2bc6fb6aff9cae2a27c0e4f06"
		 hash17= "d96e44c8befe84a794127ba3601f0aee"
		 hash18= "e5b97304c33c9a681bcabcd573cc96d0"

	strings:

	
 		 $s1= "{8856F961-340A-11D0-A96B-00C04FD705A2}" fullword wide
		 $s2= "Content-Type: application/x-www-form-urlencoded" fullword wide
		 $s3= "ExperientialDesperateDesignation" fullword wide
		 $s4= "FreestandingDeltoidHebrew" fullword wide
		 $s5= "@http://ibf-cmi-1938953175.us-east-1.elb.amazonaws.com" fullword wide
		 $s6= "I|IxItIpIlIhIdI`IIXIPIHI@I8I0I(I I" fullword wide
		 $s7= "IllegalDeadeningEchinoderms.exe" fullword wide
		 $s8= "LancetInexplicableInability.exe" fullword wide
		 $s9= "PerformerPreselectsProletariat.exe" fullword wide
		 $s10= "rationales practicalities" fullword wide
		 $s11= "RovingsRadishSpectrometric.exe" fullword wide
		 $s12= "U_i=V`j>Wak?Xbl@YcmAZdnB[eoCfpD]gq" fullword wide
		 $a1= "@http://ibf-cmi-1938953175.us-east-1.elb.amazonaws.com" fullword ascii

		 $hex1= {2461313d2022406874}
		 $hex2= {247331303d20227261}
		 $hex3= {247331313d2022526f}
		 $hex4= {247331323d2022555f}
		 $hex5= {2473313d20227b3838}
		 $hex6= {2473323d2022436f6e}
		 $hex7= {2473333d2022457870}
		 $hex8= {2473343d2022467265}
		 $hex9= {2473353d2022406874}
		 $hex10= {2473363d2022497c49}
		 $hex11= {2473373d2022496c6c}
		 $hex12= {2473383d20224c616e}
		 $hex13= {2473393d2022506572}

	condition:
		8 of them
}
