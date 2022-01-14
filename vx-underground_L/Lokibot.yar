
/*
   YARA Rule Set
   Author: resteex
   Identifier: Lokibot 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Lokibot {
	meta: 
		 description= "Lokibot Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_04-07-06" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "04bdaec3bf8ef272bd6de2acf3cb828c"
		 hash2= "21e6f4fefdf70039a9160ca04a388389"
		 hash3= "3f327df4753c877cc8c91a952df75fb9"
		 hash4= "4e7c50fb3577f51f87e113c2fc40d5e7"
		 hash5= "6cc1182298faedff4123a01cd71f17f5"
		 hash6= "79cbe5c736dca5564640e51892f32c1b"
		 hash7= "8cf5cb10708d0fea42106a1d31ba4248"
		 hash8= "8f35517bd68bbe4d0d2362445172763a"
		 hash9= "95f5f9111344c4c472b9d6656337abe3"
		 hash10= "97ee10e7b9b299b04c83d12eaf6dc5f5"
		 hash11= "9b8e1997fa6a66bc23a203c92c175f77"
		 hash12= "a0339a15a2f219b54b3c1a6b4afbc6be"
		 hash13= "cf940aab721563c8e310b535f0e8a2f8"
		 hash14= "f3d18776fefa9b0cffa6914cdf306cc9"

	strings:

	
 		 $s1= ";=;>;?;@;BACADAEAFAGAJIKILIMIPO" fullword wide
		 $s2= "Bt_Continue_As_Guest.BackgroundImage" fullword wide
		 $s3= "Bt_Continue_As_Manager.BackgroundImage" fullword wide
		 $s4= "Bt_Continue_As_Player.BackgroundImage" fullword wide
		 $s5= "Bt_Continue_change_details.BackgroundImage" fullword wide
		 $s6= "Bt_reversi_instuctions.BackgroundImage" fullword wide
		 $s7= "Bt_User_managment_back.BackgroundImage" fullword wide
		 $s8= "Bt_User_Managment_exit.BackgroundImage" fullword wide
		 $s9= "Bt_usersOptions_exit.BackgroundImage" fullword wide
		 $s10= "{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}N" fullword wide
		 $s11= "Microsoft.Container.EncryptionTransform" fullword wide
		 $s12= "Remove_Manager_show.BackgroundImage" fullword wide
		 $a1= ";=;>;?;@;BACADAEAFAGAJIKILIMIPO" fullword ascii

		 $hex1= {2461313d20223b3d3b}
		 $hex2= {247331303d20227b46}
		 $hex3= {247331313d20224d69}
		 $hex4= {247331323d20225265}
		 $hex5= {2473313d20223b3d3b}
		 $hex6= {2473323d202242745f}
		 $hex7= {2473333d202242745f}
		 $hex8= {2473343d202242745f}
		 $hex9= {2473353d202242745f}
		 $hex10= {2473363d202242745f}
		 $hex11= {2473373d202242745f}
		 $hex12= {2473383d202242745f}
		 $hex13= {2473393d202242745f}

	condition:
		1 of them
}
