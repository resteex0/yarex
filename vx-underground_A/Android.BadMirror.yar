
/*
   YARA Rule Set
   Author: resteex
   Identifier: Android_BadMirror 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Android_BadMirror {
	meta: 
		 description= "Android_BadMirror Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-12_19-29-19" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0bf78e15633c3d9381a1195e866bece1"
		 hash2= "1e4646c234d62e185ed2d95ce973569b"
		 hash3= "2fad71e5574cca4020583ab6d1b2a5aa"
		 hash4= "415990651f6b53b6df3208bea7e5e29d"
		 hash5= "4f437c0e4a424bc25c1a3abf26321d98"
		 hash6= "5cfad806d395ed8767897a99d3fe57b9"
		 hash7= "613d3f95ee24b3de704a2c38bab827de"
		 hash8= "bd8080486017ab8401c119a717812d17"

	strings:

	
 		 $s1= "2012-01-09T23:23:32+08:00" fullword wide
		 $s2= "2012-03-20T15:29:12+08:00" fullword wide
		 $s3= "2012-03-20T15:29:13+08:00" fullword wide
		 $s4= "2012-03-22T14:28:16+08:00" fullword wide
		 $s5= "2012-03-22T14:32:22+08:00" fullword wide
		 $s6= "2012-03-22T14:35:32+08:00" fullword wide
		 $s7= "com.loveplay.CatchFish.zxcps.zx1.test" fullword wide
		 $s8= "com.xmld.gwcm.xg821bb.zx1" fullword wide
		 $s9= "Edge - Sweet Music from the Game" fullword wide
		 $s10= "EGeneric RGB ProfileGenerel RGB-beskrivels" fullword wide
		 $s11= "gamestudio.nimble.console.zx1" fullword wide
		 $s12= "Genel RGB ProfiliYleinen RGB-profiiliUniwersalny profil RG" fullword wide
		 $s13= "ki RGB profilPerfil RGB gen" fullword wide
		 $s14= "org.funcity.runrunner.yh.zx1" fullword wide
		 $s15= "Profilo RGB genericoGenerisk RGB-profi" fullword wide
		 $s16= "The Shameful Last Minute Music" fullword wide

		 $hex1= {247331303d20224547}
		 $hex2= {247331313d20226761}
		 $hex3= {247331323d20224765}
		 $hex4= {247331333d20226b69}
		 $hex5= {247331343d20226f72}
		 $hex6= {247331353d20225072}
		 $hex7= {247331363d20225468}
		 $hex8= {2473313d2022323031}
		 $hex9= {2473323d2022323031}
		 $hex10= {2473333d2022323031}
		 $hex11= {2473343d2022323031}
		 $hex12= {2473353d2022323031}
		 $hex13= {2473363d2022323031}
		 $hex14= {2473373d2022636f6d}
		 $hex15= {2473383d2022636f6d}
		 $hex16= {2473393d2022456467}

	condition:
		2 of them
}
