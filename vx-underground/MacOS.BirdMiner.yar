
/*
   YARA Rule Set
   Author: resteex
   Identifier: MacOS_BirdMiner 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_MacOS_BirdMiner {
	meta: 
		 description= "MacOS_BirdMiner Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-13-46" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "05723632efc2b45d12e0fc1cdcb4092d"
		 hash2= "7cafea82e5dbb9b29d483ba5f8b94c79"
		 hash3= "a2698800705b26bfd9ef2f28ded2b50d"
		 hash4= "a9625bc237704cc7a1b12db06c654dea"
		 hash5= "a99892e4e81d5eda92cf8adb36f1c5d0"

	strings:

	
 		 $s1= "1ValhallaVintageVerbKeyfileForTeamHEXWARS.vkeyfile" fullword wide
		 $s2= "'/7?GOv_J~N|yqWpirzkstlu}" fullword wide
		 $s3= "=>?@A>?@A>?@A>?@A>?@ABCBC" fullword wide
		 $s4= ">?@A>?@A>?@A>?@A>?@ADDDEDE*+DEDE*+FG" fullword wide
		 $s5= "=>?@ABTSRQPONMLKJIHGFEDCU67" fullword wide
		 $s6= "=>?@ABTSRQPONMLKJIHGFEDCU7" fullword wide
		 $s7= ")HIJKLMNOPQRSTUVWXYZ[]^_`abcd" fullword wide
		 $s8= "MemoryOverwriteRequestControl" fullword wide
		 $s9= "OQSUWY[]_acegikmPRTVXZ^`bdfhjln" fullword wide
		 $s10= "Valhalla_VintageVerb_1_7_1_macOS" fullword wide
		 $s11= "Valhalla_VintageVerb_1_7_1_macOS@" fullword wide
		 $s12= "VR^ZFBNJvr~zfbnj+)/-#!'%;9?=317" fullword wide
		 $a1= "1ValhallaVintageVerbKeyfileForTeamHEXWARS.vkeyfile" fullword ascii

		 $hex1= {2461313d2022315661}
		 $hex2= {247331303d20225661}
		 $hex3= {247331313d20225661}
		 $hex4= {247331323d20225652}
		 $hex5= {2473313d2022315661}
		 $hex6= {2473323d2022272f37}
		 $hex7= {2473333d20223d3e3f}
		 $hex8= {2473343d20223e3f40}
		 $hex9= {2473353d20223d3e3f}
		 $hex10= {2473363d20223d3e3f}
		 $hex11= {2473373d2022294849}
		 $hex12= {2473383d20224d656d}
		 $hex13= {2473393d20224f5153}

	condition:
		8 of them
}
