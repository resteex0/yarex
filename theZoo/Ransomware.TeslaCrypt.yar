
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_TeslaCrypt 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_TeslaCrypt {
	meta: 
		 description= "Ransomware_TeslaCrypt Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-37-52" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "209a288c68207d57e0ce6e60ebf60729"
		 hash2= "6d3d62a4cff19b4f2cc7ce9027c33be8"
		 hash3= "6e080aa085293bb9fbdcc9015337d309"

	strings:

	
 		 $s1= "CLSID_AsyncReader" fullword wide
		 $s2= "CLSID_AsyncReader2" fullword wide
		 $s3= "Control PanelDesktop" fullword wide
		 $s4= "CryptoLocker.lnk" fullword wide
		 $s5= "CryptoLocker-v3" fullword wide
		 $s6= "Decryption key:" fullword wide
		 $s7= "FileDescription" fullword wide
		 $s8= "HELP_TO_DECRYPT_YOUR_FILES.bmp" fullword wide
		 $s9= "HELP_TO_DECRYPT_YOUR_FILES.txt" fullword wide
		 $s10= "https://www.torproject.org/projects/torbrowser.html.en" fullword wide
		 $s11= "LanmanWorkstation" fullword wide
		 $s12= "OriginalFilename" fullword wide
		 $s13= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s14= "%ssystem32cmd.exe" fullword wide
		 $s15= "Verification key:" fullword wide
		 $s16= "VS_VERSION_INFO" fullword wide
		 $s17= "w+ ,ccs=UTF-16LE" fullword wide
		 $s18= "www.torproject.org/projects/torbrowser.html.en" fullword wide
		 $a1= "https://www.torproject.org/projects/torbrowser.html.en" fullword ascii
		 $a2= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword ascii
		 $a3= "www.torproject.org/projects/torbrowser.html.en" fullword ascii

		 $hex1= {2461313d2022687474}
		 $hex2= {2461323d2022536f66}
		 $hex3= {2461333d2022777777}
		 $hex4= {247331303d20226874}
		 $hex5= {247331313d20224c61}
		 $hex6= {247331323d20224f72}
		 $hex7= {247331333d2022536f}
		 $hex8= {247331343d20222573}
		 $hex9= {247331353d20225665}
		 $hex10= {247331363d20225653}
		 $hex11= {247331373d2022772b}
		 $hex12= {247331383d20227777}
		 $hex13= {2473313d2022434c53}
		 $hex14= {2473323d2022434c53}
		 $hex15= {2473333d2022436f6e}
		 $hex16= {2473343d2022437279}
		 $hex17= {2473353d2022437279}
		 $hex18= {2473363d2022446563}
		 $hex19= {2473373d202246696c}
		 $hex20= {2473383d202248454c}
		 $hex21= {2473393d202248454c}

	condition:
		7 of them
}
