
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Jigsaw 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Jigsaw {
	meta: 
		 description= "Ransomware_Jigsaw Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-53-35" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2773e3dc59472296cb0024ba7715a64e"

	strings:

	
 		 $s1= "12Xspzstah37626slkwKhsKSHA" fullword wide
		 $s2= "address/balance/" fullword wide
		 $s3= "Assembly Version" fullword wide
		 $s4= "BitcoinBlackmailer.exe" fullword wide
		 $s5= "buttonCheckPayment" fullword wide
		 $s6= "buttonViewEncryptedFiles" fullword wide
		 $s7= "costura.newtonsoft.json.dll.zip" fullword wide
		 $s8= "dataGridViewEncryptedFiles" fullword wide
		 $s9= "DeleteItself.bat" fullword wide
		 $s10= "Drpbxdrpbx.exe" fullword wide
		 $s11= "EncryptedFileList.txt" fullword wide
		 $s12= "ExtensionsToEncrypt" fullword wide
		 $s13= "FileDescription" fullword wide
		 $s14= "FileSystemSimulation" fullword wide
		 $s15= "FormEncryptedFiles" fullword wide
		 $s16= "Frfxfirefox.exe" fullword wide
		 $s17= "http://btc.blockr.io/api/v1/" fullword wide
		 $s18= "labelFilesToDelete" fullword wide
		 $s19= "LegalTrademarks" fullword wide
		 $s20= "Main.Properties.Resources" fullword wide
		 $s21= "newtonsoft.json" fullword wide
		 $s22= "NotTxtTest.nottxt" fullword wide
		 $s23= "OoIsAwwF23cICQoLDA0ODe==" fullword wide
		 $s24= "OriginalFilename" fullword wide
		 $s25= "SOFTWAREMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s26= "vanityAddresses" fullword wide
		 $s27= "VS_VERSION_INFO" fullword wide
		 $a1= "SOFTWAREMicrosoftWindowsCurrentVersionRun" fullword ascii

		 $hex1= {2461313d2022534f46}
		 $hex2= {247331303d20224472}
		 $hex3= {247331313d2022456e}
		 $hex4= {247331323d20224578}
		 $hex5= {247331333d20224669}
		 $hex6= {247331343d20224669}
		 $hex7= {247331353d2022466f}
		 $hex8= {247331363d20224672}
		 $hex9= {247331373d20226874}
		 $hex10= {247331383d20226c61}
		 $hex11= {247331393d20224c65}
		 $hex12= {2473313d2022313258}
		 $hex13= {247332303d20224d61}
		 $hex14= {247332313d20226e65}
		 $hex15= {247332323d20224e6f}
		 $hex16= {247332333d20224f6f}
		 $hex17= {247332343d20224f72}
		 $hex18= {247332353d2022534f}
		 $hex19= {247332363d20227661}
		 $hex20= {247332373d20225653}
		 $hex21= {2473323d2022616464}
		 $hex22= {2473333d2022417373}
		 $hex23= {2473343d2022426974}
		 $hex24= {2473353d2022627574}
		 $hex25= {2473363d2022627574}
		 $hex26= {2473373d2022636f73}
		 $hex27= {2473383d2022646174}
		 $hex28= {2473393d202244656c}

	condition:
		3 of them
}
