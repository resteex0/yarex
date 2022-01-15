
/*
   YARA Rule Set
   Author: resteex
   Identifier: SnakeKeylogger 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_SnakeKeylogger {
	meta: 
		 description= "SnakeKeylogger Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-18-48" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1bad301dc6bc6e3ebda9398dc725cc09"
		 hash2= "2e5077d9cc4b6187f18e95fecc6bbd06"
		 hash3= "432dafd9a9d895a6be98225d93533bc9"
		 hash4= "5a4a93f2575eb856a8eefd6e51480edb"
		 hash5= "6f604a598bd5f7c618f07959e7747c32"
		 hash6= "7a20fca2f86df8d559c5375f340463a5"
		 hash7= "87252a7dc3e57b82a34f1d27041e5ed9"
		 hash8= "88fba5ee75304db402d27f5528bbadc9"
		 hash9= "9b43421aed19f006408299b9b8b64ccc"
		 hash10= "acccbed12f341452b319fe8eba4ce933"
		 hash11= "cbb0c2728f585c50a4506ddc36418fbd"
		 hash12= "d9ab1bffed2d390d04afa425a7cd6a0b"
		 hash13= "e24e5174ad14f83752150354518dc88f"

	strings:

	
 		 $s1= "$this.AutoScaleDimensions" fullword wide
		 $s2= "//agendamentos//agendamento" fullword wide
		 $s3= "AgendamentosToolStripMenuItem" fullword wide
		 $s4= "colorBackgroundToolStripMenuItem" fullword wide
		 $s5= "colorSelectBackgroundToolStripMenuItem" fullword wide
		 $s6= "colorSelectTextToolStripMenuItem" fullword wide
		 $s7= "colorTextToolStripMenuItem" fullword wide
		 $s8= "colorTextToolStripMenuItem1" fullword wide
		 $s9= "ComandosToolStripMenuItem" fullword wide
		 $s10= "controleportwitter@gmail.com" fullword wide
		 $s11= "ControlePorTwitter.Resources" fullword wide
		 $s12= "ControlePorTwitter.Zodiac" fullword wide
		 $s13= "DiretorioArquivoConfiguracao=" fullword wide
		 $s14= "findNextToolStripMenuItem" fullword wide
		 $s15= "Glsifnfktmcrggbjkpf.Fmxxihtoecbcvliwsdlmkru.dll" fullword wide
		 $s16= "Glsifnfktmcrggbjkpf.Properties.Resources" fullword wide
		 $s17= "../help/buttonThumbDown.bmp" fullword wide
		 $s18= "../help/buttonThumbUp.bmp" fullword wide
		 $s19= "HostExecutionContextSwitch" fullword wide
		 $s20= "http://api.twitter.com/1/direct_messages.xml?since_id={0}" fullword wide
		 $s21= "http://dl.dropbox.com/u/95912365/DynamicLink.txt" fullword wide
		 $s22= "http://dl.dropbox.com/u/95912365/Update.txt" fullword wide
		 $s23= "https://dl.dropbox.com/u/32095369/" fullword wide
		 $s24= "https://dl.dropbox.com/u/32095369/IRpack.zip" fullword wide
		 $s25= "https://dl.dropbox.com/u/32095369/IR.txt" fullword wide
		 $s26= "https://dl.dropbox.com/u/32095369/TFRpack.zip" fullword wide
		 $s27= "https://dl.dropbox.com/u/32095369/TFR.txt" fullword wide
		 $s28= "https://github.com/AsayuGit" fullword wide
		 $s29= "https://login.minecraft.net/?user=" fullword wide
		 $s30= "https://twitter.com/KB_Gaming" fullword wide
		 $s31= "https://www.bing.com/search?q=" fullword wide
		 $s32= "https://www.google.com/search?q=" fullword wide
		 $s33= "http://tempuri.org/DsFavorites.xsd" fullword wide
		 $s34= "http://twitter.com/statuses/user_timeline.xml?screen_name={0}" fullword wide
		 $s35= "http://www.killerbeesgaming.com" fullword wide
		 $s36= "http://www.w3.org/2001/XMLSchema" fullword wide
		 $s37= "Jymcbt.Properties.Resources" fullword wide
		 $s38= "KillerBeesGaming Client2.exe" fullword wide
		 $s39= "KillerBeesGaming_Client.Bees" fullword wide
		 $s40= "KillerBeesGaming Client.exe" fullword wide
		 $s41= "KillerBeesGaming Client.exe" fullword wide
		 $s42= "KillerBeesGaming_Client.Resources" fullword wide
		 $s43= "lblDataUltimaMensagemLida" fullword wide
		 $s44= "MensagensToolStripMenuItem" fullword wide
		 $s45= "mining.industrial-craft.net" fullword wide
		 $s46= "modsrei_minimapkeyconfig.txt" fullword wide
		 $s47= "newWindowToolStripMenuItem" fullword wide
		 $s48= "OpenCC_GUI.Languages.Language_" fullword wide
		 $s49= "pageSetupToolStripMenuItem" fullword wide
		 $s50= "//parametros//UltimaMsgId" fullword wide
		 $s51= "Product_Specifications_Details_202100_RFQ.exe" fullword wide
		 $s52= "RestricaoUsuariosPorNomeString" fullword wide
		 $s53= "RGBGame.Properties.Resources" fullword wide
		 $s54= "searchWithBingToolStripMenuItem" fullword wide
		 $s55= "searchWithGoogleToolStripMenuItem" fullword wide
		 $s56= "selectAllToolStripMenuItem" fullword wide
		 $s57= "sendFeedbackToolStripMenuItem" fullword wide
		 $s58= "Specifications_Details_20337_FLQ.exe" fullword wide
		 $s59= "statusBarToolStripMenuItem" fullword wide
		 $s60= "Tetris.Properties.Resources" fullword wide
		 $s61= "timeDateToolStripMenuItem" fullword wide
		 $s62= "urn:schemas-microsoft-com:xml-diffgram-v1" fullword wide
		 $s63= "viewHelpToolStripMenuItem" fullword wide
		 $s64= "VisualizarToolStripMenuItem" fullword wide
		 $s65= "WinForms_RecursiveFormCreate" fullword wide
		 $s66= "WinForms_SeeInnerException" fullword wide
		 $s67= "wordWrapToolStripMenuItem" fullword wide
		 $a1= "http://api.twitter.com/1/direct_messages.xml?since_id={0}" fullword ascii
		 $a2= "http://twitter.com/statuses/user_timeline.xml?screen_name={0}" fullword ascii

		 $hex1= {2461313d2022687474}
		 $hex2= {2461323d2022687474}
		 $hex3= {247331303d2022636f}
		 $hex4= {247331313d2022436f}
		 $hex5= {247331323d2022436f}
		 $hex6= {247331333d20224469}
		 $hex7= {247331343d20226669}
		 $hex8= {247331353d2022476c}
		 $hex9= {247331363d2022476c}
		 $hex10= {247331373d20222e2e}
		 $hex11= {247331383d20222e2e}
		 $hex12= {247331393d2022486f}
		 $hex13= {2473313d2022247468}
		 $hex14= {247332303d20226874}
		 $hex15= {247332313d20226874}
		 $hex16= {247332323d20226874}
		 $hex17= {247332333d20226874}
		 $hex18= {247332343d20226874}
		 $hex19= {247332353d20226874}
		 $hex20= {247332363d20226874}
		 $hex21= {247332373d20226874}
		 $hex22= {247332383d20226874}
		 $hex23= {247332393d20226874}
		 $hex24= {2473323d20222f2f61}
		 $hex25= {247333303d20226874}
		 $hex26= {247333313d20226874}
		 $hex27= {247333323d20226874}
		 $hex28= {247333333d20226874}
		 $hex29= {247333343d20226874}
		 $hex30= {247333353d20226874}
		 $hex31= {247333363d20226874}
		 $hex32= {247333373d20224a79}
		 $hex33= {247333383d20224b69}
		 $hex34= {247333393d20224b69}
		 $hex35= {2473333d2022416765}
		 $hex36= {247334303d20224b69}
		 $hex37= {247334313d20224b69}
		 $hex38= {247334323d20224b69}
		 $hex39= {247334333d20226c62}
		 $hex40= {247334343d20224d65}
		 $hex41= {247334353d20226d69}
		 $hex42= {247334363d20226d6f}
		 $hex43= {247334373d20226e65}
		 $hex44= {247334383d20224f70}
		 $hex45= {247334393d20227061}
		 $hex46= {2473343d2022636f6c}
		 $hex47= {247335303d20222f2f}
		 $hex48= {247335313d20225072}
		 $hex49= {247335323d20225265}
		 $hex50= {247335333d20225247}
		 $hex51= {247335343d20227365}
		 $hex52= {247335353d20227365}
		 $hex53= {247335363d20227365}
		 $hex54= {247335373d20227365}
		 $hex55= {247335383d20225370}
		 $hex56= {247335393d20227374}
		 $hex57= {2473353d2022636f6c}
		 $hex58= {247336303d20225465}
		 $hex59= {247336313d20227469}
		 $hex60= {247336323d20227572}
		 $hex61= {247336333d20227669}
		 $hex62= {247336343d20225669}
		 $hex63= {247336353d20225769}
		 $hex64= {247336363d20225769}
		 $hex65= {247336373d2022776f}
		 $hex66= {2473363d2022636f6c}
		 $hex67= {2473373d2022636f6c}
		 $hex68= {2473383d2022636f6c}
		 $hex69= {2473393d2022436f6d}

	condition:
		46 of them
}
