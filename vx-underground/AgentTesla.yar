
/*
   YARA Rule Set
   Author: resteex
   Identifier: AgentTesla 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_AgentTesla {
	meta: 
		 description= "AgentTesla Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-12_23-46-07" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "14a388b154b55a25c66b1bfef9499b64"
		 hash2= "1559eb5515eb732de889dcdff24662c9"
		 hash3= "19116e822e8178fc103e51fe18c825a4"
		 hash4= "1d7ebed1baece67a31ce0a17a0320cb2"
		 hash5= "20f2885ae3ffb24d8a905b8714207d5b"
		 hash6= "282c9c3ec7ffed97693709297772c923"
		 hash7= "29d9976d73aabf191eafe0f8b045cc85"
		 hash8= "2a325a8d5588a4a0f59bedc75142082a"
		 hash9= "2c796a675fe4d3587af0bdadb10abb6b"
		 hash10= "37f68678914c4b15b4f1768037d3b3a1"
		 hash11= "3cd8aa88a04bed66e00df1810933be1f"
		 hash12= "3ed5730d8b144e0dc00d144595e21551"
		 hash13= "413ca1f198008a2980f7891c059bc188"
		 hash14= "459a093eb5e65eaa2ea203129f6fc91b"
		 hash15= "4b71d55f16c4a497fb2457c340d5a8a6"
		 hash16= "506887f557d9399e9cd663b65b2271d5"
		 hash17= "5b14a7366cf5dbea3386c6afbd25f012"
		 hash18= "5f67fb00e05a10d2d497b03ea2985931"
		 hash19= "679e61e35641582d91f79ec97752b2a5"
		 hash20= "6802c9c481671ec10ee1178946a46c73"
		 hash21= "7e19235ca4a6192bdace52baa0a40d26"
		 hash22= "81afa08f1a1acfa3fd9f52ecadda2f55"
		 hash23= "8df4b43e11c352b502cea6a13e220468"
		 hash24= "8e2aa51f45393d980a4d9b20947976b6"
		 hash25= "8f4ba6f084527fe557a3f6cc42e20302"
		 hash26= "91647ee9941ad4d5027fc5b5f1ac7217"
		 hash27= "93e11d77cbe4ba9e38b6e4cdb7af8428"
		 hash28= "99d846bbf242277134ba3b6cb92ab2eb"
		 hash29= "adb42bae8d1ab779c2fb58a47115b73e"
		 hash30= "bacc98ebdf2f1565f597959c6d8206b9"
		 hash31= "bc9f0c07dfe0016049662acbafe3c96f"
		 hash32= "c59677e174a469869400d73ef00bb6e3"
		 hash33= "d4d3c3af1b87b9fdfeb486205786e607"
		 hash34= "d7abc0880783e5e1c08f8a70a292473b"
		 hash35= "d8e5aa1965cbd11b4031df178d936bcb"
		 hash36= "dc6a5d1b3accb015fe2b6f91176c57c5"
		 hash37= "e1e7b17c9e0a298346b82f04fabd4f60"
		 hash38= "e5b234b445e81c5a55f21bc75eb40e5e"
		 hash39= "eaf39a263bece3cbd0d6b70e22c12d8f"
		 hash40= "ecf6a9ec7dbc4c268d6f07df63b0ea21"
		 hash41= "f29673f00584145b44295bd7f8803506"
		 hash42= "f2c11dc15dd41d48b94a58ffb54d5a8c"
		 hash43= "f3bde54a6199f0530df0c8b9b110a2d6"
		 hash44= "f8efaa5826c602395a6317abb2905a25"
		 hash45= "faac549cb964350c5bb2ea12baa99976"
		 hash46= "ffdc0c9d0453f714bfc0b1d98141c21d"

	strings:

	
 		 $s1= "{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}{11}{12}{13}{14}{15}{16}{17}{18}{19}{20}{21}{22}{23}{24}{25}{26}{2" fullword wide
		 $s2= "{102}{103}{104}{105}{106}{107}{108}{109}{110}{111}{112}{113}{114}{115}{116}{117}{118}{119}{120}{121}" fullword wide
		 $s3= "{122}{123}{124}{125}{126}{127}{128}{129}{130}{131}" fullword wide
		 $s4= "2}{53}{54}{55}{56}{57}{58}{59}{60}{61}{62}{63}{64}{65}{66}{67}{68}{69}{70}{71}{72}" fullword wide
		 $s5= "2}{53}{54}{55}{56}{57}{58}{59}{60}{61}{62}{63}{64}{65}{66}{67}{68}{69}{70}{71}{72}{73}{74}{75}{76}{7" fullword wide
		 $s6= "43826d1e-e718-42ee-bc55-a1e261c37bfe" fullword wide
		 $s7= "7}{28}{29}{30}{31}{32}{33}{34}{35}{36}{37}{38}{39}{40}{41}{42}{43}{44}{45}{46}{47}{48}{49}{50}{51}{5" fullword wide
		 $s8= "7}{78}{79}{80}{81}{82}{83}{84}{85}{86}{87}{88}{89}{90}{91}{92}{93}{94}{95}{96}{97}{98}{99}{100}{101}" fullword wide
		 $s9= "A7a5a12aa79caQGa7843bqeK7dSEc14haV4Qk3ax7Se4C" fullword wide
		 $s10= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s11= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s12= "Arquivo ControlePorTwitter.cfg inexistente" fullword wide
		 $s13= "BA47pe49Q4bGMkM18o4bavXaa9f646y1A1u9a81te248IbW1" fullword wide
		 $s14= "C2cdI1db8r2i1c3gJ4VpkdS9t813Iacz984eUD474aa8Ia" fullword wide
		 $s15= "Capi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s16= "CQeBiZjIQQ29NrMbGXx.v5yq8sj1tTg6NZoJAKI" fullword wide
		 $s17= "CveEmpresaDataGridViewTextBoxColumn" fullword wide
		 $s18= "CvesssubmenuDataGridViewTextBoxColumn" fullword wide
		 $s19= "CvessubmenuDataGridViewTextBoxColumn" fullword wide
		 $s20= "CvesubmenuDataGridViewTextBoxColumn" fullword wide
		 $s21= "D3771oAStHe2f9819w94cY9t1Ck8eBfb88a" fullword wide
		 $s22= "D5dczBdfccAWTa2GgcmdIht4eey1bk7Acy9t14698wY" fullword wide
		 $s23= "DirectoryBackgroundshellSymlinkMaker" fullword wide
		 $s24= "E1cad98d7pqrpv6E4b24aq71IAn41783b6p8P4N6" fullword wide
		 $s25= "E6b7defajb3L6jaa4GeTl5aid1aadp492dF8e7U84o" fullword wide
		 $s26= "Eb4aa6dTc4984Dc1f7664ePbTUp64437f848eba" fullword wide
		 $s27= "Ebq50XeCI66161XOJ1exfch6LdN98IRJUf68BA9D6l1K" fullword wide
		 $s28= "Ep319KRf4My447cf14dnh64a4f1vzx118HX" fullword wide
		 $s29= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s30= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s31= "F7f9d11e8158cqdSf8HPM4tSsz18J84c181r5e" fullword wide
		 $s32= "F84A98U7401e9ay4d8cdD5dh3fSaca8z4eW8" fullword wide
		 $s33= "{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}N" fullword wide
		 $s34= "FJU8coLKdV1U74yeQ12f1qK8faBdP4gbBo8refrn64toJjH4" fullword wide
		 $s35= "F.StartPosition = FormStartPosition.CenterParent" fullword wide
		 $s36= "GrayIris.Utilities.Properties.Resources" fullword wide
		 $s37= "G:VSprojectsFlyingGameFlyingGameSoundsBeep.wav" fullword wide
		 $s38= "G:VSprojectsFlyingGameFlyingGameSoundsBombAway.wav" fullword wide
		 $s39= "G:VSprojectsFlyingGameFlyingGameSoundsBombXplode.wav" fullword wide
		 $s40= "G:VSprojectsFlyingGameFlyingGameSoundsEnemyXplode.wav" fullword wide
		 $s41= "G:VSprojectsFlyingGameFlyingGameSoundsfire.wav" fullword wide
		 $s42= "G:VSprojectsFlyingGameFlyingGameSoundstada.wav" fullword wide
		 $s43= "hjzSoKEdezlRCIYwJFEAerVUZCdMcHUt.exe" fullword wide
		 $s44= "http://api.twitter.com/1/direct_messages.xml?since_id={0}" fullword wide
		 $s45= "http://api.twitter.com/1/statuses/user_timeline.xml?screen_name=KB_Gaming" fullword wide
		 $s46= "http://dl.dropbox.com/u/95912365/DynamicLink.txt" fullword wide
		 $s47= "http://dl.dropbox.com/u/95912365/Update.txt" fullword wide
		 $s48= "https://bakercost.gq/liverpool-fc-news/features/steven-gerrard-liverpool-future-dalglish--goal-926FB" fullword wide
		 $s49= "https://dl.dropbox.com/u/32095369/IRpack.zip" fullword wide
		 $s50= "https://dl.dropbox.com/u/32095369/IR.txt" fullword wide
		 $s51= "https://dl.dropbox.com/u/32095369/TFRpack.zip" fullword wide
		 $s52= "https://dl.dropbox.com/u/32095369/TFR.txt" fullword wide
		 $s53= "https://login.eveonline.com/account/external?provider=Fb&returnUrl=%2F" fullword wide
		 $s54= "https://login.eveonline.com/account/external?provider=Steam&returnUrl=%2F" fullword wide
		 $s55= "https://secure.eveonline.com/signup/" fullword wide
		 $s56= "https://www.eveonline.com/articles/patch-notes/?origin=launcher" fullword wide
		 $s57= "https://www.theonionrouter.com/dist.torproject.org/torbrowser/9.5.3/tor-win32-0.4.3.6.zip" fullword wide
		 $s58= "http://twitter.com/statuses/user_timeline.xml?screen_name={0}" fullword wide
		 $s59= "Leba4e4o0dK31jaeKhb88b259daaKb9Y21W3v7m39ff" fullword wide
		 $s60= "M9476b7U5H9z97VEaHkjYe74afeXbeTpJ44kMS9dAIea89E" fullword wide
		 $s61= "Manina.Windows.Forms.Properties.Resources" fullword wide
		 $s62= "Microsoft.Container.EncryptionTransform" fullword wide
		 $s63= "N1u1Gd6Pn69ceAPw4WkT61b58944p7AjdaF88086dea" fullword wide
		 $s64= "Nb7I483Z9L9N7Uzew9897Cf3EadW2gtd7Y4p4737as" fullword wide
		 $s65= "NodeGraphControl.Properties.Resources" fullword wide
		 $s66= "NomsistemaDataGridViewTextBoxColumn" fullword wide
		 $s67= "pi-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s68= "pi-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s69= "printPreviewToolStripMenuItem.Image" fullword wide
		 $s70= "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=" fullword wide
		 $s71= "PUDdbXbik56Etu81b65e9u1V1565mG1f94ve24799lw8779" fullword wide
		 $s72= "RutaAplicacionDataGridViewTextBoxColumn" fullword wide
		 $s73= "SoftwareMicrosoftWindowsCurrentVersion" fullword wide
		 $s74= "Unsupported ProcessWindowStyle value." fullword wide
		 $s75= "urn:schemas-microsoft-com:xml-diffgram-v1" fullword wide
		 $s76= "Vc2aoez9u43E9rc754BAedc516dcb4V56Ib5ar6977f8DC" fullword wide
		 $s77= "Wac98791fcp5hz9NuccVOpxe4ee5XZz9V48afRdewbAe8" fullword wide
		 $s78= "WindowsFormsApp1.Properties.Resources" fullword wide
		 $a1= "iSorY2BG82mUoRaK46HyXyCvITCqIFkdJ0A2jhtY069CgAzKjmOrt6RNj+865YfXKgLco8iCWQJtq9aRH6s6OFXuGoAcEX0AjL5KxICCtjpt3Xal6uhwjKKimzjbtuSx+wz1ih1Y2Fa7Ly7ZNy3n8s" fullword ascii
		 $a2= "++wT+eAPCTAB8iT9s9Y9jGyCT8eysq6UA6KIW+2WZs21iRMssM3aQ2HYqcyr1J3cY6rSvslUA6aYzV221A5k3CK84sA67K7IdAvX5s9lhGo05gBOJ4ZDWWzfpHNsPiJ5IA1rRQvsfj6xJ5yssWQila" fullword ascii

		 $hex1= {2461313d202269536f}
		 $hex2= {2461323d20222b2b77}
		 $hex3= {247331303d20226170}
		 $hex4= {247331313d20226170}
		 $hex5= {247331323d20224172}
		 $hex6= {247331333d20224241}
		 $hex7= {247331343d20224332}
		 $hex8= {247331353d20224361}
		 $hex9= {247331363d20224351}
		 $hex10= {247331373d20224376}
		 $hex11= {247331383d20224376}
		 $hex12= {247331393d20224376}
		 $hex13= {2473313d20227b307d}
		 $hex14= {247332303d20224376}
		 $hex15= {247332313d20224433}
		 $hex16= {247332323d20224435}
		 $hex17= {247332333d20224469}
		 $hex18= {247332343d20224531}
		 $hex19= {247332353d20224536}
		 $hex20= {247332363d20224562}
		 $hex21= {247332373d20224562}
		 $hex22= {247332383d20224570}
		 $hex23= {247332393d20226578}
		 $hex24= {2473323d20227b3130}
		 $hex25= {247333303d20226578}
		 $hex26= {247333313d20224637}
		 $hex27= {247333323d20224638}
		 $hex28= {247333333d20227b46}
		 $hex29= {247333343d2022464a}
		 $hex30= {247333353d2022462e}
		 $hex31= {247333363d20224772}
		 $hex32= {247333373d2022473a}
		 $hex33= {247333383d2022473a}
		 $hex34= {247333393d2022473a}
		 $hex35= {2473333d20227b3132}
		 $hex36= {247334303d2022473a}
		 $hex37= {247334313d2022473a}
		 $hex38= {247334323d2022473a}
		 $hex39= {247334333d2022686a}
		 $hex40= {247334343d20226874}
		 $hex41= {247334353d20226874}
		 $hex42= {247334363d20226874}
		 $hex43= {247334373d20226874}
		 $hex44= {247334383d20226874}
		 $hex45= {247334393d20226874}
		 $hex46= {2473343d2022327d7b}
		 $hex47= {247335303d20226874}
		 $hex48= {247335313d20226874}
		 $hex49= {247335323d20226874}
		 $hex50= {247335333d20226874}
		 $hex51= {247335343d20226874}
		 $hex52= {247335353d20226874}
		 $hex53= {247335363d20226874}
		 $hex54= {247335373d20226874}
		 $hex55= {247335383d20226874}
		 $hex56= {247335393d20224c65}
		 $hex57= {2473353d2022327d7b}
		 $hex58= {247336303d20224d39}
		 $hex59= {247336313d20224d61}
		 $hex60= {247336323d20224d69}
		 $hex61= {247336333d20224e31}
		 $hex62= {247336343d20224e62}
		 $hex63= {247336353d20224e6f}
		 $hex64= {247336363d20224e6f}
		 $hex65= {247336373d20227069}
		 $hex66= {247336383d20227069}
		 $hex67= {247336393d20227072}
		 $hex68= {2473363d2022343338}
		 $hex69= {247337303d20225072}
		 $hex70= {247337313d20225055}
		 $hex71= {247337323d20225275}
		 $hex72= {247337333d2022536f}
		 $hex73= {247337343d2022556e}
		 $hex74= {247337353d20227572}
		 $hex75= {247337363d20225663}
		 $hex76= {247337373d20225761}
		 $hex77= {247337383d20225769}
		 $hex78= {2473373d2022377d7b}
		 $hex79= {2473383d2022377d7b}
		 $hex80= {2473393d2022413761}

	condition:
		10 of them
}
