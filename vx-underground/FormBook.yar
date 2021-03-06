
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_FormBook 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_FormBook {
	meta: 
		 description= "vx_underground2_FormBook Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-56-51" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "028bf5bc572cf06e10c315334c397649"
		 hash2= "08730cdd286a4c9d46b38bb6545ac311"
		 hash3= "0b2d200b5f2dfc4e8f23fb1e93b9073f"
		 hash4= "0c87a280c26cdeb9d2fddf088c00eec7"
		 hash5= "0e715db2198ff670f4bf0e88e0e9b547"
		 hash6= "113f59d0bd4384226e40c17bf899935d"
		 hash7= "1e7bc879d7960afaa08148c635ae534f"
		 hash8= "2312324f5776b722b0d2242d6de074da"
		 hash9= "2ad386557a4c28ac6a39a6563ce2c490"
		 hash10= "2efc1c831fb879dc9af9e27261156d72"
		 hash11= "3dd87d18a1e0e5d97de8b77458d18f74"
		 hash12= "3e9bb4780693f9415c4e31cc7d578c25"
		 hash13= "41b2324864f8389319f7af2d004d6b40"
		 hash14= "4d6fc4ea4d0ac131db5dcffe37c50325"
		 hash15= "547805d838749b0f0649c924db427c5d"
		 hash16= "5898734f512fe21e26447c8b28fe802f"
		 hash17= "5b0a8804322abd640a1adfc8e19023f1"
		 hash18= "655318bec9b30d5a2f2dedf399d87438"
		 hash19= "6d5ef38c928715d84453b55395976428"
		 hash20= "6f69dab30bc56739e66919ff268b3b2a"
		 hash21= "701c6b75f0630fa7b4f12343ede0df54"
		 hash22= "750919bd7e02e7821efa1b1bd0ed4eda"
		 hash23= "7b2f837b3a3f8980901ca3a6f624d8d2"
		 hash24= "7c67d687aa9d574fcea531bda2eda1da"
		 hash25= "7ceecb14777497d950fef12be23cb30d"
		 hash26= "82816953c8ab81cab088fe61e1d64789"
		 hash27= "839de683df6ed956916017ff901d58f3"
		 hash28= "8ad6f5bcb95f2fd9717db09a9531254d"
		 hash29= "8ffb5b1aba6759d623f20a9744de4dd0"
		 hash30= "a3336f2a85c572aab40243c347ebfe59"
		 hash31= "a5964d858bf1688f2de5746ec08dabf5"
		 hash32= "ad8da5cd9ca3626cadab03a8eb60b62c"
		 hash33= "b5c67441c0b05ce335b2868e8ed28256"
		 hash34= "bad05e5a760ce7c6044eb5107f2163c6"
		 hash35= "bbd2f0585dc1db6e0765422c0caeaa29"
		 hash36= "be986c495952935b1e6cad471cf14747"
		 hash37= "e071eda90d0e53ace9919357d98281e4"
		 hash38= "e74da43c10752c24480ed5a858a2575c"
		 hash39= "f7eb2bff3a410fd8ef59e22b4e8c178b"
		 hash40= "f8874c315b198d265440f6ce9ba1d6bf"
		 hash41= "f91a66d080744b9e8b946984d6d747c4"
		 hash42= "f961d6f3eb82bc072a1c85287efb2ed4"
		 hash43= "fd587cf3f06742803e917b6700101c05"

	strings:

	
 		 $s1= "4173796E634D65737361676548656C70" fullword wide
		 $s2= "43826d1e-e718-42ee-bc55-a1e261c37bfe" fullword wide
		 $s3= "496E74657266616365466F7277617264696E67537570706F" fullword wide
		 $s4= "526573747269637465644572726F724F626A65" fullword wide
		 $s5= "53757070726573734D65737361676541747472696275" fullword wide
		 $s6= "547269706C6544455343727970746F5365727669636550726F766964" fullword wide
		 $s7= "AboutUserOSToolStripMenuItem" fullword wide
		 $s8= "//agendamentos//agendamento" fullword wide
		 $s9= "AgendamentosToolStripMenuItem" fullword wide
		 $s10= "aiiD39x/oTfKXhd/dkA41iBiQ6YtYGdk" fullword wide
		 $s11= "ApplicationsToolStripMenuItem" fullword wide
		 $s12= "AssemblyTargetedPatchBandAttribu.exe" fullword wide
		 $s13= "BackToolStripButton.Image" fullword wide
		 $s14= "btnBezier.BackgroundImage" fullword wide
		 $s15= "btnCircle.BackgroundImage" fullword wide
		 $s16= "btnSelect.BackgroundImage" fullword wide
		 $s17= "btnSquare.BackgroundImage" fullword wide
		 $s18= "Calculator.Properties.Resources" fullword wide
		 $s19= "C:ODD HighscoreHighscore.txt" fullword wide
		 $s20= "ComandosToolStripMenuItem" fullword wide
		 $s21= "ComCompatibleVersionAttribu.exe" fullword wide
		 $s22= "Contacto: toursandtripsSV@tours.com" fullword wide
		 $s23= "ContentsToolStripMenuItem" fullword wide
		 $s24= "Contribuyente inexistente." fullword wide
		 $s25= "Contribuyentes.idDomicilio" fullword wide
		 $s26= "controleportwitter@gmail.com" fullword wide
		 $s27= "ControlePorTwitter.Resources" fullword wide
		 $s28= "ControlePorTwitter.Zodiac" fullword wide
		 $s29= "ControlVehicular.RegistrarLicencias" fullword wide
		 $s30= "ControlVehicular.Resources" fullword wide
		 $s31= "copyToolStripMenuItem.Image" fullword wide
		 $s32= "C:UsersGlebDesktophex_dump.txt" fullword wide
		 $s33= "cutToolStripMenuItem.Image" fullword wide
		 $s34= "Dataimagespowerupsextraball.png" fullword wide
		 $s35= "Dataimagespowerupsspeedup.png" fullword wide
		 $s36= "DiretorioArquivoConfiguracao=" fullword wide
		 $s37= "EmpleadosToolStripMenuItem" fullword wide
		 $s38= "EndSessionToolStripMenuItem" fullword wide
		 $s39= "ExitToShellToolStripMenuItem" fullword wide
		 $s40= "ExitUserOSToolStripMenuItem" fullword wide
		 $s41= "{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}N" fullword wide
		 $s42= "FoldersToolStripButton.Image" fullword wide
		 $s43= "ForwardToolStripButton.Image" fullword wide
		 $s44= "Gcxifsdkvaiqxmznvaay.Aucrorbejpjpqs.dll" fullword wide
		 $s45= "Gcxifsdkvaiqxmznvaay.Properties.Resources" fullword wide
		 $s46= "G:VSprojectsFlyingGameFlyingGameSoundsBeep.wav" fullword wide
		 $s47= "G:VSprojectsFlyingGameFlyingGameSoundsBombAway.wav" fullword wide
		 $s48= "G:VSprojectsFlyingGameFlyingGameSoundsBombXplode.wav" fullword wide
		 $s49= "G:VSprojectsFlyingGameFlyingGameSoundsEnemyXplode.wav" fullword wide
		 $s50= "G:VSprojectsFlyingGameFlyingGameSoundsfire.wav" fullword wide
		 $s51= "G:VSprojectsFlyingGameFlyingGameSoundstada.wav" fullword wide
		 $s52= "HighScoresToolStripMenuItem" fullword wide
		 $s53= "http://api.twitter.com/1/direct_messages.xml?since_id={0}" fullword wide
		 $s54= "http://dl.dropbox.com/u/95912365/DynamicLink.txt" fullword wide
		 $s55= "http://dl.dropbox.com/u/95912365/Update.txt" fullword wide
		 $s56= "https://dl.dropbox.com/u/32095369/" fullword wide
		 $s57= "https://dl.dropbox.com/u/32095369/IRpack.zip" fullword wide
		 $s58= "https://dl.dropbox.com/u/32095369/IR.txt" fullword wide
		 $s59= "https://dl.dropbox.com/u/32095369/TFRpack.zip" fullword wide
		 $s60= "https://dl.dropbox.com/u/32095369/TFR.txt" fullword wide
		 $s61= "https://login.minecraft.net/?user=" fullword wide
		 $s62= "https://twitter.com/KB_Gaming" fullword wide
		 $s63= "http://tempuri.org/DsFavorites.xsd" fullword wide
		 $s64= "http://twitter.com/statuses/user_timeline.xml?screen_name={0}" fullword wide
		 $s65= "http://www.killerbeesgaming.com" fullword wide
		 $s66= "http://www.w3.org/2001/XMLSchema" fullword wide
		 $s67= "ICustomPropertyProviderIm" fullword wide
		 $s68= "IManagedActivationFacto.exe" fullword wide
		 $s69= "indexToolStripMenuItem.Image" fullword wide
		 $s70= "IntroducedMethodEnumerat.exe" fullword wide
		 $s71= "KillerBeesGaming Client2.exe" fullword wide
		 $s72= "KillerBeesGaming_Client.Bees" fullword wide
		 $s73= "KillerBeesGaming Client.exe" fullword wide
		 $s74= "KillerBeesGaming Client.exe" fullword wide
		 $s75= "KillerBeesGaming_Client.Resources" fullword wide
		 $s76= "LargeIconsToolStripMenuItem" fullword wide
		 $s77= "lblDataUltimaMensagemLida" fullword wide
		 $s78= "ListViewToolStripButton.Image" fullword wide
		 $s79= "LocalidadesToolStripMenuItem" fullword wide
		 $s80= "Login.Properties.Resources" fullword wide
		 $s81= "Manina.Windows.Forms.Properties.Resources" fullword wide
		 $s82= "MensagensToolStripMenuItem" fullword wide
		 $s83= "Microsoft.Container.DataSpaces" fullword wide
		 $s84= "Microsoft.Container.EncryptionTransform" fullword wide
		 $s85= "mining.industrial-craft.net" fullword wide
		 $s86= "MiniNoteToolStripMenuItem" fullword wide
		 $s87= "modsrei_minimapkeyconfig.txt" fullword wide
		 $s88= "Multas.fechaExpedicionMulta" fullword wide
		 $s89= "Multas.fechaLiquidacionMulta" fullword wide
		 $s90= "NavigationLib.Properties.Resources" fullword wide
		 $s91= "NewLevelToolStripMenuItem" fullword wide
		 $s92= "newToolStripMenuItem.Image" fullword wide
		 $s93= "NodeGraphControl.Properties.Resources" fullword wide
		 $s94= "OpenCC_GUI.Languages.Language_" fullword wide
		 $s95= "openFileDialog1.TrayLocation" fullword wide
		 $s96= "OpenLevelDesignerToolStripMenuItem" fullword wide
		 $s97= "OpenLevelToolStripMenuItem" fullword wide
		 $s98= "openToolStripMenuItem.Image" fullword wide
		 $s99= "//parametros//UltimaMsgId" fullword wide
		 $s100= "pasteToolStripMenuItem.Image" fullword wide
		 $s101= "PrintPreviewToolStripMenuItem" fullword wide
		 $s102= "printPreviewToolStripMenuItem.Image" fullword wide
		 $s103= "printToolStripMenuItem.Image" fullword wide
		 $s104= "PropertiesToolStripMenuItem" fullword wide
		 $s105= "QuickOpenToolStripMenuItem" fullword wide
		 $s106= "_qwertyuiopasdfghjklzxcvbnm" fullword wide
		 $s107= "qwertyuiopasdfghjklzxcvbnm" fullword wide
		 $s108= "redoToolStripMenuItem.Image" fullword wide
		 $s109= "RestricaoUsuariosPorNomeString" fullword wide
		 $s110= "SaveLevelToolStripMenuItem" fullword wide
		 $s111= "saveToolStripMenuItem.Image" fullword wide
		 $s112= "searchToolStripMenuItem.Image" fullword wide
		 $s113= "SelectAllToolStripMenuItem" fullword wide
		 $s114= "SettingsPanelToolStripMenuItem" fullword wide
		 $s115= "ShowEmptyBlocksToolStripMenuItem" fullword wide
		 $s116= "ShowFramerateToolStripMenuItem" fullword wide
		 $s117= "SmallIconsToolStripMenuItem" fullword wide
		 $s118= "SparselyPopulatedArrayFragme.exe" fullword wide
		 $s119= "Srzekpufgqcvcawqz.Gkgebzotmnzstswk.dll" fullword wide
		 $s120= "Srzekpufgqcvcawqz.Properties.Resources" fullword wide
		 $s121= "StartCustomSessionToolStripMenuItem" fullword wide
		 $s122= "StartNewSessionToolStripMenuItem" fullword wide
		 $s123= "StartTo100CToolStripMenuItem" fullword wide
		 $s124= "StartTo65CToolStripMenuItem" fullword wide
		 $s125= "StartTo80CToolStripMenuItem" fullword wide
		 $s126= "StartTo95CToolStripMenuItem" fullword wide
		 $s127= "StaticArrayInitTypeSize.exe" fullword wide
		 $s128= "StaticIndexRangePartitionForILi" fullword wide
		 $s129= "StatusBarToolStripMenuItem" fullword wide
		 $s130= "STOREASSEMBLYFILESTATUSFLA.exe" fullword wide
		 $s131= "StrongEncryptionDataSpace" fullword wide
		 $s132= "StrongEncryptionTransform" fullword wide
		 $s133= "TripleDESCryptoServiceProvid" fullword wide
		 $s134= "undoToolStripMenuItem.Image" fullword wide
		 $s135= "urn:schemas-microsoft-com:xml-diffgram-v1" fullword wide
		 $s136= "UserCoreShellToolStripMenuItem" fullword wide
		 $s137= "UserSystemBrowserToolStripMenuItem" fullword wide
		 $s138= "VisualizarToolStripMenuItem" fullword wide
		 $s139= "WindowsFormsApp1.Properties.Resources" fullword wide
		 $s140= "WinForms_RecursiveFormCreate" fullword wide
		 $s141= "WinForms_SeeInnerException" fullword wide
		 $a1= "$STATIC$DisplayPictureBox_MouseMove$20211C12817D$canvasX$Init" fullword ascii
		 $a2= "$STATIC$HighScoresForm_Load$20211C1280A9$customLevelsTab$Init" fullword ascii
		 $a3= "$STATIC$mGame_EarnedHighScore$203181180A41234$entryForm$Init" fullword ascii
		 $a4= "$STATIC$PreviewPictureBox_MouseClick$20211C12817D$clickObject" fullword ascii
		 $a5= "$STATIC$PreviewPictureBox_MouseClick$20211C12817D$xScale$Init" fullword ascii
		 $a6= "$STATIC$PreviewPictureBox_MouseClick$20211C12817D$yScale$Init" fullword ascii
		 $a7= "http://cacerts.digicert.com/DigiCertEVCodeSigningCA-SHA2.crt0" fullword ascii
		 $a8= "Manina.Windows.Forms.FileSystemLabel+FileSystemLabelDesigner" fullword ascii

		 $hex1= {2461313d2022245354}
		 $hex2= {2461323d2022245354}
		 $hex3= {2461333d2022245354}
		 $hex4= {2461343d2022245354}
		 $hex5= {2461353d2022245354}
		 $hex6= {2461363d2022245354}
		 $hex7= {2461373d2022687474}
		 $hex8= {2461383d20224d616e}
		 $hex9= {24733130303d202270}
		 $hex10= {24733130313d202250}
		 $hex11= {24733130323d202270}
		 $hex12= {24733130333d202270}
		 $hex13= {24733130343d202250}
		 $hex14= {24733130353d202251}
		 $hex15= {24733130363d20225f}
		 $hex16= {24733130373d202271}
		 $hex17= {24733130383d202272}
		 $hex18= {24733130393d202252}
		 $hex19= {247331303d20226169}
		 $hex20= {24733131303d202253}
		 $hex21= {24733131313d202273}
		 $hex22= {24733131323d202273}
		 $hex23= {24733131333d202253}
		 $hex24= {24733131343d202253}
		 $hex25= {24733131353d202253}
		 $hex26= {24733131363d202253}
		 $hex27= {24733131373d202253}
		 $hex28= {24733131383d202253}
		 $hex29= {24733131393d202253}
		 $hex30= {247331313d20224170}
		 $hex31= {24733132303d202253}
		 $hex32= {24733132313d202253}
		 $hex33= {24733132323d202253}
		 $hex34= {24733132333d202253}
		 $hex35= {24733132343d202253}
		 $hex36= {24733132353d202253}
		 $hex37= {24733132363d202253}
		 $hex38= {24733132373d202253}
		 $hex39= {24733132383d202253}
		 $hex40= {24733132393d202253}
		 $hex41= {247331323d20224173}
		 $hex42= {24733133303d202253}
		 $hex43= {24733133313d202253}
		 $hex44= {24733133323d202253}
		 $hex45= {24733133333d202254}
		 $hex46= {24733133343d202275}
		 $hex47= {24733133353d202275}
		 $hex48= {24733133363d202255}
		 $hex49= {24733133373d202255}
		 $hex50= {24733133383d202256}
		 $hex51= {24733133393d202257}
		 $hex52= {247331333d20224261}
		 $hex53= {24733134303d202257}
		 $hex54= {24733134313d202257}
		 $hex55= {247331343d20226274}
		 $hex56= {247331353d20226274}
		 $hex57= {247331363d20226274}
		 $hex58= {247331373d20226274}
		 $hex59= {247331383d20224361}
		 $hex60= {247331393d2022433a}
		 $hex61= {2473313d2022343137}
		 $hex62= {247332303d2022436f}
		 $hex63= {247332313d2022436f}
		 $hex64= {247332323d2022436f}
		 $hex65= {247332333d2022436f}
		 $hex66= {247332343d2022436f}
		 $hex67= {247332353d2022436f}
		 $hex68= {247332363d2022636f}
		 $hex69= {247332373d2022436f}
		 $hex70= {247332383d2022436f}
		 $hex71= {247332393d2022436f}
		 $hex72= {2473323d2022343338}
		 $hex73= {247333303d2022436f}
		 $hex74= {247333313d2022636f}
		 $hex75= {247333323d2022433a}
		 $hex76= {247333333d20226375}
		 $hex77= {247333343d20224461}
		 $hex78= {247333353d20224461}
		 $hex79= {247333363d20224469}
		 $hex80= {247333373d2022456d}
		 $hex81= {247333383d2022456e}
		 $hex82= {247333393d20224578}
		 $hex83= {2473333d2022343936}
		 $hex84= {247334303d20224578}
		 $hex85= {247334313d20227b46}
		 $hex86= {247334323d2022466f}
		 $hex87= {247334333d2022466f}
		 $hex88= {247334343d20224763}
		 $hex89= {247334353d20224763}
		 $hex90= {247334363d2022473a}
		 $hex91= {247334373d2022473a}
		 $hex92= {247334383d2022473a}
		 $hex93= {247334393d2022473a}
		 $hex94= {2473343d2022353236}
		 $hex95= {247335303d2022473a}
		 $hex96= {247335313d2022473a}
		 $hex97= {247335323d20224869}
		 $hex98= {247335333d20226874}
		 $hex99= {247335343d20226874}
		 $hex100= {247335353d20226874}
		 $hex101= {247335363d20226874}
		 $hex102= {247335373d20226874}
		 $hex103= {247335383d20226874}
		 $hex104= {247335393d20226874}
		 $hex105= {2473353d2022353337}
		 $hex106= {247336303d20226874}
		 $hex107= {247336313d20226874}
		 $hex108= {247336323d20226874}
		 $hex109= {247336333d20226874}
		 $hex110= {247336343d20226874}
		 $hex111= {247336353d20226874}
		 $hex112= {247336363d20226874}
		 $hex113= {247336373d20224943}
		 $hex114= {247336383d2022494d}
		 $hex115= {247336393d2022696e}
		 $hex116= {2473363d2022353437}
		 $hex117= {247337303d2022496e}
		 $hex118= {247337313d20224b69}
		 $hex119= {247337323d20224b69}
		 $hex120= {247337333d20224b69}
		 $hex121= {247337343d20224b69}
		 $hex122= {247337353d20224b69}
		 $hex123= {247337363d20224c61}
		 $hex124= {247337373d20226c62}
		 $hex125= {247337383d20224c69}
		 $hex126= {247337393d20224c6f}
		 $hex127= {2473373d202241626f}
		 $hex128= {247338303d20224c6f}
		 $hex129= {247338313d20224d61}
		 $hex130= {247338323d20224d65}
		 $hex131= {247338333d20224d69}
		 $hex132= {247338343d20224d69}
		 $hex133= {247338353d20226d69}
		 $hex134= {247338363d20224d69}
		 $hex135= {247338373d20226d6f}
		 $hex136= {247338383d20224d75}
		 $hex137= {247338393d20224d75}
		 $hex138= {2473383d20222f2f61}
		 $hex139= {247339303d20224e61}
		 $hex140= {247339313d20224e65}
		 $hex141= {247339323d20226e65}
		 $hex142= {247339333d20224e6f}
		 $hex143= {247339343d20224f70}
		 $hex144= {247339353d20226f70}
		 $hex145= {247339363d20224f70}
		 $hex146= {247339373d20224f70}
		 $hex147= {247339383d20226f70}
		 $hex148= {247339393d20222f2f}
		 $hex149= {2473393d2022416765}

	condition:
		99 of them
}
