
/*
   YARA Rule Set
   Author: resteex
   Identifier: FormBook 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_FormBook {
	meta: 
		 description= "FormBook Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_01-09-36" 
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

	
 		 $s1= "43826d1e-e718-42ee-bc55-a1e261c37bfe" fullword wide
		 $s2= "45646974416E64436F6E74696E756548656C70" fullword wide
		 $s3= "49437573746F6D50726F706572747950726F7669646572496D" fullword wide
		 $s4= "496E74657266616365466F7277617264696E67537570706F" fullword wide
		 $s5= "526573747269637465644572726F724F626A65" fullword wide
		 $s6= "537461746963496E64657852616E6765506172746974696F6E466F72494C69" fullword wide
		 $s7= "53757070726573734D65737361676541747472696275" fullword wide
		 $s8= "547269706C6544455343727970746F5365727669636550726F766964" fullword wide
		 $s9= "AssemblyTargetedPatchBandAttribu.exe" fullword wide
		 $s10= ";=;>;?;@;BACADAEAFAGAJIKILIMIPO" fullword wide
		 $s11= "Contacto: toursandtripsSV@tours.com" fullword wide
		 $s12= "ControlVehicular.RegistrarLicencias" fullword wide
		 $s13= "Dataimagespowerupsextraball.png" fullword wide
		 $s14= "{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}N" fullword wide
		 $s15= "Gcxifsdkvaiqxmznvaay.Aucrorbejpjpqs.dll" fullword wide
		 $s16= "Gcxifsdkvaiqxmznvaay.Properties.Resources" fullword wide
		 $s17= "G:VSprojectsFlyingGameFlyingGameSoundsBeep.wav" fullword wide
		 $s18= "G:VSprojectsFlyingGameFlyingGameSoundsBombAway.wav" fullword wide
		 $s19= "G:VSprojectsFlyingGameFlyingGameSoundsBombXplode.wav" fullword wide
		 $s20= "G:VSprojectsFlyingGameFlyingGameSoundsEnemyXplode.wav" fullword wide
		 $s21= "G:VSprojectsFlyingGameFlyingGameSoundsfire.wav" fullword wide
		 $s22= "G:VSprojectsFlyingGameFlyingGameSoundstada.wav" fullword wide
		 $s23= "http://api.twitter.com/1/direct_messages.xml?since_id={0}" fullword wide
		 $s24= "http://dl.dropbox.com/u/95912365/DynamicLink.txt" fullword wide
		 $s25= "http://dl.dropbox.com/u/95912365/Update.txt" fullword wide
		 $s26= "https://dl.dropbox.com/u/32095369/IRpack.zip" fullword wide
		 $s27= "https://dl.dropbox.com/u/32095369/IR.txt" fullword wide
		 $s28= "https://dl.dropbox.com/u/32095369/TFRpack.zip" fullword wide
		 $s29= "https://dl.dropbox.com/u/32095369/TFR.txt" fullword wide
		 $s30= "http://twitter.com/statuses/user_timeline.xml?screen_name={0}" fullword wide
		 $s31= "Manina.Windows.Forms.Properties.Resources" fullword wide
		 $s32= "Microsoft.Container.EncryptionTransform" fullword wide
		 $s33= "NodeGraphControl.Properties.Resources" fullword wide
		 $s34= "printPreviewToolStripMenuItem.Image" fullword wide
		 $s35= "Srzekpufgqcvcawqz.Gkgebzotmnzstswk.dll" fullword wide
		 $s36= "Srzekpufgqcvcawqz.Properties.Resources" fullword wide
		 $s37= "StartCustomSessionToolStripMenuItem" fullword wide
		 $s38= "urn:schemas-microsoft-com:xml-diffgram-v1" fullword wide
		 $s39= "WindowsFormsApp1.Properties.Resources" fullword wide
		 $a1= "49437573746F6D50726F706572747950726F7669646572496D" fullword ascii
		 $a2= "537461746963496E64657852616E6765506172746974696F6E466F72494C69" fullword ascii
		 $a3= "547269706C6544455343727970746F5365727669636550726F766964" fullword ascii
		 $a4= ";=;>;?;@;BACADAEAFAGAJIKILIMIPO" fullword ascii
		 $a5= "G:VSprojectsFlyingGameFlyingGameSoundsBeep.wav" fullword ascii
		 $a6= "G:VSprojectsFlyingGameFlyingGameSoundsBombAway.wav" fullword ascii
		 $a7= "G:VSprojectsFlyingGameFlyingGameSoundsBombXplode.wav" fullword ascii
		 $a8= "G:VSprojectsFlyingGameFlyingGameSoundsEnemyXplode.wav" fullword ascii
		 $a9= "G:VSprojectsFlyingGameFlyingGameSoundsfire.wav" fullword ascii
		 $a10= "G:VSprojectsFlyingGameFlyingGameSoundstada.wav" fullword ascii
		 $a11= "http://api.twitter.com/1/direct_messages.xml?since_id={0}" fullword ascii
		 $a12= "http://twitter.com/statuses/user_timeline.xml?screen_name={0}" fullword ascii

		 $hex1= {246131303d2022473a}
		 $hex2= {246131313d20226874}
		 $hex3= {246131323d20226874}
		 $hex4= {2461313d2022343934}
		 $hex5= {2461323d2022353337}
		 $hex6= {2461333d2022353437}
		 $hex7= {2461343d20223b3d3b}
		 $hex8= {2461353d2022473a56}
		 $hex9= {2461363d2022473a56}
		 $hex10= {2461373d2022473a56}
		 $hex11= {2461383d2022473a56}
		 $hex12= {2461393d2022473a56}
		 $hex13= {247331303d20223b3d}
		 $hex14= {247331313d2022436f}
		 $hex15= {247331323d2022436f}
		 $hex16= {247331333d20224461}
		 $hex17= {247331343d20227b46}
		 $hex18= {247331353d20224763}
		 $hex19= {247331363d20224763}
		 $hex20= {247331373d2022473a}
		 $hex21= {247331383d2022473a}
		 $hex22= {247331393d2022473a}
		 $hex23= {2473313d2022343338}
		 $hex24= {247332303d2022473a}
		 $hex25= {247332313d2022473a}
		 $hex26= {247332323d2022473a}
		 $hex27= {247332333d20226874}
		 $hex28= {247332343d20226874}
		 $hex29= {247332353d20226874}
		 $hex30= {247332363d20226874}
		 $hex31= {247332373d20226874}
		 $hex32= {247332383d20226874}
		 $hex33= {247332393d20226874}
		 $hex34= {2473323d2022343536}
		 $hex35= {247333303d20226874}
		 $hex36= {247333313d20224d61}
		 $hex37= {247333323d20224d69}
		 $hex38= {247333333d20224e6f}
		 $hex39= {247333343d20227072}
		 $hex40= {247333353d20225372}
		 $hex41= {247333363d20225372}
		 $hex42= {247333373d20225374}
		 $hex43= {247333383d20227572}
		 $hex44= {247333393d20225769}
		 $hex45= {2473333d2022343934}
		 $hex46= {2473343d2022343936}
		 $hex47= {2473353d2022353236}
		 $hex48= {2473363d2022353337}
		 $hex49= {2473373d2022353337}
		 $hex50= {2473383d2022353437}
		 $hex51= {2473393d2022417373}

	condition:
		6 of them
}
