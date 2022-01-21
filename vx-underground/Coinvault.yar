
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Coinvault 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Coinvault {
	meta: 
		 description= "vx_underground2_Coinvault Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-54-14" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0154e37a91e3c6b00d1c7186042ca2fd"
		 hash2= "0bf70d0622c92c445bc291d1b270c579"
		 hash3= "151b7c75a5d52483fe1f715f2a7d14bd"
		 hash4= "30f00592cddf35ce71f14f6c79f6d657"
		 hash5= "33a48664fae995fe3d2cbe9e3f29933f"
		 hash6= "3a3182809f8506c8b56d4a1a53903515"
		 hash7= "3bf51d7a4af710860d5c1b95fea601d7"
		 hash8= "404dc2494f9343bc17dedf4c34ce54e6"
		 hash9= "4f980da754606b67e4d56c1dc5d8bd53"
		 hash10= "579de8200a3c342a1c82bfaff35f9265"
		 hash11= "58f7418abd6d15dc3ae78fafabd8a58b"
		 hash12= "5b3a7bd4785c7ec5c9e2e8a4195283c5"
		 hash13= "67314850fdec88bf5d9a988949a58ebe"
		 hash14= "70b83a5696dd5719542ff6938f199339"
		 hash15= "799e6359c53a1d6ed205c6bfa734ca71"
		 hash16= "8f6ef3e250d6576f0a40971f081c83da"
		 hash17= "a1e2846c596b23b2db6fac258a290d6c"
		 hash18= "b34dae88b8fae8dfefdcf41a88106cdc"
		 hash19= "b4732ac2be70eb25eb5a937f03607a61"
		 hash20= "b7590f676ceaf3acc0134cccfd9af32a"
		 hash21= "c94e34e0d687c82a0e7e3588ef647156"
		 hash22= "cdc962a64fe8087090cf084e60ea75d5"
		 hash23= "e6691b3f782ba76ba8bef81283d81578"

	strings:

	
 		 $s1= ".%4.4d%2.2d%2.2d%2.2d%2.2d%2.2d.NK2Edit.bak" fullword wide
		 $s2= "9617c104-8052-4ded-ab6a-094f91c693d7" fullword wide
		 $s3= "AppdataMicrosoftWindows" fullword wide
		 $s4= "application/x-www-form-urlencoded" fullword wide
		 $s5= "ecvOubvXOQpInufpKyTERRgbh" fullword wide
		 $s6= "eeXctDADzyTKWiOPYjHJkpCvX" fullword wide
		 $s7= "FindReplace.FieldComboBoxName" fullword wide
		 $s8= "FindReplace.FieldDisplayName" fullword wide
		 $s9= "FindReplace.FieldSearchString" fullword wide
		 $s10= "FindReplace.MatchWholeString" fullword wide
		 $s11= "GetReceiveFolder Succeeded" fullword wide
		 $s12= "/head>" fullword wide
		 $s13= "HKEY_CURRENT_USERSoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s14= "http://clredirect.ddns.net/" fullword wide
		 $s15= "http://clredirect.no-ip.net/" fullword wide
		 $s16= "http://mailupl.no-ip.net/" fullword wide
		 $s17= "http://www.nirsoft.net/utils/nk2edit_license.html" fullword wide
		 $s18= "http://www.nirsoft.net/utils/outlook_nk2_edit.html" fullword wide
		 $s19= "iAaWDfFxlEosGOxknWYqYVGAI" fullword wide
		 $s20= "IPM.Configuration.Autocomplete" fullword wide
		 $s21= "jdBlcRwVmafosttMWXIoUtlBG" fullword wide
		 $s22= "Locker.Properties.Resources" fullword wide
		 $s23= "LSWHMmgFhxTsbWKOekntQskAd" fullword wide
		 $s24= "MailSpreader.Properties.Resources" fullword wide
		 $s25= "MicrosoftOutlookRoamCache" fullword wide
		 $s26= "NK2Editshellopencommand" fullword wide
		 $s27= "NKMailboxOptions.AllowSelectProfile" fullword wide
		 $s28= "NKMailboxOptions.MaxEmails" fullword wide
		 $s29= "NKMailboxOptions.NumOfDays" fullword wide
		 $s30= "NKMailboxOptions.ReceivedMessages" fullword wide
		 $s31= "NKMailboxOptions.SentMessages" fullword wide
		 $s32= "rmcXgfjoglHfyaTLgZFyJNKvx" fullword wide
		 $s33= "SkipCommandLineNoProfiles" fullword wide
		 $s34= "SoftwareMicrosoftOffice" fullword wide
		 $s35= "SOFTWAREMicrosoftOffice14.0Outlook" fullword wide
		 $s36= "SOFTWAREMicrosoftOffice15.0Outlook" fullword wide
		 $s37= "SOFTWAREMicrosoftOffice16.0Outlook" fullword wide
		 $s38= "SOFTWAREMicrosoftOffice%d.0Outlook" fullword wide
		 $s39= "SOFTWAREMicrosoftOffice%d.0OutlookAutoNameCheck" fullword wide
		 $s40= "SOFTWAREMicrosoftWindowsCurrentVersionApp PathsOUTLOOK.EXE" fullword wide
		 $s41= "SoftwareMicrosoftWindowsCurrentVersionExplorerShell Folders" fullword wide
		 $s42= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s43= "UiNWzmqEUKyXPOjMPHpUNlLXZ" fullword wide
		 $s44= "ULgYZAWFPBOlfnlazpkdWBXEU" fullword wide
		 $s45= "UseAddressBookDefaultProfile" fullword wide
		 $s46= "VOLugpcBBEttmofPfXoLwuZVv" fullword wide
		 $s47= "wBufZPHNgpyCCnZXOZPkkjWeJ" fullword wide
		 $s48= "yOxABQQTpXdGkBBQzzuzIvQlm" fullword wide
		 $a1= "\\192.168.0.10c$ProjectsVS2005NK2EditReleaseNK2Edit.pdb" fullword ascii
		 $a2= "kAdNSWHBmgFixTs`WKOokntSskAmLSWIMmgBhxTpbWKOeanuQskAdJS&H'maF" fullword ascii
		 $a3= "MIiAaVDfFxlDorGOx{nvYqYSG@IhA`WTfoxlEjsEOpkeVIqvVGA@iCaADlGhl" fullword ascii
		 $a4= "TZUiNVzmqEUJyYPOj]PipUNiLYZTiOWjmXEUK|XRObM[I`UalLXSUkNAzgpUU" fullword ascii

		 $hex1= {2461313d2022313932}
		 $hex2= {2461323d20226b4164}
		 $hex3= {2461333d20224d4969}
		 $hex4= {2461343d2022545a55}
		 $hex5= {247331303d20224669}
		 $hex6= {247331313d20224765}
		 $hex7= {247331323d20222f68}
		 $hex8= {247331333d2022484b}
		 $hex9= {247331343d20226874}
		 $hex10= {247331353d20226874}
		 $hex11= {247331363d20226874}
		 $hex12= {247331373d20226874}
		 $hex13= {247331383d20226874}
		 $hex14= {247331393d20226941}
		 $hex15= {2473313d20222e2534}
		 $hex16= {247332303d20224950}
		 $hex17= {247332313d20226a64}
		 $hex18= {247332323d20224c6f}
		 $hex19= {247332333d20224c53}
		 $hex20= {247332343d20224d61}
		 $hex21= {247332353d20224d69}
		 $hex22= {247332363d20224e4b}
		 $hex23= {247332373d20224e4b}
		 $hex24= {247332383d20224e4b}
		 $hex25= {247332393d20224e4b}
		 $hex26= {2473323d2022393631}
		 $hex27= {247333303d20224e4b}
		 $hex28= {247333313d20224e4b}
		 $hex29= {247333323d2022726d}
		 $hex30= {247333333d2022536b}
		 $hex31= {247333343d2022536f}
		 $hex32= {247333353d2022534f}
		 $hex33= {247333363d2022534f}
		 $hex34= {247333373d2022534f}
		 $hex35= {247333383d2022534f}
		 $hex36= {247333393d2022534f}
		 $hex37= {2473333d2022417070}
		 $hex38= {247334303d2022534f}
		 $hex39= {247334313d2022536f}
		 $hex40= {247334323d2022536f}
		 $hex41= {247334333d20225569}
		 $hex42= {247334343d2022554c}
		 $hex43= {247334353d20225573}
		 $hex44= {247334363d2022564f}
		 $hex45= {247334373d20227742}
		 $hex46= {247334383d2022794f}
		 $hex47= {2473343d2022617070}
		 $hex48= {2473353d2022656376}
		 $hex49= {2473363d2022656558}
		 $hex50= {2473373d202246696e}
		 $hex51= {2473383d202246696e}
		 $hex52= {2473393d202246696e}

	condition:
		34 of them
}
