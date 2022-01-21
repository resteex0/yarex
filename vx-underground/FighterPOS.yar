
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_FighterPOS 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_FighterPOS {
	meta: 
		 description= "vx_underground2_FighterPOS Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-56-41" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "03e2598ed6749480879524dc50968ce5"
		 hash2= "0476145bab17d348caad05233a21c59c"
		 hash3= "0ca6d769dbce182f84a82835fe44fc5f"
		 hash4= "2917f38b4b310d0d26599af11bd9ca2f"
		 hash5= "29d5b1ffdd4701cad0edeb8773ad6574"
		 hash6= "31c19f04e4a5cd4c1b9cf530349f3f39"
		 hash7= "3590e9305fc0c4a8d7085bd33675d035"
		 hash8= "3e6e1e03fed32ba9d27d46c3981666a8"
		 hash9= "591304b96923aa03979477885f238ad1"
		 hash10= "5c855ee2247b039f01892818021d4003"
		 hash11= "5e58d7ffa3c946a0fb730d82afebc8f9"
		 hash12= "5f2c71138cabb2591558368888a4b0cc"
		 hash13= "677f66594ee0cf2cbf4d7bc87435cbef"
		 hash14= "6cb50f7f2fe6f69ee8613d531e816089"
		 hash15= "78b610809b8d76504845f7c6acbf5872"
		 hash16= "7b9a36f3d28fdcf6cf142a9b2aa0f1d8"
		 hash17= "83f4c831576d2668d61148cbeeaead3b"
		 hash18= "86796f798d87ceaf81779f6d9f0ce9d3"
		 hash19= "9284a3db47bb237dbf39803b9af33ce6"
		 hash20= "9fd89e62451545c7c03ed9bb995885af"
		 hash21= "a3382a248a89277e1f2aea3c4c081581"
		 hash22= "a455a05fad2434843cdfb0afa8c03b82"
		 hash23= "a522a3fbab74e6436121c4da9c65644f"
		 hash24= "ab329da23704672235f8201bb735a512"
		 hash25= "b9cfa4698972c89a2b47369873558cc5"
		 hash26= "ba953dc12994580f1135c1c4ca0aafec"
		 hash27= "c31095e453b165a561fd30f98c384df0"
		 hash28= "c40c0726196ab1d6afab94cf09f2fc7c"
		 hash29= "c4245850a3e45cd63d3510856fe5b34e"
		 hash30= "c8eccca5edd2d030aa64869a2decd445"
		 hash31= "d13e1b8632f391d94c5e4138d5f26371"
		 hash32= "d1d96fa9349126e11bce189f5bc206d1"
		 hash33= "d8b6f7d0d071177825bde72b5467baf8"
		 hash34= "e29d9560b6fcc14290f411eed9f4ff4f"
		 hash35= "e794171d0ebbe14f3e0aaf70c68c4e86"
		 hash36= "e9ef65b60183a7d3a8cdc1151e67d9f6"
		 hash37= "f04a3b785783140186befdccf57c4e3c"
		 hash38= "f11bf1952276c823b173d5aaca5f3c3e"
		 hash39= "f351b06f5681509e723e67f679e4b627"
		 hash40= "f4f7686c4f1e8f1fd76363a269ed9fda"
		 hash41= "ff3ce3c400a57b15684468995406684d"

	strings:

	
 		 $s1= "28C4C820-401A-101B-A3C9-08002B2F49FB" fullword wide
		 $s2= "35408482665400332571209654820175389" fullword wide
		 $s3= "5F25031207055F3401005F2403" fullword wide
		 $s4= "5F25031209145F3401005F2403" fullword wide
		 $s5= "5F25031212175F3401005F2403" fullword wide
		 $s6= "5F25031403105F3401005F2403" fullword wide
		 $s7= "BrFighter@ctclubedeluta.org" fullword wide
		 $s8= "cloud515.unlimitedwebhosting.co.uk" fullword wide
		 $s9= "Content-Type: application/x-www-form-urlencoded" fullword wide
		 $s10= "CSocketPlus.ArrayIndexInUse" fullword wide
		 $s11= "CSocketPlus.CleanSocketArray" fullword wide
		 $s12= "CSocketPlus.DestroySocket" fullword wide
		 $s13= "CSocketPlus.GetBufferLenTCP" fullword wide
		 $s14= "CSocketPlus.GetFreeSocketIndex" fullword wide
		 $s15= "CSocketPlus.GetLocalHostName" fullword wide
		 $s16= "CSocketPlus.GetSocketIndex" fullword wide
		 $s17= "CSocketPlus.ProcessOptions" fullword wide
		 $s18= "CSocketPlus.RecvDataToBuffer" fullword wide
		 $s19= "CSocketPlus.ResolveIfHostname" fullword wide
		 $s20= "CSocketPlus.SendBufferedData" fullword wide
		 $s21= "CSocketPlus.SendBufferedDataUDP" fullword wide
		 $s22= "floki@fromthegods.website" fullword wide
		 $s23= "GUID8DisplayViewsOnSharePointSite" fullword wide
		 $s24= "HARDWAREDESCRIPTIONSystemBIOS" fullword wide
		 $s25= "HARDWAREDESCRIPTIONSystemCentralProcessor0" fullword wide
		 $s26= "http://schemas.microsoft.com/cdo/configuration/" fullword wide
		 $s27= "IMESentenceMode$UnicodeCompression" fullword wide
		 $s28= "MicrosoftInternet Explorer" fullword wide
		 $s29= "modSocketPlus.DestroyWinsockMessageWindow" fullword wide
		 $s30= "modSocketPlus.FinalizeProcesses" fullword wide
		 $s31= "modSocketPlus.InitiateProcesses" fullword wide
		 $s32= "modSocketPlus.RegisterSocket" fullword wide
		 $s33= "MSysAccessStorage_SCRATCH" fullword wide
		 $s34= "MSysNavPaneGroupCategories" fullword wide
		 $s35= "MSysNavPaneGroupToObjects" fullword wide
		 $s36= "Position SelectedObjectID" fullword wide
		 $s37= "provider=microsoft.jet.oledb.4.0;" fullword wide
		 $s38= "sCDE57A55-8B86-11D0-b3C6-00A0C90AEA82" fullword wide
		 $s39= "Scripting.FileSystemObject" fullword wide
		 $s40= "server129.web-hosting.com " fullword wide
		 $s41= "SOFTWAREMicrosoftSecurity Center" fullword wide
		 $s42= "SOFTWAREMicrosoftWindowsCurrentVersionPoliciesSystem" fullword wide
		 $s43= "SOFTWAREMicrosoftWindows NTCurrentVersion" fullword wide
		 $s44= "spanish-dominican republic" fullword wide
		 $s45= "szObject$szReferencedColumn$szReferencedObject" fullword wide
		 $s46= "szObject$szReferencedObject" fullword wide
		 $s47= "/upload/WindowsUpdate.exe" fullword wide
		 $s48= "WinNT://./Administratoren,group" fullword wide

		 $hex1= {247331303d20224353}
		 $hex2= {247331313d20224353}
		 $hex3= {247331323d20224353}
		 $hex4= {247331333d20224353}
		 $hex5= {247331343d20224353}
		 $hex6= {247331353d20224353}
		 $hex7= {247331363d20224353}
		 $hex8= {247331373d20224353}
		 $hex9= {247331383d20224353}
		 $hex10= {247331393d20224353}
		 $hex11= {2473313d2022323843}
		 $hex12= {247332303d20224353}
		 $hex13= {247332313d20224353}
		 $hex14= {247332323d2022666c}
		 $hex15= {247332333d20224755}
		 $hex16= {247332343d20224841}
		 $hex17= {247332353d20224841}
		 $hex18= {247332363d20226874}
		 $hex19= {247332373d2022494d}
		 $hex20= {247332383d20224d69}
		 $hex21= {247332393d20226d6f}
		 $hex22= {2473323d2022333534}
		 $hex23= {247333303d20226d6f}
		 $hex24= {247333313d20226d6f}
		 $hex25= {247333323d20226d6f}
		 $hex26= {247333333d20224d53}
		 $hex27= {247333343d20224d53}
		 $hex28= {247333353d20224d53}
		 $hex29= {247333363d2022506f}
		 $hex30= {247333373d20227072}
		 $hex31= {247333383d20227343}
		 $hex32= {247333393d20225363}
		 $hex33= {2473333d2022354632}
		 $hex34= {247334303d20227365}
		 $hex35= {247334313d2022534f}
		 $hex36= {247334323d2022534f}
		 $hex37= {247334333d2022534f}
		 $hex38= {247334343d20227370}
		 $hex39= {247334353d2022737a}
		 $hex40= {247334363d2022737a}
		 $hex41= {247334373d20222f75}
		 $hex42= {247334383d20225769}
		 $hex43= {2473343d2022354632}
		 $hex44= {2473353d2022354632}
		 $hex45= {2473363d2022354632}
		 $hex46= {2473373d2022427246}
		 $hex47= {2473383d2022636c6f}
		 $hex48= {2473393d2022436f6e}

	condition:
		32 of them
}
