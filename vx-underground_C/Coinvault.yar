
/*
   YARA Rule Set
   Author: resteex
   Identifier: Coinvault 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Coinvault {
	meta: 
		 description= "Coinvault Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_00-28-29" 
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
		 $s3= "/head>" fullword wide
		 $s4= "HKEY_CURRENT_USERSoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s5= "http://www.nirsoft.net/utils/nk2edit_license.html" fullword wide
		 $s6= "http://www.nirsoft.net/utils/outlook_nk2_edit.html" fullword wide
		 $s7= "NKMailboxOptions.AllowSelectProfile" fullword wide
		 $s8= "SOFTWAREMicrosoftOffice14.0Outlook" fullword wide
		 $s9= "SOFTWAREMicrosoftOffice15.0Outlook" fullword wide
		 $s10= "SOFTWAREMicrosoftOffice16.0Outlook" fullword wide
		 $s11= "SOFTWAREMicrosoftOffice%d.0Outlook" fullword wide
		 $s12= "SOFTWAREMicrosoftOffice%d.0OutlookAutoNameCheck" fullword wide
		 $s13= "SOFTWAREMicrosoftWindowsCurrentVersionApp PathsOUTLOOK.EXE" fullword wide
		 $s14= "SoftwareMicrosoftWindowsCurrentVersionExplorerShell Folders" fullword wide
		 $s15= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $a1= "HKEY_CURRENT_USERSoftwareMicrosoftWindowsCurrentVersionRun" fullword ascii
		 $a2= "http://www.nirsoft.net/utils/outlook_nk2_edit.html" fullword ascii
		 $a3= "SOFTWAREMicrosoftOffice%d.0OutlookAutoNameCheck" fullword ascii
		 $a4= "SOFTWAREMicrosoftWindowsCurrentVersionApp PathsOUTLOOK.EXE" fullword ascii
		 $a5= "SoftwareMicrosoftWindowsCurrentVersionExplorerShell Folders" fullword ascii

		 $hex1= {2461313d2022484b45}
		 $hex2= {2461323d2022687474}
		 $hex3= {2461333d2022534f46}
		 $hex4= {2461343d2022534f46}
		 $hex5= {2461353d2022536f66}
		 $hex6= {247331303d2022534f}
		 $hex7= {247331313d2022534f}
		 $hex8= {247331323d2022534f}
		 $hex9= {247331333d2022534f}
		 $hex10= {247331343d2022536f}
		 $hex11= {247331353d2022536f}
		 $hex12= {2473313d20222e2534}
		 $hex13= {2473323d2022393631}
		 $hex14= {2473333d20222f6865}
		 $hex15= {2473343d2022484b45}
		 $hex16= {2473353d2022687474}
		 $hex17= {2473363d2022687474}
		 $hex18= {2473373d20224e4b4d}
		 $hex19= {2473383d2022534f46}
		 $hex20= {2473393d2022534f46}

	condition:
		2 of them
}
