
/*
   YARA Rule Set
   Author: resteex
   Identifier: EquationGroup_Fanny 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_EquationGroup_Fanny {
	meta: 
		 description= "EquationGroup_Fanny Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-25-55" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0a209ac0de4ac033f31d6ba9191a8f7a"

	strings:

	
 		 $s1= "CcnFormSyncExFBC" fullword wide
		 $s2= "system32win32k.sys" fullword wide
		 $a1= "0x%02hx%02hx%02hx%02hx%02hx%02hx" fullword ascii
		 $a2= "4%5F5J5N5R5V5Z5^5b5f5j5n5r5v5z5~5" fullword ascii
		 $a3= "6(64686@6D6L6P66`6l6p6|6" fullword ascii
		 $a4= "c:windowssystem32kernel32.dll" fullword ascii
		 $a5= "GetSidIdentifierAuthority" fullword ascii
		 $a6= "InitializeSecurityDescriptor" fullword ascii
		 $a7= "khomIYNEoYOOUSRuRZSNQ]HUSR}" fullword ascii
		 $a8= "MmBuildMdlForNonPagedPool" fullword ascii
		 $a9= "MmMapLockedPagesSpecifyCache" fullword ascii
		 $a10= "PsDereferencePrimaryToken" fullword ascii
		 $a11= "RtlImageDirectoryEntryToData" fullword ascii
		 $a12= "SetSecurityDescriptorDacl" fullword ascii
		 $a13= "SetSecurityDescriptorGroup" fullword ascii
		 $a14= "SetSecurityDescriptorOwner" fullword ascii
		 $a15= "SetUnhandledExceptionFilter" fullword ascii
		 $a16= "SoftwareMicrosoftMSNetMng" fullword ascii
		 $a17= "SystemCurrentControlSetServicesPartMgrEnum" fullword ascii
		 $a18= "SystemCurrentControlSetServicesUSBSTOREnum" fullword ascii

		 $hex1= {246131303d20225073}
		 $hex2= {246131313d20225274}
		 $hex3= {246131323d20225365}
		 $hex4= {246131333d20225365}
		 $hex5= {246131343d20225365}
		 $hex6= {246131353d20225365}
		 $hex7= {246131363d2022536f}
		 $hex8= {246131373d20225379}
		 $hex9= {246131383d20225379}
		 $hex10= {2461313d2022307825}
		 $hex11= {2461323d2022342535}
		 $hex12= {2461333d2022362836}
		 $hex13= {2461343d2022633a77}
		 $hex14= {2461353d2022476574}
		 $hex15= {2461363d2022496e69}
		 $hex16= {2461373d20226b686f}
		 $hex17= {2461383d20224d6d42}
		 $hex18= {2461393d20224d6d4d}
		 $hex19= {2473313d202243636e}
		 $hex20= {2473323d2022737973}

	condition:
		2 of them
}
