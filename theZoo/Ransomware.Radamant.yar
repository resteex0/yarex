
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Radamant 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Radamant {
	meta: 
		 description= "Ransomware_Radamant Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-27-59" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "6152709e741c4d5a5d793d35817b4c3d"
		 hash2= "892626ba70f22a5c7593116b8d2defcf"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "LegalTrademarks" fullword wide
		 $s3= "Microsoft Corporation" fullword wide
		 $s4= "OriginalFilename" fullword wide
		 $s5= "VS_VERSION_INFO" fullword wide
		 $a1= "_AllocateAndInitializeSid@44" fullword ascii
		 $a2= "__gnu_exception_handler@4" fullword ascii
		 $a3= "__imp__AllocateAndInitializeSid@44" fullword ascii
		 $a4= "__imp__CryptAcquireContextA@20" fullword ascii
		 $a5= "__imp__DnsRecordListFree@8" fullword ascii
		 $a6= "__imp__GetComputerNameA@8" fullword ascii
		 $a7= "__imp__GetCurrentHwProfileA@4" fullword ascii
		 $a8= "__imp__GetCurrentProcess@0" fullword ascii
		 $a9= "__imp__GetLogicalDrives@0" fullword ascii
		 $a10= "__imp__GetModuleFileNameA@12" fullword ascii
		 $a11= "__imp__GetModuleHandleA@4" fullword ascii
		 $a12= "__imp__GetWindowsDirectoryA@8" fullword ascii
		 $a13= "__imp__RegCreateKeyExA@36" fullword ascii
		 $a14= "__imp__RegQueryValueExA@24" fullword ascii
		 $a15= "__imp__SetFileAttributesA@8" fullword ascii
		 $a16= "__imp__SetUnhandledExceptionFilter@4" fullword ascii
		 $a17= "__imp__SHGetFolderPathA@20" fullword ascii
		 $a18= "__major_subsystem_version__" fullword ascii
		 $a19= "__minor_subsystem_version__" fullword ascii
		 $a20= "__pei386_runtime_relocator" fullword ascii
		 $a21= "___RUNTIME_PSEUDO_RELOC_LIST__" fullword ascii
		 $a22= "__RUNTIME_PSEUDO_RELOC_LIST__" fullword ascii
		 $a23= "___RUNTIME_PSEUDO_RELOC_LIST_END__" fullword ascii
		 $a24= "__RUNTIME_PSEUDO_RELOC_LIST_END__" fullword ascii
		 $a25= "_SetUnhandledExceptionFilter@4" fullword ascii
		 $a26= "__size_of_stack_reserve__" fullword ascii
		 $a27= "___w32_sharedptr_default_unexpected" fullword ascii
		 $a28= "___w32_sharedptr_initialize" fullword ascii
		 $a29= "___w32_sharedptr_terminate" fullword ascii
		 $a30= "___w32_sharedptr_unexpected" fullword ascii
		 $a31= "__Z14decryptFileAESPcS_Phm" fullword ascii
		 $a32= "__Z14encryptFileAESPcS_Phm" fullword ascii
		 $a33= "__Z15generateRSAkeysPhPmS_S0_" fullword ascii
		 $a34= "__Z16SendDataToServerPcS_S_mS_" fullword ascii
		 $a35= "__Z17FindAndCryprFilesPhm" fullword ascii
		 $a36= "__Z18CreateFileOnDskTopPcS_" fullword ascii
		 $a37= "__Z19FindAndDecryprFilesPhm" fullword ascii
		 $a38= "__Z19IsUserElevatedAdminv" fullword ascii
		 $a39= "__Z20GetEncryptedFileSizePi" fullword ascii
		 $a40= "__Z26try_to_create_file_on_diskPc" fullword ascii
		 $a41= "__ZN3MD510MD5_memcpyEPhS0_j" fullword ascii
		 $a42= "__ZN3MD510MD5_memsetEPhij" fullword ascii
		 $a43= "__ZN3MD512MD5TransformEPmPh" fullword ascii
		 $a44= "__ZN3MD57MD5InitEP7MD5_CTX" fullword ascii
		 $a45= "__ZN3MD58MD5FinalEPhP7MD5_CTX" fullword ascii
		 $a46= "__ZN3MD59MD5UpdateEP7MD5_CTXPhj" fullword ascii
		 $a47= "_ZZ11aes_set_keyE7ft_init" fullword ascii
		 $a48= "_ZZ11aes_set_keyE7kt_init" fullword ascii

		 $hex1= {246131303d20225f5f}
		 $hex2= {246131313d20225f5f}
		 $hex3= {246131323d20225f5f}
		 $hex4= {246131333d20225f5f}
		 $hex5= {246131343d20225f5f}
		 $hex6= {246131353d20225f5f}
		 $hex7= {246131363d20225f5f}
		 $hex8= {246131373d20225f5f}
		 $hex9= {246131383d20225f5f}
		 $hex10= {246131393d20225f5f}
		 $hex11= {2461313d20225f416c}
		 $hex12= {246132303d20225f5f}
		 $hex13= {246132313d20225f5f}
		 $hex14= {246132323d20225f5f}
		 $hex15= {246132333d20225f5f}
		 $hex16= {246132343d20225f5f}
		 $hex17= {246132353d20225f53}
		 $hex18= {246132363d20225f5f}
		 $hex19= {246132373d20225f5f}
		 $hex20= {246132383d20225f5f}
		 $hex21= {246132393d20225f5f}
		 $hex22= {2461323d20225f5f67}
		 $hex23= {246133303d20225f5f}
		 $hex24= {246133313d20225f5f}
		 $hex25= {246133323d20225f5f}
		 $hex26= {246133333d20225f5f}
		 $hex27= {246133343d20225f5f}
		 $hex28= {246133353d20225f5f}
		 $hex29= {246133363d20225f5f}
		 $hex30= {246133373d20225f5f}
		 $hex31= {246133383d20225f5f}
		 $hex32= {246133393d20225f5f}
		 $hex33= {2461333d20225f5f69}
		 $hex34= {246134303d20225f5f}
		 $hex35= {246134313d20225f5f}
		 $hex36= {246134323d20225f5f}
		 $hex37= {246134333d20225f5f}
		 $hex38= {246134343d20225f5f}
		 $hex39= {246134353d20225f5f}
		 $hex40= {246134363d20225f5f}
		 $hex41= {246134373d20225f5a}
		 $hex42= {246134383d20225f5a}
		 $hex43= {2461343d20225f5f69}
		 $hex44= {2461353d20225f5f69}
		 $hex45= {2461363d20225f5f69}
		 $hex46= {2461373d20225f5f69}
		 $hex47= {2461383d20225f5f69}
		 $hex48= {2461393d20225f5f69}
		 $hex49= {2473313d202246696c}
		 $hex50= {2473323d20224c6567}
		 $hex51= {2473333d20224d6963}
		 $hex52= {2473343d20224f7269}
		 $hex53= {2473353d202256535f}

	condition:
		6 of them
}
