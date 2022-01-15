
/*
   YARA Rule Set
   Author: resteex
   Identifier: Numando 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Numando {
	meta: 
		 description= "Numando Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-15-57" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "16f43b0466a7cedc0d723f616dd557ba"
		 hash2= "1f26da52aea0b3dfe2e829665bd2474f"
		 hash3= "473b4e622b982a92cba1ba8afcda8273"
		 hash4= "511f4e49af5641f2f7eb78c85948272b"
		 hash5= "52253bd91559b9e0e30b0f9e56f41bb6"
		 hash6= "c7d18c4670aebfa94bfbe270f651f424"
		 hash7= "e39592c0b83c040fda60c5bad8cc65c5"
		 hash8= "f3daed1c9a3126de6699e3d93ba11ae4"

	strings:

	
 		 $s1= "+$%&')*34569:;=>GHJKLMNOPQTVWY[_bdehklmnopqs}" fullword wide
		 $s2= "{00B41853-4377-4AD8-AD44-8404E0D331EC}" fullword wide
		 $s3= "{011B9112-EBB1-4A6C-86CB-C2FDC9EA7B0E}" fullword wide
		 $s4= "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}" fullword wide
		 $s5= "**+,-0145689=@ABCDGHIJLNOPQUXYZ[^abcdghijknopstuw" fullword wide
		 $s6= "{04E73476-518E-4B6A-8E10-021A00078847}" fullword wide
		 $s7= "{14D3E42A-A318-4D77-9895-A7EE585EFC3B}" fullword wide
		 $s8= "{1777F761-68AD-4D8A-87BD-30B759FA33DD}" fullword wide
		 $s9= "{18989B1D-99B5-455B-841C-AB7C74E4DDFC}" fullword wide
		 $s10= "{1ABEAF09-435F-47D6-9FEB-0AD05D4EF3EA}" fullword wide
		 $s11= "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}" fullword wide
		 $s12= "{1B3EA5DC-B587-4786-B4EF-BD1DC332AEAE}" fullword wide
		 $s13= "{1C8772BD-6E6F-4C9D-8FF8-B5EA072F86EF}" fullword wide
		 $s14= "{1D844339-3DAE-413E-BC13-62D6A52816B2}" fullword wide
		 $s15= "{2400183A-6185-49FB-A2D8-4A392A602BA3}" fullword wide
		 $s16= "{2B0F765D-C0E9-4171-908E-08A611B84FF6}" fullword wide
		 $s17= "{3214FAB5-9757-4298-BB61-92A9DEAA44FF}" fullword wide
		 $s18= "{33E28130-4E1E-4676-835A-98395C3BC3BB}" fullword wide
		 $s19= "{352481E8-33BE-4251-BA85-6007CAEDCF9D}" fullword wide
		 $s20= "{3EA123B5-6316-452E-9D51-A489E06E2347}" fullword wide
		 $s21= "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}" fullword wide
		 $s22= "{3F40FA9E-26CA-4CA2-93C9-603622349915}" fullword wide
		 $s23= "{4153F732-D670-4E44-8AB7-500F2B576BDA}" fullword wide
		 $s24= "{43826D1E-E718-42EE-BC55-A1E261C37BFE}" fullword wide
		 $s25= "{4C5C32FF-BB9D-43b0-B5B4-2D72E54EAAA4}" fullword wide
		 $s26= "{53C65973-D89D-4EA0-8567-8788C14E0A02}" fullword wide
		 $s27= "{580CB155-841D-4D48-9F59-866A035C2241}" fullword wide
		 $s28= "{5E6C858F-0E22-4760-9AFE-EA3317B67173}" fullword wide
		 $s29= "{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}" fullword wide
		 $s30= "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}" fullword wide
		 $s31= "{64E2917E-AA13-4CA4-BFFE-EA6EDA3AFCB4}" fullword wide
		 $s32= "{6F1AE751-4D8A-4B25-AC0A-C6CB912A9791}" fullword wide
		 $s33= "{7102C98C-EF47-4F04-A227-FE33650BF954}" fullword wide
		 $s34= "{724EF170-A42D-4FEF-9F26-B60E846FBA4F}" fullword wide
		 $s35= ".7z=application/x-7z-compressed" fullword wide
		 $s36= "{816D4DFD-FF7B-4C16-8943-EEB07DF989CB}" fullword wide
		 $s37= "{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}" fullword wide
		 $s38= "{835AC3CE-E36B-4D65-B50F-2863A682ABEE}" fullword wide
		 $s39= "{8983036C-27C0-404B-8F08-102D10DCFD74}" fullword wide
		 $s40= "{8AD10C31-2ADB-4296-A8F7-E4701232C972}" fullword wide
		 $s41= "{8B74A499-37F8-4DEA-B5A0-D72FC501CEFA}" fullword wide
		 $s42= "{905e63b6-c1bf-494e-b29c-65b732d3d21a}" fullword wide
		 $s43= "{9274BD8D-CFD1-41C3-B35E-B13F55A758F4}" fullword wide
		 $s44= "{957A4EC0-E67B-4E86-A383-6AF7270B216A}" fullword wide
		 $s45= "{9E52AB10-F80D-49DF-ACB8-4330F5687855}" fullword wide
		 $s46= "{A1FE0698-609D-400F-BF10-F52238DD6475}" fullword wide
		 $s47= "{A4115719-D62E-491D-AA7C-E74B8BE3B067}" fullword wide
		 $s48= "{A58B51D1-89BF-4D88-939D-B6D0DB2EEB53}" fullword wide
		 $s49= "{A63293E8-664E-48DB-A079-DF759E0509F7}" fullword wide
		 $s50= "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}" fullword wide
		 $s51= ".aab=application/x-authorware-bin" fullword wide
		 $s52= ".aam=application/x-authorware-map" fullword wide
		 $s53= ".aas=application/x-authorware-seg" fullword wide
		 $s54= ".abw=application/x-abiword" fullword wide
		 $s55= ".ace=application/x-ace-compressed" fullword wide
		 $s56= "AcquireCredentialsHandleW" fullword wide
		 $s57= "{AE50C081-EBD2-438A-8655-8A092E34987A}" fullword wide
		 $s58= ".ai=application/postscript" fullword wide
		 $s59= "AI_DETECTED_ACTIVESYNC_VERSION" fullword wide
		 $s60= "AI_DETECTED_ADOBEREADER_VERSION" fullword wide
		 $s61= "AI_DETECTED_COLOR_QUALITY" fullword wide
		 $s62= "AI_DETECTED_DIRECTX_VERSION" fullword wide
		 $s63= "AI_DETECTED_DOTNET_CORE32_VERSION" fullword wide
		 $s64= "AI_DETECTED_DOTNET_CORE64_VERSION" fullword wide
		 $s65= "AI_DETECTED_DOTNET_CORE_VERSION" fullword wide
		 $s66= "AI_DETECTED_DOTNET_VERSION" fullword wide
		 $s67= "AI_DETECTED_INTERNET_CONNECTION" fullword wide
		 $s68= "AI_DETECTED_JDK32_VERSION" fullword wide
		 $s69= "AI_DETECTED_JDK64_VERSION" fullword wide
		 $s70= "AI_DETECTED_JRE32_VERSION" fullword wide
		 $s71= "AI_DETECTED_JRE64_VERSION" fullword wide
		 $s72= "AI_DETECTED_MINOR_UPGRADE" fullword wide
		 $s73= "AI_DETECTED_NOT_VIRTUAL_MACHINE" fullword wide
		 $s74= "AI_DETECTED_OFFICE_ACCESS_VERSION" fullword wide
		 $s75= "AI_DETECTED_OFFICE_EXCEL2003_PIA_VERSION" fullword wide
		 $s76= "AI_DETECTED_OFFICE_EXCEL2007_PIA_VERSION" fullword wide
		 $s77= "AI_DETECTED_OFFICE_EXCEL2010_PIA_VERSION" fullword wide
		 $s78= "AI_DETECTED_OFFICE_EXCEL_PIA_VERSION" fullword wide
		 $s79= "AI_DETECTED_OFFICE_EXCEL_VERSION" fullword wide
		 $s80= "AI_DETECTED_OFFICE_GROOVE_VERSION" fullword wide
		 $s81= "AI_DETECTED_OFFICE_INFOPATH2003_PIA_VERSION" fullword wide
		 $s82= "AI_DETECTED_OFFICE_INFOPATH2007_PIA_VERSION" fullword wide
		 $s83= "AI_DETECTED_OFFICE_INFOPATH2010_PIA_VERSION" fullword wide
		 $s84= "AI_DETECTED_OFFICE_INFOPATH_PIA_VERSION" fullword wide
		 $s85= "AI_DETECTED_OFFICE_INFOPATH_VERSION" fullword wide
		 $s86= "AI_DETECTED_OFFICE_LYNC_VERSION" fullword wide
		 $s87= "AI_DETECTED_OFFICE_MSFORMS2003_PIA_VERSION" fullword wide
		 $s88= "AI_DETECTED_OFFICE_MSFORMS2007_PIA_VERSION" fullword wide
		 $s89= "AI_DETECTED_OFFICE_MSFORMS2010_PIA_VERSION" fullword wide
		 $s90= "AI_DETECTED_OFFICE_MSFORMS_PIA_VERSION" fullword wide
		 $s91= "AI_DETECTED_OFFICE_MSGRAPH2003_PIA_VERSION" fullword wide
		 $s92= "AI_DETECTED_OFFICE_MSGRAPH2007_PIA_VERSION" fullword wide
		 $s93= "AI_DETECTED_OFFICE_MSGRAPH2010_PIA_VERSION" fullword wide
		 $s94= "AI_DETECTED_OFFICE_MSGRAPH_PIA_VERSION" fullword wide
		 $s95= "AI_DETECTED_OFFICE_MSPROJECT2007_PIA_VERSION" fullword wide
		 $s96= "AI_DETECTED_OFFICE_MSPROJECT2010_PIA_VERSION" fullword wide
		 $s97= "AI_DETECTED_OFFICE_MSPROJECT_PIA_VERSION" fullword wide
		 $s98= "AI_DETECTED_OFFICE_ONENOTE_VERSION" fullword wide
		 $s99= "AI_DETECTED_OFFICE_OUTLOOK2003_PIA_VERSION" fullword wide
		 $s100= "AI_DETECTED_OFFICE_OUTLOOK2007_PIA_VERSION" fullword wide
		 $s101= "AI_DETECTED_OFFICE_OUTLOOK2010_PIA_VERSION" fullword wide
		 $s102= "AI_DETECTED_OFFICE_OUTLOOK_PIA_VERSION" fullword wide
		 $s103= "AI_DETECTED_OFFICE_OUTLOOK_VERSION" fullword wide
		 $s104= "AI_DETECTED_OFFICE_POWERPOINT2003_PIA_VERSION" fullword wide
		 $s105= "AI_DETECTED_OFFICE_POWERPOINT2007_PIA_VERSION" fullword wide
		 $s106= "AI_DETECTED_OFFICE_POWERPOINT2010_PIA_VERSION" fullword wide
		 $s107= "AI_DETECTED_OFFICE_POWERPOINT_PIA_VERSION" fullword wide
		 $s108= "AI_DETECTED_OFFICE_POWERPOINT_VERSION" fullword wide
		 $s109= "AI_DETECTED_OFFICE_PUBLISHER_VERSION" fullword wide
		 $s110= "AI_DETECTED_OFFICE_SHARED2007_PIA_VERSION" fullword wide
		 $s111= "AI_DETECTED_OFFICE_SHARED2010_PIA_VERSION" fullword wide
		 $s112= "AI_DETECTED_OFFICE_SHARED_PIA_VERSION" fullword wide
		 $s113= "AI_DETECTED_OFFICE_SHAREPOINT_VERSION" fullword wide
		 $s114= "AI_DETECTED_OFFICE_SKYDRIVEPRO_VERSION" fullword wide
		 $s115= "AI_DETECTED_OFFICE_SMARTTAG2003_PIA_VERSION" fullword wide
		 $s116= "AI_DETECTED_OFFICE_SMARTTAG2007_PIA_VERSION" fullword wide
		 $s117= "AI_DETECTED_OFFICE_SMARTTAG2010_PIA_VERSION" fullword wide
		 $s118= "AI_DETECTED_OFFICE_SMARTTAG_PIA_VERSION" fullword wide
		 $s119= "AI_DETECTED_OFFICE_VISIO2003_PIA_VERSION" fullword wide
		 $s120= "AI_DETECTED_OFFICE_VISIO2007_PIA_VERSION" fullword wide
		 $s121= "AI_DETECTED_OFFICE_VISIO2010_PIA_VERSION" fullword wide
		 $s122= "AI_DETECTED_OFFICE_VISIO_PIA_VERSION" fullword wide
		 $s123= "AI_DETECTED_OFFICE_VISIO_VERSION" fullword wide
		 $s124= "AI_DETECTED_OFFICE_WORD2003_PIA_VERSION" fullword wide
		 $s125= "AI_DETECTED_OFFICE_WORD2007_PIA_VERSION" fullword wide
		 $s126= "AI_DETECTED_OFFICE_WORD2010_PIA_VERSION" fullword wide
		 $s127= "AI_DETECTED_OFFICE_WORD_PIA_VERSION" fullword wide
		 $s128= "AI_DETECTED_OFFICE_WORD_VERSION" fullword wide
		 $s129= "AI_DETECTED_PHYSICAL_MEMORY" fullword wide
		 $s130= "AI_DETECTED_POWERSHELL_VERSION" fullword wide
		 $s131= "AI_DETECTED_PRODUCT_ANTIVIRUS" fullword wide
		 $s132= "AI_DETECTED_SCREEN_RESOLUTION_X" fullword wide
		 $s133= "AI_DETECTED_SCREEN_RESOLUTION_Y" fullword wide
		 $s134= "AI_DETECTED_SHAREPOINT_DEPLOYMENT" fullword wide
		 $s135= "AI_DETECTED_SHAREPOINT_PERMISSIONS" fullword wide
		 $s136= "AI_DETECTED_SHAREPOINT_SERVICES" fullword wide
		 $s137= "AI_DETECTED_SHAREPOINT_VERSION" fullword wide
		 $s138= "AI_DETECTED_SQLCOMPACT35_VERSION" fullword wide
		 $s139= "AI_DETECTED_SQLCOMPACT40_VERSION" fullword wide
		 $s140= "AI_DETECTED_SQLCOMPACT_VERSION" fullword wide
		 $s141= "AI_DETECTED_SQLEXPRESS2005_VERSION" fullword wide
		 $s142= "AI_DETECTED_SQLEXPRESS2008R2_VERSION" fullword wide
		 $s143= "AI_DETECTED_SQLEXPRESS2008_VERSION" fullword wide
		 $s144= "AI_DETECTED_SQLEXPRESS2012_VERSION" fullword wide
		 $s145= "AI_DETECTED_SQLEXPRESS2014_VERSION" fullword wide
		 $s146= "AI_DETECTED_SQLEXPRESS2016_VERSION" fullword wide
		 $s147= "AI_DETECTED_SQLEXPRESS2017_VERSION" fullword wide
		 $s148= "AI_DETECTED_SQLEXPRESS2019_VERSION" fullword wide
		 $s149= "AI_DETECTED_SQLEXPRESS_VERSION" fullword wide
		 $s150= "AI_DETECTED_VIRTUAL_MACHINE" fullword wide
		 $s151= "AI_DETECTED_WINDOWS_AZURE_VM" fullword wide
		 $s152= "AI_LOGON_AS_SERVICE_ACCOUNTS" fullword wide
		 $s153= "AI_MSM_TRIAL_MESSAGE_BODY" fullword wide
		 $s154= "AI_OVERRIDE_MIGRATED_FEATURE_STATES" fullword wide
		 $s155= "AI_PATH_VALIDATION_FAILED" fullword wide
		 $s156= "AI_PATH_VALIDATION_FILENAME" fullword wide
		 $s157= "AI_Replaced_Versions_List" fullword wide
		 $s158= "AI_ServiceConfigFailureActions" fullword wide
		 $s159= "AI_Upgrade_Replace_Question_No" fullword wide
		 $s160= "AI_Upgrade_Replace_Question_Yes" fullword wide
		 $s161= ".alz=application/x-alz-compressed" fullword wide
		 $s162= ".ani=application/x-navi-animation" fullword wide
		 $s163= "api-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s164= "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		 $s165= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s166= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s167= "api-ms-win-core-file-l1-2-2" fullword wide
		 $s168= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s169= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s170= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s171= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s172= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s173= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s174= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s175= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s176= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s177= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s178= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s179= "application/xml-external-parsed-entity" fullword wide
		 $s180= "application/x-www-form-urlencoded" fullword wide
		 $s181= ".asf=application/vnd.ms-asf" fullword wide
		 $s182= ".asx=video/x-ms-asf-plugin" fullword wide
		 $s183= "{B2279272-3FD2-434D-B94E-E4E0F8561AC4}" fullword wide
		 $s184= "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" fullword wide
		 $s185= "{B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5}" fullword wide
		 $s186= "{B94237E7-57AC-4347-9151-B08C6C32D1F7}" fullword wide
		 $s187= "{B97D20BB-F46A-4C97-BA10-5E3608430854}" fullword wide
		 $s188= "BackUp_AI_Upgrade_Question_No" fullword wide
		 $s189= "BackUp_AI_Upgrade_Question_Yes" fullword wide
		 $s190= ".bat=application/x-msdos-program" fullword wide
		 $s191= "=>?BCDEFGJKLMNQRSTWXY_a" fullword wide
		 $s192= ".bcpio=application/x-bcpio" fullword wide
		 $s193= "{C1E59364-35F6-44B3-AF0F-FCA934C4B252}" fullword wide
		 $s194= "{C1F1028F-D91A-43E8-A117-4F7CAFD7A041}" fullword wide
		 $s195= "{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}" fullword wide
		 $s196= "{C5ABBF53-E17F-4121-8900-86626FC2C973}" fullword wide
		 $s197= ".cab=application/vnd.ms-cab-compressed" fullword wide
		 $s198= ".cat=application/vnd.ms-pki.seccat" fullword wide
		 $s199= ".cdt=image/x-coreldrawtemplate" fullword wide
		 $s200= ">@CEIKNPQSTVXablmnopqrstuvxz|}" fullword wide
		 $s201= ".cer=application/x-x509-ca-cert" fullword wide
		 $s202= "CheckExistingGroups start." fullword wide
		 $s203= ".chm=application/vnd.ms-htmlhelp" fullword wide
		 $s204= ".chrt=application/vnd.kde.kchart" fullword wide
		 $s205= ".cil=application/vnd.ms-artgalry" fullword wide
		 $s206= ".class=application/java-vm" fullword wide
		 $s207= "clGradientInactiveCaption" fullword wide
		 $s208= ".clp=application/x-msclip" fullword wide
		 $s209= ".com=application/x-msdos-program" fullword wide
		 $s210= "com.embarcadero.NVSMARTMAX" fullword wide
		 $s211= "ConfigureNonAdminServiceStart" fullword wide
		 $s212= "Content-Transfer-Encoding: %s" fullword wide
		 $s213= "ConvertStringSidToSid failed!" fullword wide
		 $s214= "ConvertStringSidToSid succeeded!" fullword wide
		 $s215= "ConvertStringSidToSid successful!" fullword wide
		 $s216= "Copying subauthorities..." fullword wide
		 $s217= ".cpt=application/mac-compactpro" fullword wide
		 $s218= ".cpt=image/x-corelphotopaint" fullword wide
		 $s219= ".cqk=application/x-calquick" fullword wide
		 $s220= ".crd=application/x-mscardfile" fullword wide
		 $s221= ".crl=application/pkix-crl" fullword wide
		 $s222= "__crt_strtox::floating_point_value::as_double" fullword wide
		 $s223= "__crt_strtox::floating_point_value::as_float" fullword wide
		 $s224= "CRYPTO_cleanup_all_ex_data" fullword wide
		 $s225= "CRYPTO_set_locking_callback" fullword wide
		 $s226= "CRYPTO_set_mem_debug_functions" fullword wide
		 $s227= "csISO95JIS62291984handadd" fullword wide
		 $s228= "CurrentMajorVersionNumber" fullword wide
		 $s229= "CurrentMinorVersionNumber" fullword wide
		 $s230= "{D0384E7D-BAC3-4797-8F14-CBA229B392B5}" fullword wide
		 $s231= "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}" fullword wide
		 $s232= "{D9DC8A3B-B784-432E-A781-5A1130A75963}" fullword wide
		 $s233= ".dcr=application/x-director" fullword wide
		 $s234= "D:(D;;GA;;;NU)(A;;FA;;;SY)(A;;0x0012019b;;;WD)" fullword wide
		 $s235= "D:(D;;GA;;;NU)(A;;FA;;;SY)(A;;0x0012019f;;;WD)" fullword wide
		 $s236= "{DE974D24-D9C6-4D3E-BF91-F4455120B917}" fullword wide
		 $s237= ".deb=application/x-debian-package" fullword wide
		 $s238= "DelphiRM_GetObjectInstance" fullword wide
		 $s239= "/Deployed>" fullword wide
		 $s240= "{DFDF76A2-C82A-4D63-906A-5644AC457385}" fullword wide
		 $s241= ".dir=application/x-director" fullword wide
		 $s242= ".dist=vnd.apple.installer+xml" fullword wide
		 $s243= ".distz=vnd.apple.installer+xml" fullword wide
		 $s244= ".dll=application/x-msdos-program" fullword wide
		 $s245= ".dmg=application/x-apple-diskimage" fullword wide
		 $s246= "DownlevelGetLocaleScripts" fullword wide
		 $s247= "DownlevelGetStringScripts" fullword wide
		 $s248= "DrawThemeParentBackground" fullword wide
		 $s249= ".dxr=application/x-director" fullword wide
		 $s250= "{EA7564AC-C67D-4868-BE5C-26E4FC2223FF}" fullword wide
		 $s251= "ebcdic-international-500+euro" fullword wide
		 $s252= ".ebk=application/x-expandedbook" fullword wide
		 $s253= "{ED4824AF-DCE4-45A8-81E2-FC7965083634}" fullword wide
		 $s254= "{ED569DB3-58C4-4463-971F-4AAABB6440BD}" fullword wide
		 $s255= "{EECBA6B8-3A62-44AD-99EB-8666265466F9}" fullword wide
		 $s256= "EnableNonClientDpiScaling" fullword wide
		 $s257= ".eps=application/postscript" fullword wide
		 $s258= "EVP_CIPHER_CTX_block_size" fullword wide
		 $s259= "EVP_CIPHER_CTX_get_app_data" fullword wide
		 $s260= "EVP_CIPHER_CTX_key_length" fullword wide
		 $s261= "EVP_CIPHER_CTX_set_app_data" fullword wide
		 $s262= "EVP_CIPHER_CTX_set_key_length" fullword wide
		 $s263= "EVP_PKEY_asn1_set_private" fullword wide
		 $s264= "EVP_PKEY_CTX_get0_peerkey" fullword wide
		 $s265= "EVP_PKEY_CTX_get_app_data" fullword wide
		 $s266= "EVP_PKEY_CTX_get_keygen_info" fullword wide
		 $s267= "EVP_PKEY_CTX_get_operation" fullword wide
		 $s268= "EVP_PKEY_CTX_set0_keygen_info" fullword wide
		 $s269= "EVP_PKEY_CTX_set_app_data" fullword wide
		 $s270= "EVP_PKEY_get_default_digest_nid" fullword wide
		 $s271= "EVP_PKEY_meth_set_cleanup" fullword wide
		 $s272= "EVP_PKEY_meth_set_decrypt" fullword wide
		 $s273= "EVP_PKEY_meth_set_encrypt" fullword wide
		 $s274= "EVP_PKEY_meth_set_paramgen" fullword wide
		 $s275= "EVP_PKEY_meth_set_signctx" fullword wide
		 $s276= "EVP_PKEY_meth_set_verifyctx" fullword wide
		 $s277= "EVP_PKEY_meth_set_verify_recover" fullword wide
		 $s278= "EVP_PKEY_missing_parameters" fullword wide
		 $s279= "EVP_PKEY_verify_recover_init" fullword wide
		 $s280= ".exe=application/x-msdos-program" fullword wide
		 $s281= "Extended_UNIX_Code_Fixed_Width_for_Japanese" fullword wide
		 $s282= "Extended_UNIX_Code_Packed_Format_for_Japanese" fullword wide
		 $s283= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s284= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s285= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s286= "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}" fullword wide
		 $s287= "{F1B5AE30-CB00-4DCF-978B-07D33B034ADB}" fullword wide
		 $s288= "{F38BF404-1D43-42F2-9305-67DE0B28FC23}" fullword wide
		 $s289= "{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}" fullword wide
		 $s290= "{FAB10E66-B22C-4274-8647-7CA1BA5EF30F}" fullword wide
		 $s291= "{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}" fullword wide
		 $s292= "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}" fullword wide
		 $s293= ";>?FGHJLMQUVYZ[]^abcde" fullword wide
		 $s294= ".fif=application/fractals" fullword wide
		 $s295= ".flm=application/vnd.kde.kivio" fullword wide
		 $s296= ".fml=application/x-file-mirror-list" fullword wide
		 $s297= "FOLDERID_CommonAdminTools" fullword wide
		 $s298= "FOLDERID_ProgramFilesCommon" fullword wide
		 $s299= "FOLDERID_ProgramFilesCommonX86" fullword wide
		 $s300= "GetThemeBackgroundContentRect" fullword wide
		 $s301= "GetThemeDocumentationProperty" fullword wide
		 $s302= "GetUniDirectionalAdapterInfo" fullword wide
		 $s303= "GlobalCplShutdown-8D5475ED-3A12-4f45-9ACE-23289E49C0DF" fullword wide
		 $s304= ".gnumeric=application/x-gnumeric" fullword wide
		 $s305= "GRP_ACCESS_CONTROL_ASSISTANCE_OPS" fullword wide
		 $s306= "GRP_DOMAIN_ENTERPRISE_ADMINS" fullword wide
		 $s307= "GRP_HYPER_V_ADMINISTRATORS" fullword wide
		 $s308= "GRP_NETWORK_CONFIGURATION_OPS" fullword wide
		 $s309= "GRP_REMOTE_MANAGEMENT_USERS" fullword wide
		 $s310= "GRP_RID_INCOMING_FOREST_TRUST_BUILDERS" fullword wide
		 $s311= "GRP_SYSTEM_MANAGED_ACCOUNTS" fullword wide
		 $s312= "HKLMSoftwareAdobeAcrobat Reader10.0InstallPath" fullword wide
		 $s313= "HKLMSoftwareAdobeAcrobat Reader11.0InstallPath" fullword wide
		 $s314= "HKLMSoftwareAdobeAcrobat Reader5.0InstallPath" fullword wide
		 $s315= "HKLMSoftwareAdobeAcrobat Reader6.0InstallPath" fullword wide
		 $s316= "HKLMSoftwareAdobeAcrobat Reader7.0InstallPath" fullword wide
		 $s317= "HKLMSoftwareAdobeAcrobat Reader8.0InstallPath" fullword wide
		 $s318= "HKLMSoftwareAdobeAcrobat Reader9.0InstallPath" fullword wide
		 $s319= "HKLMSOFTWAREJavaSoftJDKCurrentVersion" fullword wide
		 $s320= "HKLMSOFTWAREJavaSoftJRECurrentVersion" fullword wide
		 $s321= "HKLMSOFTWAREMicrosoftDirectXVersion" fullword wide
		 $s322= "HKLMSOFTWAREMicrosoft.NETFrameworkpolicyv1.03705" fullword wide
		 $s323= "HKLMSOFTWAREMicrosoftPowerShell1Install" fullword wide
		 $s324= "HKLMSOFTWAREMicrosoftXNAFrameworkv1.0NativeLibraryPath" fullword wide
		 $s325= "HKLMSOFTWAREMicrosoftXNAFrameworkv2.0NativeLibraryPath" fullword wide
		 $s326= "HKLMSOFTWAREMicrosoftXNAFrameworkv3.0NativeLibraryPath" fullword wide
		 $s327= "HKLMSOFTWAREMicrosoftXNAFrameworkv3.1NativeLibraryPath" fullword wide
		 $s328= "HKLMSOFTWAREMicrosoftXNAFrameworkv4.0NativeLibraryPath" fullword wide
		 $s329= "HKLMSYSTEMCurrentControlSetServicesW3SVCDisplayName" fullword wide
		 $s330= ".hpf=application/x-icq-hpf" fullword wide
		 $s331= ".hqx=application/mac-binhex40" fullword wide
		 $s332= "htmlfileshellopencommand" fullword wide
		 $s333= "http://www.indyproject.org/" fullword wide
		 $s334= "i2d_NETSCAPE_CERT_SEQUENCE" fullword wide
		 $s335= ".iii=application/x-iphone" fullword wide
		 $s336= "ImmersiveBackgroundWindow" fullword wide
		 $s337= ".ims=application/vnd.ms-ims" fullword wide
		 $s338= "InitializeConditionVariable" fullword wide
		 $s339= "InitializeProcessForWsWatch" fullword wide
		 $s340= "InitializeSecurityContextW" fullword wide
		 $s341= ".ins=application/x-internet-signup" fullword wide
		 $s342= "ISO-8859-1-Windows-3.0-Latin-1" fullword wide
		 $s343= "ISO-8859-1-Windows-3.1-Latin-1" fullword wide
		 $s344= "ISO-8859-2-Windows-Latin-2" fullword wide
		 $s345= "ISO-8859-9-Windows-Latin-5" fullword wide
		 $s346= ".iso=application/x-iso9660-image" fullword wide
		 $s347= "IsThemeBackgroundPartiallyTransparent" fullword wide
		 $s348= "IsThemeDialogTextureEnabled" fullword wide
		 $s349= ".jar=application/java-archive" fullword wide
		 $s350= ".karbon=application/vnd.kde.karbon" fullword wide
		 $s351= ".kfo=application/vnd.kde.kformula" fullword wide
		 $s352= "KLMNORSTWXYZ[bdegnruwxy|}" fullword wide
		 $s353= ".kon=application/vnd.kde.kontour" fullword wide
		 $s354= ".kpr=application/vnd.kde.kpresenter" fullword wide
		 $s355= ".kpt=application/vnd.kde.kpresenter" fullword wide
		 $s356= ".kwd=application/vnd.kde.kword" fullword wide
		 $s357= ".kwt=application/vnd.kde.kword" fullword wide
		 $s358= ".latex=application/x-latex" fullword wide
		 $s359= "[LocalAppDataFolder]Programs" fullword wide
		 $s360= "[LocalAppDataFolder]ProgramsCommon" fullword wide
		 $s361= "LookupAliasFromRid failed" fullword wide
		 $s362= "LookupUserGroupFromRid failed" fullword wide
		 $s363= "LookupUserGroupFromRidSDDL:" fullword wide
		 $s364= "LookupUserGroupFromRidSDDL failed" fullword wide
		 $s365= "LookupUserGroupFromSid failed" fullword wide
		 $s366= ".lrm=application/vnd.ms-lrm" fullword wide
		 $s367= ".m13=application/x-msmediaview" fullword wide
		 $s368= ".m14=application/x-msmediaview" fullword wide
		 $s369= ".man=application/x-troff-man" fullword wide
		 $s370= ".mdb=application/x-msaccess" fullword wide
		 $s371= ".me=application/x-troff-me" fullword wide
		 $s372= "MIMEDatabaseContent Type" fullword wide
		 $s373= "MIMEDatabaseContent Type" fullword wide
		 $s374= "minkernelcrtsucrtinccorecrt_internal_strtox.h" fullword wide
		 $s375= ".mjf=audio/x-vnd.AudioExplosion.MjuiceMediaFile" fullword wide
		 $s376= ".mny=application/x-msmoney" fullword wide
		 $s377= ".mpkg=vnd.apple.installer+xml" fullword wide
		 $s378= ".mpp=application/vnd.ms-project" fullword wide
		 $s379= ".ms=application/x-troff-ms" fullword wide
		 $s380= "multipart/form-data; boundary=" fullword wide
		 $s381= ".mvb=application/x-msmediaview" fullword wide
		 $s382= ".nix=application/x-mix-transfer" fullword wide
		 $s383= "NVIDIA CorporationDisplay" fullword wide
		 $s384= ".odb=application/vnd.oasis.opendocument.database" fullword wide
		 $s385= ".odc=application/vnd.oasis.opendocument.chart" fullword wide
		 $s386= ".odf=application/vnd.oasis.opendocument.formula" fullword wide
		 $s387= ".odg=application/vnd.oasis.opendocument.graphics" fullword wide
		 $s388= ".odi=application/vnd.oasis.opendocument.image" fullword wide
		 $s389= ".odm=application/vnd.oasis.opendocument.text-master" fullword wide
		 $s390= ".odp=application/vnd.oasis.opendocument.presentation" fullword wide
		 $s391= ".ods=application/vnd.oasis.opendocument.spreadsheet" fullword wide
		 $s392= ".odt=application/vnd.oasis.opendocument.text" fullword wide
		 $s393= "OpenSSL_add_all_algorithms" fullword wide
		 $s394= "OPENSSL_add_all_algorithms_noconf" fullword wide
		 $s395= "_ossl_old_des_ecb_encrypt" fullword wide
		 $s396= "_ossl_old_des_set_odd_parity" fullword wide
		 $s397= ".otg=application/vnd.oasis.opendocument.graphics-template" fullword wide
		 $s398= ".oth=application/vnd.oasis.opendocument.text-web" fullword wide
		 $s399= ".otp=application/vnd.oasis.opendocument.presentation-template" fullword wide
		 $s400= ".ots=application/vnd.oasis.opendocument.spreadsheet-template" fullword wide
		 $s401= ".ott=application/vnd.oasis.opendocument.text-template" fullword wide
		 $s402= ".p12=application/x-pkcs12" fullword wide
		 $s403= ".p7b=application/x-pkcs7-certificates" fullword wide
		 $s404= ".p7m=application/pkcs7-mime" fullword wide
		 $s405= ".p7r=application/x-pkcs7-certreqresp" fullword wide
		 $s406= ".p7s=application/pkcs7-signature" fullword wide
		 $s407= ".package=application/vnd.autopackage" fullword wide
		 $s408= ".pat=image/x-coreldrawpattern" fullword wide
		 $s409= ".pbm=image/x-portable-bitmap" fullword wide
		 $s410= "PEM_read_bio_DSAPrivateKey" fullword wide
		 $s411= "PEM_read_bio_NETSCAPE_CERT_SEQUENCE" fullword wide
		 $s412= "PEM_read_bio_RSAPrivateKey" fullword wide
		 $s413= "PEM_read_bio_RSAPublicKey" fullword wide
		 $s414= "PEM_write_bio_DSAPrivateKey" fullword wide
		 $s415= "PEM_write_bio_NETSCAPE_CERT_SEQUENCE" fullword wide
		 $s416= "PEM_write_bio_PKCS8PrivateKey" fullword wide
		 $s417= "PEM_write_bio_RSAPrivateKey" fullword wide
		 $s418= "PEM_write_bio_RSAPublicKey" fullword wide
		 $s419= "PendingFileRenameOperations" fullword wide
		 $s420= ".pfr=application/font-tdpfr" fullword wide
		 $s421= ".pgm=image/x-portable-graymap" fullword wide
		 $s422= ".pkg=vnd.apple.installer+xml" fullword wide
		 $s423= ".pko=application/vnd.ms-pki.pko" fullword wide
		 $s424= "PLATFORMTARGETS TCADASTRO" fullword wide
		 $s425= "PLATFORMTARGETS TFRMFUNDO" fullword wide
		 $s426= ".pnm=image/x-portable-anymap" fullword wide
		 $s427= ".pnq=application/x-icq-pnq" fullword wide
		 $s428= ".pot=application/mspowerpoint" fullword wide
		 $s429= ".ppm=image/x-portable-pixmap" fullword wide
		 $s430= ".pps=application/mspowerpoint" fullword wide
		 $s431= ".ppt=application/mspowerpoint" fullword wide
		 $s432= ".ppz=application/mspowerpoint" fullword wide
		 $s433= "[ProgramFiles64Folder]Microsoft OfficeOffice14vviewer.dll" fullword wide
		 $s434= "[ProgramFiles64Folder]Microsoft OfficeOffice15lync.exe" fullword wide
		 $s435= "[ProgramFiles64Folder]Microsoft OfficeOffice15vviewer.dll" fullword wide
		 $s436= "[ProgramFilesFolder]Microsoft OfficeOffice14vviewer.dll" fullword wide
		 $s437= "[ProgramFilesFolder]Microsoft OfficeOffice15lync.exe" fullword wide
		 $s438= "[ProgramFilesFolder]Microsoft OfficeOffice15vviewer.dll" fullword wide
		 $s439= ".ps=application/postscript" fullword wide
		 $s440= ".pub=application/x-mspublisher" fullword wide
		 $s441= ".qpw=application/x-quattropro" fullword wide
		 $s442= ".qtl=application/x-quicktimeplayer" fullword wide
		 $s443= "QuerySecurityPackageInfoW" fullword wide
		 $s444= ".ram=audio/x-pn-realaudio" fullword wide
		 $s445= ".ResolveServiceProperties end." fullword wide
		 $s446= ".rf=image/vnd.rn-realflash" fullword wide
		 $s447= ".rjs=application/vnd.rn-realsystem-rjs" fullword wide
		 $s448= ".rm=application/vnd.rn-realmedia" fullword wide
		 $s449= ".rmp=application/vnd.rn-rn_music_package" fullword wide
		 $s450= ".rms=video/vnd.rn-realvideo-secure" fullword wide
		 $s451= ".rmx=application/vnd.rn-realsystem-rmx" fullword wide
		 $s452= ".rnx=application/vnd.rn-realplayer" fullword wide
		 $s453= ".rpm=application/x-redhat-package-manager" fullword wide
		 $s454= ".rsml=application/vnd.rn-rsml" fullword wide
		 $s455= "*RSTUVWXY]_jklmnpqrtvxyz{|}~" fullword wide
		 $s456= ".rv=video/vnd.rn-realvideo" fullword wide
		 $s457= ".scd=application/x-msschedule" fullword wide
		 $s458= ".scm=application/x-icq-scm" fullword wide
		 $s459= ".sda=application/vnd.stardivision.draw" fullword wide
		 $s460= ".sdc=application/vnd.stardivision.calc" fullword wide
		 $s461= ".sdd=application/vnd.stardivision.impress" fullword wide
		 $s462= ".ser=application/java-serialized-object" fullword wide
		 $s463= "SetLayeredWindowAttributes" fullword wide
		 $s464= ".setpay=application/set-payment-initiation" fullword wide
		 $s465= ".setreg=application/set-registration-initiation" fullword wide
		 $s466= ".shtml=server-parsed-html" fullword wide
		 $s467= ".shw=application/presentations" fullword wide
		 $s468= ".sit=application/x-stuffit" fullword wide
		 $s469= ".sitx=application/x-stuffitx" fullword wide
		 $s470= "Small Business(Restricted)" fullword wide
		 $s471= ".smf=application/vnd.stardivision.math" fullword wide
		 $s472= "SoftwareBorlandDelphiLocales" fullword wide
		 $s473= "SoftwareCaphyonAdvanced Installer" fullword wide
		 $s474= "SoftwareCodeGearLocales" fullword wide
		 $s475= "SoftwareEmbarcaderoLocales" fullword wide
		 $s476= "SOFTWAREMicrosoftInetStp" fullword wide
		 $s477= "SoftwareMicrosoftWindows NTCurrentVersion" fullword wide
		 $s478= "SOFTWAREMicrosoftWindows NTCurrentVersionFontSubstitutes" fullword wide
		 $s479= "SoftwareOracleSun RayClientInfoAgentDisconnectActions" fullword wide
		 $s480= "SoftwareOracleSun RayClientInfoAgentReconnectActions" fullword wide
		 $s481= "spanish-dominican republic" fullword wide
		 $s482= ".spl=application/futuresplash" fullword wide
		 $s483= "SSL_alert_desc_string_long" fullword wide
		 $s484= "SSL_alert_type_string_long" fullword wide
		 $s485= "SSL_COMP_get_compression_methods" fullword wide
		 $s486= "SSL_CTX_check_private_key" fullword wide
		 $s487= "SSL_CTX_load_verify_locations" fullword wide
		 $s488= "SSL_CTX_set_client_CA_list" fullword wide
		 $s489= "SSL_CTX_set_default_passwd_cb" fullword wide
		 $s490= "SSL_CTX_set_default_passwd_cb_userdata" fullword wide
		 $s491= "SSL_CTX_set_default_verify_paths" fullword wide
		 $s492= "SSL_CTX_set_session_id_context" fullword wide
		 $s493= "SSL_CTX_use_certificate_chain_file" fullword wide
		 $s494= "SSL_CTX_use_certificate_file" fullword wide
		 $s495= "SSL_CTX_use_PrivateKey_file" fullword wide
		 $s496= ".ssm=application/streamingmedia" fullword wide
		 $s497= ".sst=application/vnd.ms-pki.certstore" fullword wide
		 $s498= ".stc=application/vnd.sun.xml.calc.template" fullword wide
		 $s499= ".std=application/vnd.sun.xml.draw.template" fullword wide
		 $s500= ".sti=application/vnd.sun.xml.impress.template" fullword wide
		 $s501= ".stl=application/vnd.ms-pki.stl" fullword wide
		 $s502= ".stw=application/vnd.sun.xml.writer.template" fullword wide
		 $s503= ".sv4cpio=application/x-sv4cpio" fullword wide
		 $s504= ".sv4crc=application/x-sv4crc" fullword wide
		 $s505= ".svi=application/softvision" fullword wide
		 $s506= ".swf1=application/x-shockwave-flash" fullword wide
		 $s507= ".swf=application/x-shockwave-flash" fullword wide
		 $s508= ".sxc=application/vnd.sun.xml.calc" fullword wide
		 $s509= ".sxg=application/vnd.sun.xml.writer.global" fullword wide
		 $s510= ".sxi=application/vnd.sun.xml.impress" fullword wide
		 $s511= ".sxm=application/vnd.sun.xml.math" fullword wide
		 $s512= ".sxw=application/vnd.sun.xml.writer" fullword wide
		 $s513= "SYSTEMCurrentControlSetControlKeyboard Layouts" fullword wide
		 $s514= "SystemCurrentControlSetControlKeyboard Layouts%.8x" fullword wide
		 $s515= "SYSTEMCurrentControlSetControlProductOptions" fullword wide
		 $s516= "SYSTEMCurrentControlSetControlSession Manager" fullword wide
		 $s517= "[SystemFolder]inetsrvinetinfo.exe" fullword wide
		 $s518= "[SystemFolder]inetsrvw3wp.exe" fullword wide
		 $s519= "[SystemFolder]msiexec.exe" fullword wide
		 $s520= "[SystemFolder]wininet.dll" fullword wide
		 $s521= ".tbz2=application/x-bzip-compressed-tar" fullword wide
		 $s522= ".tbz=application/x-bzip-compressed-tar" fullword wide
		 $s523= ".texi=application/x-texinfo" fullword wide
		 $s524= ".texinfo=application/x-texinfo" fullword wide
		 $s525= "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" fullword wide
		 $s526= ".tgz=application/x-compressed-tar" fullword wide
		 $s527= ".tlz=application/x-lzma-compressed-tar" fullword wide
		 $s528= "Toolhelp32ReadProcessMemory" fullword wide
		 $s529= ".torrent=application/x-bittorrent" fullword wide
		 $s530= ".trm=application/x-msterminal" fullword wide
		 $s531= ".troff=application/x-troff" fullword wide
		 $s532= ".txz=application/x-xz-compressed-tar" fullword wide
		 $s533= ".udeb=application/x-debian-package" fullword wide
		 $s534= ".urls=application/x-url-list" fullword wide
		 $s535= "USR_KEY_DISTR_CENTER_SERVICE" fullword wide
		 $s536= ".ustar=application/x-ustar" fullword wide
		 $s537= ".vcd=application/x-cdlink" fullword wide
		 $s538= ".vor=application/vnd.stardivision.writer" fullword wide
		 $s539= ".vsl=application/x-cnet-vsl" fullword wide
		 $s540= ".wb1=application/x-quattropro" fullword wide
		 $s541= ".wb2=application/x-quattropro" fullword wide
		 $s542= ".wb3=application/x-quattropro" fullword wide
		 $s543= ".wcm=application/vnd.ms-works" fullword wide
		 $s544= ".wdb=application/vnd.ms-works" fullword wide
		 $s545= "WindowsAzureGuestAgent.exe" fullword wide
		 $s546= ".wks=application/vnd.ms-works" fullword wide
		 $s547= ".wmd=application/x-ms-wmd" fullword wide
		 $s548= ".wmlc=application/vnd.wap.wmlc" fullword wide
		 $s549= ".wmlsc=application/vnd.wap.wmlscriptc" fullword wide
		 $s550= ".wmls=text/vnd.wap.wmlscript" fullword wide
		 $s551= ".wms=application/x-ms-wms" fullword wide
		 $s552= ".wmz=application/x-ms-wmz" fullword wide
		 $s553= ".wp5=application/wordperfect5.1" fullword wide
		 $s554= ".wpd=application/wordperfect" fullword wide
		 $s555= ".wpl=application/vnd.ms-wpl" fullword wide
		 $s556= ".wps=application/vnd.ms-works" fullword wide
		 $s557= ".wri=application/x-mswrite" fullword wide
		 $s558= "WSADeleteSocketPeerTargetName" fullword wide
		 $s559= "WSAEnumNameSpaceProvidersA" fullword wide
		 $s560= "WSAEnumNameSpaceProvidersW" fullword wide
		 $s561= "WSAGetServiceClassNameByClassIdA" fullword wide
		 $s562= "WSAGetServiceClassNameByClassIdW" fullword wide
		 $s563= "WSASetSocketPeerTargetName" fullword wide
		 $s564= "X509_EXTENSION_create_by_NID" fullword wide
		 $s565= "X509_get_default_cert_file" fullword wide
		 $s566= "X509_get_default_cert_file_env" fullword wide
		 $s567= "X509_NAME_add_entry_by_txt" fullword wide
		 $s568= "X509_STORE_CTX_get_current_cert" fullword wide
		 $s569= "X509_STORE_CTX_get_error_depth" fullword wide
		 $s570= "X509_STORE_CTX_get_ex_data" fullword wide
		 $s571= "X509_STORE_load_locations" fullword wide
		 $s572= "x-EBCDIC-CyrillicSerbianBulgarian" fullword wide
		 $s573= "x-ebcdic-denmarknorway-euro" fullword wide
		 $s574= "x-ebcdic-finlandsweden-euro" fullword wide
		 $s575= "x-ebcdic-international-euro" fullword wide
		 $s576= "x-EBCDIC-JapaneseAndJapaneseLatin" fullword wide
		 $s577= "x-EBCDIC-JapaneseAndUSCanada" fullword wide
		 $s578= "x-EBCDIC-JapaneseKatakana" fullword wide
		 $s579= "x-EBCDIC-KoreanAndKoreanExtended" fullword wide
		 $s580= "x-EBCDIC-SimplifiedChinese" fullword wide
		 $s581= "x-EBCDIC-TraditionalChinese" fullword wide
		 $s582= ".xfdf=application/vnd.adobe.xfdf" fullword wide
		 $s583= ".xht=application/xhtml+xml" fullword wide
		 $s584= ".xhtml=application/xhtml+xml" fullword wide
		 $s585= ".xlb=application/x-msexcel" fullword wide
		 $s586= ".xls=application/x-msexcel" fullword wide
		 $s587= "xml-external-parsed-entity" fullword wide
		 $s588= ".xpi=application/x-xpinstall" fullword wide
		 $s589= ".xps=application/vnd.ms-xpsdocument" fullword wide
		 $s590= ".xsd=application/vnd.sun.xml.draw" fullword wide
		 $s591= ".xul=application/vnd.mozilla.xul+xml" fullword wide
		 $s592= ".z=application/x-compress" fullword wide
		 $s593= ".zip=application/x-zip-compressed" fullword wide
		 $a1= "GlobalCplShutdown-8D5475ED-3A12-4f45-9ACE-23289E49C0DF" fullword ascii
		 $a2= "HKLMSoftwareAdobeAcrobat Reader10.0InstallPath" fullword ascii
		 $a3= "HKLMSoftwareAdobeAcrobat Reader11.0InstallPath" fullword ascii
		 $a4= "HKLMSoftwareAdobeAcrobat Reader5.0InstallPath" fullword ascii
		 $a5= "HKLMSoftwareAdobeAcrobat Reader6.0InstallPath" fullword ascii
		 $a6= "HKLMSoftwareAdobeAcrobat Reader7.0InstallPath" fullword ascii
		 $a7= "HKLMSoftwareAdobeAcrobat Reader8.0InstallPath" fullword ascii
		 $a8= "HKLMSoftwareAdobeAcrobat Reader9.0InstallPath" fullword ascii
		 $a9= "HKLMSOFTWAREMicrosoft.NETFrameworkpolicyv1.03705" fullword ascii
		 $a10= "HKLMSOFTWAREMicrosoftXNAFrameworkv1.0NativeLibraryPath" fullword ascii
		 $a11= "HKLMSOFTWAREMicrosoftXNAFrameworkv2.0NativeLibraryPath" fullword ascii
		 $a12= "HKLMSOFTWAREMicrosoftXNAFrameworkv3.0NativeLibraryPath" fullword ascii
		 $a13= "HKLMSOFTWAREMicrosoftXNAFrameworkv3.1NativeLibraryPath" fullword ascii
		 $a14= "HKLMSOFTWAREMicrosoftXNAFrameworkv4.0NativeLibraryPath" fullword ascii
		 $a15= "HKLMSYSTEMCurrentControlSetServicesW3SVCDisplayName" fullword ascii
		 $a16= ".odm=application/vnd.oasis.opendocument.text-master" fullword ascii
		 $a17= ".odp=application/vnd.oasis.opendocument.presentation" fullword ascii
		 $a18= ".ods=application/vnd.oasis.opendocument.spreadsheet" fullword ascii
		 $a19= ".otg=application/vnd.oasis.opendocument.graphics-template" fullword ascii
		 $a20= ".otp=application/vnd.oasis.opendocument.presentation-template" fullword ascii
		 $a21= ".ots=application/vnd.oasis.opendocument.spreadsheet-template" fullword ascii
		 $a22= ".ott=application/vnd.oasis.opendocument.text-template" fullword ascii
		 $a23= "[ProgramFiles64Folder]Microsoft OfficeOffice14vviewer.dll" fullword ascii
		 $a24= "[ProgramFiles64Folder]Microsoft OfficeOffice15lync.exe" fullword ascii
		 $a25= "[ProgramFiles64Folder]Microsoft OfficeOffice15vviewer.dll" fullword ascii
		 $a26= "[ProgramFilesFolder]Microsoft OfficeOffice14vviewer.dll" fullword ascii
		 $a27= "[ProgramFilesFolder]Microsoft OfficeOffice15lync.exe" fullword ascii
		 $a28= "[ProgramFilesFolder]Microsoft OfficeOffice15vviewer.dll" fullword ascii
		 $a29= "SOFTWAREMicrosoftWindows NTCurrentVersionFontSubstitutes" fullword ascii
		 $a30= "SoftwareOracleSun RayClientInfoAgentDisconnectActions" fullword ascii
		 $a31= "SoftwareOracleSun RayClientInfoAgentReconnectActions" fullword ascii
		 $a32= "SYSTEMCurrentControlSetControlKeyboard Layouts" fullword ascii
		 $a33= "SystemCurrentControlSetControlKeyboard Layouts%.8x" fullword ascii
		 $a34= "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" fullword ascii

		 $hex1= {246131303d2022484b}
		 $hex2= {246131313d2022484b}
		 $hex3= {246131323d2022484b}
		 $hex4= {246131333d2022484b}
		 $hex5= {246131343d2022484b}
		 $hex6= {246131353d2022484b}
		 $hex7= {246131363d20222e6f}
		 $hex8= {246131373d20222e6f}
		 $hex9= {246131383d20222e6f}
		 $hex10= {246131393d20222e6f}
		 $hex11= {2461313d2022476c6f}
		 $hex12= {246132303d20222e6f}
		 $hex13= {246132313d20222e6f}
		 $hex14= {246132323d20222e6f}
		 $hex15= {246132333d20225b50}
		 $hex16= {246132343d20225b50}
		 $hex17= {246132353d20225b50}
		 $hex18= {246132363d20225b50}
		 $hex19= {246132373d20225b50}
		 $hex20= {246132383d20225b50}
		 $hex21= {246132393d2022534f}
		 $hex22= {2461323d2022484b4c}
		 $hex23= {246133303d2022536f}
		 $hex24= {246133313d2022536f}
		 $hex25= {246133323d20225359}
		 $hex26= {246133333d20225379}
		 $hex27= {246133343d20227465}
		 $hex28= {2461333d2022484b4c}
		 $hex29= {2461343d2022484b4c}
		 $hex30= {2461353d2022484b4c}
		 $hex31= {2461363d2022484b4c}
		 $hex32= {2461373d2022484b4c}
		 $hex33= {2461383d2022484b4c}
		 $hex34= {2461393d2022484b4c}
		 $hex35= {24733130303d202241}
		 $hex36= {24733130313d202241}
		 $hex37= {24733130323d202241}
		 $hex38= {24733130333d202241}
		 $hex39= {24733130343d202241}
		 $hex40= {24733130353d202241}
		 $hex41= {24733130363d202241}
		 $hex42= {24733130373d202241}
		 $hex43= {24733130383d202241}
		 $hex44= {24733130393d202241}
		 $hex45= {247331303d20227b31}
		 $hex46= {24733131303d202241}
		 $hex47= {24733131313d202241}
		 $hex48= {24733131323d202241}
		 $hex49= {24733131333d202241}
		 $hex50= {24733131343d202241}
		 $hex51= {24733131353d202241}
		 $hex52= {24733131363d202241}
		 $hex53= {24733131373d202241}
		 $hex54= {24733131383d202241}
		 $hex55= {24733131393d202241}
		 $hex56= {247331313d20227b31}
		 $hex57= {24733132303d202241}
		 $hex58= {24733132313d202241}
		 $hex59= {24733132323d202241}
		 $hex60= {24733132333d202241}
		 $hex61= {24733132343d202241}
		 $hex62= {24733132353d202241}
		 $hex63= {24733132363d202241}
		 $hex64= {24733132373d202241}
		 $hex65= {24733132383d202241}
		 $hex66= {24733132393d202241}
		 $hex67= {247331323d20227b31}
		 $hex68= {24733133303d202241}
		 $hex69= {24733133313d202241}
		 $hex70= {24733133323d202241}
		 $hex71= {24733133333d202241}
		 $hex72= {24733133343d202241}
		 $hex73= {24733133353d202241}
		 $hex74= {24733133363d202241}
		 $hex75= {24733133373d202241}
		 $hex76= {24733133383d202241}
		 $hex77= {24733133393d202241}
		 $hex78= {247331333d20227b31}
		 $hex79= {24733134303d202241}
		 $hex80= {24733134313d202241}
		 $hex81= {24733134323d202241}
		 $hex82= {24733134333d202241}
		 $hex83= {24733134343d202241}
		 $hex84= {24733134353d202241}
		 $hex85= {24733134363d202241}
		 $hex86= {24733134373d202241}
		 $hex87= {24733134383d202241}
		 $hex88= {24733134393d202241}
		 $hex89= {247331343d20227b31}
		 $hex90= {24733135303d202241}
		 $hex91= {24733135313d202241}
		 $hex92= {24733135323d202241}
		 $hex93= {24733135333d202241}
		 $hex94= {24733135343d202241}
		 $hex95= {24733135353d202241}
		 $hex96= {24733135363d202241}
		 $hex97= {24733135373d202241}
		 $hex98= {24733135383d202241}
		 $hex99= {24733135393d202241}
		 $hex100= {247331353d20227b32}
		 $hex101= {24733136303d202241}
		 $hex102= {24733136313d20222e}
		 $hex103= {24733136323d20222e}
		 $hex104= {24733136333d202261}
		 $hex105= {24733136343d202261}
		 $hex106= {24733136353d202261}
		 $hex107= {24733136363d202261}
		 $hex108= {24733136373d202261}
		 $hex109= {24733136383d202261}
		 $hex110= {24733136393d202261}
		 $hex111= {247331363d20227b32}
		 $hex112= {24733137303d202261}
		 $hex113= {24733137313d202261}
		 $hex114= {24733137323d202261}
		 $hex115= {24733137333d202261}
		 $hex116= {24733137343d202261}
		 $hex117= {24733137353d202261}
		 $hex118= {24733137363d202261}
		 $hex119= {24733137373d202261}
		 $hex120= {24733137383d202261}
		 $hex121= {24733137393d202261}
		 $hex122= {247331373d20227b33}
		 $hex123= {24733138303d202261}
		 $hex124= {24733138313d20222e}
		 $hex125= {24733138323d20222e}
		 $hex126= {24733138333d20227b}
		 $hex127= {24733138343d20227b}
		 $hex128= {24733138353d20227b}
		 $hex129= {24733138363d20227b}
		 $hex130= {24733138373d20227b}
		 $hex131= {24733138383d202242}
		 $hex132= {24733138393d202242}
		 $hex133= {247331383d20227b33}
		 $hex134= {24733139303d20222e}
		 $hex135= {24733139313d20223d}
		 $hex136= {24733139323d20222e}
		 $hex137= {24733139333d20227b}
		 $hex138= {24733139343d20227b}
		 $hex139= {24733139353d20227b}
		 $hex140= {24733139363d20227b}
		 $hex141= {24733139373d20222e}
		 $hex142= {24733139383d20222e}
		 $hex143= {24733139393d20222e}
		 $hex144= {247331393d20227b33}
		 $hex145= {2473313d20222b2425}
		 $hex146= {24733230303d20223e}
		 $hex147= {24733230313d20222e}
		 $hex148= {24733230323d202243}
		 $hex149= {24733230333d20222e}
		 $hex150= {24733230343d20222e}
		 $hex151= {24733230353d20222e}
		 $hex152= {24733230363d20222e}
		 $hex153= {24733230373d202263}
		 $hex154= {24733230383d20222e}
		 $hex155= {24733230393d20222e}
		 $hex156= {247332303d20227b33}
		 $hex157= {24733231303d202263}
		 $hex158= {24733231313d202243}
		 $hex159= {24733231323d202243}
		 $hex160= {24733231333d202243}
		 $hex161= {24733231343d202243}
		 $hex162= {24733231353d202243}
		 $hex163= {24733231363d202243}
		 $hex164= {24733231373d20222e}
		 $hex165= {24733231383d20222e}
		 $hex166= {24733231393d20222e}
		 $hex167= {247332313d20227b33}
		 $hex168= {24733232303d20222e}
		 $hex169= {24733232313d20222e}
		 $hex170= {24733232323d20225f}
		 $hex171= {24733232333d20225f}
		 $hex172= {24733232343d202243}
		 $hex173= {24733232353d202243}
		 $hex174= {24733232363d202243}
		 $hex175= {24733232373d202263}
		 $hex176= {24733232383d202243}
		 $hex177= {24733232393d202243}
		 $hex178= {247332323d20227b33}
		 $hex179= {24733233303d20227b}
		 $hex180= {24733233313d20227b}
		 $hex181= {24733233323d20227b}
		 $hex182= {24733233333d20222e}
		 $hex183= {24733233343d202244}
		 $hex184= {24733233353d202244}
		 $hex185= {24733233363d20227b}
		 $hex186= {24733233373d20222e}
		 $hex187= {24733233383d202244}
		 $hex188= {24733233393d20222f}
		 $hex189= {247332333d20227b34}
		 $hex190= {24733234303d20227b}
		 $hex191= {24733234313d20222e}
		 $hex192= {24733234323d20222e}
		 $hex193= {24733234333d20222e}
		 $hex194= {24733234343d20222e}
		 $hex195= {24733234353d20222e}
		 $hex196= {24733234363d202244}
		 $hex197= {24733234373d202244}
		 $hex198= {24733234383d202244}
		 $hex199= {24733234393d20222e}
		 $hex200= {247332343d20227b34}
		 $hex201= {24733235303d20227b}
		 $hex202= {24733235313d202265}
		 $hex203= {24733235323d20222e}
		 $hex204= {24733235333d20227b}
		 $hex205= {24733235343d20227b}
		 $hex206= {24733235353d20227b}
		 $hex207= {24733235363d202245}
		 $hex208= {24733235373d20222e}
		 $hex209= {24733235383d202245}
		 $hex210= {24733235393d202245}
		 $hex211= {247332353d20227b34}
		 $hex212= {24733236303d202245}
		 $hex213= {24733236313d202245}
		 $hex214= {24733236323d202245}
		 $hex215= {24733236333d202245}
		 $hex216= {24733236343d202245}
		 $hex217= {24733236353d202245}
		 $hex218= {24733236363d202245}
		 $hex219= {24733236373d202245}
		 $hex220= {24733236383d202245}
		 $hex221= {24733236393d202245}
		 $hex222= {247332363d20227b35}
		 $hex223= {24733237303d202245}
		 $hex224= {24733237313d202245}
		 $hex225= {24733237323d202245}
		 $hex226= {24733237333d202245}
		 $hex227= {24733237343d202245}
		 $hex228= {24733237353d202245}
		 $hex229= {24733237363d202245}
		 $hex230= {24733237373d202245}
		 $hex231= {24733237383d202245}
		 $hex232= {24733237393d202245}
		 $hex233= {247332373d20227b35}
		 $hex234= {24733238303d20222e}
		 $hex235= {24733238313d202245}
		 $hex236= {24733238323d202245}
		 $hex237= {24733238333d202265}
		 $hex238= {24733238343d202265}
		 $hex239= {24733238353d202265}
		 $hex240= {24733238363d20227b}
		 $hex241= {24733238373d20227b}
		 $hex242= {24733238383d20227b}
		 $hex243= {24733238393d20227b}
		 $hex244= {247332383d20227b35}
		 $hex245= {24733239303d20227b}
		 $hex246= {24733239313d20227b}
		 $hex247= {24733239323d20227b}
		 $hex248= {24733239333d20223b}
		 $hex249= {24733239343d20222e}
		 $hex250= {24733239353d20222e}
		 $hex251= {24733239363d20222e}
		 $hex252= {24733239373d202246}
		 $hex253= {24733239383d202246}
		 $hex254= {24733239393d202246}
		 $hex255= {247332393d20227b36}
		 $hex256= {2473323d20227b3030}
		 $hex257= {24733330303d202247}
		 $hex258= {24733330313d202247}
		 $hex259= {24733330323d202247}
		 $hex260= {24733330333d202247}
		 $hex261= {24733330343d20222e}
		 $hex262= {24733330353d202247}
		 $hex263= {24733330363d202247}
		 $hex264= {24733330373d202247}
		 $hex265= {24733330383d202247}
		 $hex266= {24733330393d202247}
		 $hex267= {247333303d20227b36}
		 $hex268= {24733331303d202247}
		 $hex269= {24733331313d202247}
		 $hex270= {24733331323d202248}
		 $hex271= {24733331333d202248}
		 $hex272= {24733331343d202248}
		 $hex273= {24733331353d202248}
		 $hex274= {24733331363d202248}
		 $hex275= {24733331373d202248}
		 $hex276= {24733331383d202248}
		 $hex277= {24733331393d202248}
		 $hex278= {247333313d20227b36}
		 $hex279= {24733332303d202248}
		 $hex280= {24733332313d202248}
		 $hex281= {24733332323d202248}
		 $hex282= {24733332333d202248}
		 $hex283= {24733332343d202248}
		 $hex284= {24733332353d202248}
		 $hex285= {24733332363d202248}
		 $hex286= {24733332373d202248}
		 $hex287= {24733332383d202248}
		 $hex288= {24733332393d202248}
		 $hex289= {247333323d20227b36}
		 $hex290= {24733333303d20222e}
		 $hex291= {24733333313d20222e}
		 $hex292= {24733333323d202268}
		 $hex293= {24733333333d202268}
		 $hex294= {24733333343d202269}
		 $hex295= {24733333353d20222e}
		 $hex296= {24733333363d202249}
		 $hex297= {24733333373d20222e}
		 $hex298= {24733333383d202249}
		 $hex299= {24733333393d202249}
		 $hex300= {247333333d20227b37}
		 $hex301= {24733334303d202249}
		 $hex302= {24733334313d20222e}
		 $hex303= {24733334323d202249}
		 $hex304= {24733334333d202249}
		 $hex305= {24733334343d202249}
		 $hex306= {24733334353d202249}
		 $hex307= {24733334363d20222e}
		 $hex308= {24733334373d202249}
		 $hex309= {24733334383d202249}
		 $hex310= {24733334393d20222e}
		 $hex311= {247333343d20227b37}
		 $hex312= {24733335303d20222e}
		 $hex313= {24733335313d20222e}
		 $hex314= {24733335323d20224b}
		 $hex315= {24733335333d20222e}
		 $hex316= {24733335343d20222e}
		 $hex317= {24733335353d20222e}
		 $hex318= {24733335363d20222e}
		 $hex319= {24733335373d20222e}
		 $hex320= {24733335383d20222e}
		 $hex321= {24733335393d20225b}
		 $hex322= {247333353d20222e37}
		 $hex323= {24733336303d20225b}
		 $hex324= {24733336313d20224c}
		 $hex325= {24733336323d20224c}
		 $hex326= {24733336333d20224c}
		 $hex327= {24733336343d20224c}
		 $hex328= {24733336353d20224c}
		 $hex329= {24733336363d20222e}
		 $hex330= {24733336373d20222e}
		 $hex331= {24733336383d20222e}
		 $hex332= {24733336393d20222e}
		 $hex333= {247333363d20227b38}
		 $hex334= {24733337303d20222e}
		 $hex335= {24733337313d20222e}
		 $hex336= {24733337323d20224d}
		 $hex337= {24733337333d20224d}
		 $hex338= {24733337343d20226d}
		 $hex339= {24733337353d20222e}
		 $hex340= {24733337363d20222e}
		 $hex341= {24733337373d20222e}
		 $hex342= {24733337383d20222e}
		 $hex343= {24733337393d20222e}
		 $hex344= {247333373d20227b38}
		 $hex345= {24733338303d20226d}
		 $hex346= {24733338313d20222e}
		 $hex347= {24733338323d20222e}
		 $hex348= {24733338333d20224e}
		 $hex349= {24733338343d20222e}
		 $hex350= {24733338353d20222e}
		 $hex351= {24733338363d20222e}
		 $hex352= {24733338373d20222e}
		 $hex353= {24733338383d20222e}
		 $hex354= {24733338393d20222e}
		 $hex355= {247333383d20227b38}
		 $hex356= {24733339303d20222e}
		 $hex357= {24733339313d20222e}
		 $hex358= {24733339323d20222e}
		 $hex359= {24733339333d20224f}
		 $hex360= {24733339343d20224f}
		 $hex361= {24733339353d20225f}
		 $hex362= {24733339363d20225f}
		 $hex363= {24733339373d20222e}
		 $hex364= {24733339383d20222e}
		 $hex365= {24733339393d20222e}
		 $hex366= {247333393d20227b38}
		 $hex367= {2473333d20227b3031}
		 $hex368= {24733430303d20222e}
		 $hex369= {24733430313d20222e}
		 $hex370= {24733430323d20222e}
		 $hex371= {24733430333d20222e}
		 $hex372= {24733430343d20222e}
		 $hex373= {24733430353d20222e}
		 $hex374= {24733430363d20222e}
		 $hex375= {24733430373d20222e}
		 $hex376= {24733430383d20222e}
		 $hex377= {24733430393d20222e}
		 $hex378= {247334303d20227b38}
		 $hex379= {24733431303d202250}
		 $hex380= {24733431313d202250}
		 $hex381= {24733431323d202250}
		 $hex382= {24733431333d202250}
		 $hex383= {24733431343d202250}
		 $hex384= {24733431353d202250}
		 $hex385= {24733431363d202250}
		 $hex386= {24733431373d202250}
		 $hex387= {24733431383d202250}
		 $hex388= {24733431393d202250}
		 $hex389= {247334313d20227b38}
		 $hex390= {24733432303d20222e}
		 $hex391= {24733432313d20222e}
		 $hex392= {24733432323d20222e}
		 $hex393= {24733432333d20222e}
		 $hex394= {24733432343d202250}
		 $hex395= {24733432353d202250}
		 $hex396= {24733432363d20222e}
		 $hex397= {24733432373d20222e}
		 $hex398= {24733432383d20222e}
		 $hex399= {24733432393d20222e}
		 $hex400= {247334323d20227b39}
		 $hex401= {24733433303d20222e}
		 $hex402= {24733433313d20222e}
		 $hex403= {24733433323d20222e}
		 $hex404= {24733433333d20225b}
		 $hex405= {24733433343d20225b}
		 $hex406= {24733433353d20225b}
		 $hex407= {24733433363d20225b}
		 $hex408= {24733433373d20225b}
		 $hex409= {24733433383d20225b}
		 $hex410= {24733433393d20222e}
		 $hex411= {247334333d20227b39}
		 $hex412= {24733434303d20222e}
		 $hex413= {24733434313d20222e}
		 $hex414= {24733434323d20222e}
		 $hex415= {24733434333d202251}
		 $hex416= {24733434343d20222e}
		 $hex417= {24733434353d20222e}
		 $hex418= {24733434363d20222e}
		 $hex419= {24733434373d20222e}
		 $hex420= {24733434383d20222e}
		 $hex421= {24733434393d20222e}
		 $hex422= {247334343d20227b39}
		 $hex423= {24733435303d20222e}
		 $hex424= {24733435313d20222e}
		 $hex425= {24733435323d20222e}
		 $hex426= {24733435333d20222e}
		 $hex427= {24733435343d20222e}
		 $hex428= {24733435353d20222a}
		 $hex429= {24733435363d20222e}
		 $hex430= {24733435373d20222e}
		 $hex431= {24733435383d20222e}
		 $hex432= {24733435393d20222e}
		 $hex433= {247334353d20227b39}
		 $hex434= {24733436303d20222e}
		 $hex435= {24733436313d20222e}
		 $hex436= {24733436323d20222e}
		 $hex437= {24733436333d202253}
		 $hex438= {24733436343d20222e}
		 $hex439= {24733436353d20222e}
		 $hex440= {24733436363d20222e}
		 $hex441= {24733436373d20222e}
		 $hex442= {24733436383d20222e}
		 $hex443= {24733436393d20222e}
		 $hex444= {247334363d20227b41}
		 $hex445= {24733437303d202253}
		 $hex446= {24733437313d20222e}
		 $hex447= {24733437323d202253}
		 $hex448= {24733437333d202253}
		 $hex449= {24733437343d202253}
		 $hex450= {24733437353d202253}
		 $hex451= {24733437363d202253}
		 $hex452= {24733437373d202253}
		 $hex453= {24733437383d202253}
		 $hex454= {24733437393d202253}
		 $hex455= {247334373d20227b41}
		 $hex456= {24733438303d202253}
		 $hex457= {24733438313d202273}
		 $hex458= {24733438323d20222e}
		 $hex459= {24733438333d202253}
		 $hex460= {24733438343d202253}
		 $hex461= {24733438353d202253}
		 $hex462= {24733438363d202253}
		 $hex463= {24733438373d202253}
		 $hex464= {24733438383d202253}
		 $hex465= {24733438393d202253}
		 $hex466= {247334383d20227b41}
		 $hex467= {24733439303d202253}
		 $hex468= {24733439313d202253}
		 $hex469= {24733439323d202253}
		 $hex470= {24733439333d202253}
		 $hex471= {24733439343d202253}
		 $hex472= {24733439353d202253}
		 $hex473= {24733439363d20222e}
		 $hex474= {24733439373d20222e}
		 $hex475= {24733439383d20222e}
		 $hex476= {24733439393d20222e}
		 $hex477= {247334393d20227b41}
		 $hex478= {2473343d20227b3031}
		 $hex479= {24733530303d20222e}
		 $hex480= {24733530313d20222e}
		 $hex481= {24733530323d20222e}
		 $hex482= {24733530333d20222e}
		 $hex483= {24733530343d20222e}
		 $hex484= {24733530353d20222e}
		 $hex485= {24733530363d20222e}
		 $hex486= {24733530373d20222e}
		 $hex487= {24733530383d20222e}
		 $hex488= {24733530393d20222e}
		 $hex489= {247335303d20227b41}
		 $hex490= {24733531303d20222e}
		 $hex491= {24733531313d20222e}
		 $hex492= {24733531323d20222e}
		 $hex493= {24733531333d202253}
		 $hex494= {24733531343d202253}
		 $hex495= {24733531353d202253}
		 $hex496= {24733531363d202253}
		 $hex497= {24733531373d20225b}
		 $hex498= {24733531383d20225b}
		 $hex499= {24733531393d20225b}
		 $hex500= {247335313d20222e61}
		 $hex501= {24733532303d20225b}
		 $hex502= {24733532313d20222e}
		 $hex503= {24733532323d20222e}
		 $hex504= {24733532333d20222e}
		 $hex505= {24733532343d20222e}
		 $hex506= {24733532353d202274}
		 $hex507= {24733532363d20222e}
		 $hex508= {24733532373d20222e}
		 $hex509= {24733532383d202254}
		 $hex510= {24733532393d20222e}
		 $hex511= {247335323d20222e61}
		 $hex512= {24733533303d20222e}
		 $hex513= {24733533313d20222e}
		 $hex514= {24733533323d20222e}
		 $hex515= {24733533333d20222e}
		 $hex516= {24733533343d20222e}
		 $hex517= {24733533353d202255}
		 $hex518= {24733533363d20222e}
		 $hex519= {24733533373d20222e}
		 $hex520= {24733533383d20222e}
		 $hex521= {24733533393d20222e}
		 $hex522= {247335333d20222e61}
		 $hex523= {24733534303d20222e}
		 $hex524= {24733534313d20222e}
		 $hex525= {24733534323d20222e}
		 $hex526= {24733534333d20222e}
		 $hex527= {24733534343d20222e}
		 $hex528= {24733534353d202257}
		 $hex529= {24733534363d20222e}
		 $hex530= {24733534373d20222e}
		 $hex531= {24733534383d20222e}
		 $hex532= {24733534393d20222e}
		 $hex533= {247335343d20222e61}
		 $hex534= {24733535303d20222e}
		 $hex535= {24733535313d20222e}
		 $hex536= {24733535323d20222e}
		 $hex537= {24733535333d20222e}
		 $hex538= {24733535343d20222e}
		 $hex539= {24733535353d20222e}
		 $hex540= {24733535363d20222e}
		 $hex541= {24733535373d20222e}
		 $hex542= {24733535383d202257}
		 $hex543= {24733535393d202257}
		 $hex544= {247335353d20222e61}
		 $hex545= {24733536303d202257}
		 $hex546= {24733536313d202257}
		 $hex547= {24733536323d202257}
		 $hex548= {24733536333d202257}
		 $hex549= {24733536343d202258}
		 $hex550= {24733536353d202258}
		 $hex551= {24733536363d202258}
		 $hex552= {24733536373d202258}
		 $hex553= {24733536383d202258}
		 $hex554= {24733536393d202258}
		 $hex555= {247335363d20224163}
		 $hex556= {24733537303d202258}
		 $hex557= {24733537313d202258}
		 $hex558= {24733537323d202278}
		 $hex559= {24733537333d202278}
		 $hex560= {24733537343d202278}
		 $hex561= {24733537353d202278}
		 $hex562= {24733537363d202278}
		 $hex563= {24733537373d202278}
		 $hex564= {24733537383d202278}
		 $hex565= {24733537393d202278}
		 $hex566= {247335373d20227b41}
		 $hex567= {24733538303d202278}
		 $hex568= {24733538313d202278}
		 $hex569= {24733538323d20222e}
		 $hex570= {24733538333d20222e}
		 $hex571= {24733538343d20222e}
		 $hex572= {24733538353d20222e}
		 $hex573= {24733538363d20222e}
		 $hex574= {24733538373d202278}
		 $hex575= {24733538383d20222e}
		 $hex576= {24733538393d20222e}
		 $hex577= {247335383d20222e61}
		 $hex578= {24733539303d20222e}
		 $hex579= {24733539313d20222e}
		 $hex580= {24733539323d20222e}
		 $hex581= {24733539333d20222e}
		 $hex582= {247335393d20224149}
		 $hex583= {2473353d20222a2a2b}
		 $hex584= {247336303d20224149}
		 $hex585= {247336313d20224149}
		 $hex586= {247336323d20224149}
		 $hex587= {247336333d20224149}
		 $hex588= {247336343d20224149}
		 $hex589= {247336353d20224149}
		 $hex590= {247336363d20224149}
		 $hex591= {247336373d20224149}
		 $hex592= {247336383d20224149}
		 $hex593= {247336393d20224149}
		 $hex594= {2473363d20227b3034}
		 $hex595= {247337303d20224149}
		 $hex596= {247337313d20224149}
		 $hex597= {247337323d20224149}
		 $hex598= {247337333d20224149}
		 $hex599= {247337343d20224149}
		 $hex600= {247337353d20224149}
		 $hex601= {247337363d20224149}
		 $hex602= {247337373d20224149}
		 $hex603= {247337383d20224149}
		 $hex604= {247337393d20224149}
		 $hex605= {2473373d20227b3134}
		 $hex606= {247338303d20224149}
		 $hex607= {247338313d20224149}
		 $hex608= {247338323d20224149}
		 $hex609= {247338333d20224149}
		 $hex610= {247338343d20224149}
		 $hex611= {247338353d20224149}
		 $hex612= {247338363d20224149}
		 $hex613= {247338373d20224149}
		 $hex614= {247338383d20224149}
		 $hex615= {247338393d20224149}
		 $hex616= {2473383d20227b3137}
		 $hex617= {247339303d20224149}
		 $hex618= {247339313d20224149}
		 $hex619= {247339323d20224149}
		 $hex620= {247339333d20224149}
		 $hex621= {247339343d20224149}
		 $hex622= {247339353d20224149}
		 $hex623= {247339363d20224149}
		 $hex624= {247339373d20224149}
		 $hex625= {247339383d20224149}
		 $hex626= {247339393d20224149}
		 $hex627= {2473393d20227b3138}

	condition:
		418 of them
}
