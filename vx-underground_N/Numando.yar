
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
		 date = "2022-01-14_06-03-19" 
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
		 $s35= "{816D4DFD-FF7B-4C16-8943-EEB07DF989CB}" fullword wide
		 $s36= "{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}" fullword wide
		 $s37= "{835AC3CE-E36B-4D65-B50F-2863A682ABEE}" fullword wide
		 $s38= "{8983036C-27C0-404B-8F08-102D10DCFD74}" fullword wide
		 $s39= "{8AD10C31-2ADB-4296-A8F7-E4701232C972}" fullword wide
		 $s40= "{8B74A499-37F8-4DEA-B5A0-D72FC501CEFA}" fullword wide
		 $s41= "{905e63b6-c1bf-494e-b29c-65b732d3d21a}" fullword wide
		 $s42= "{9274BD8D-CFD1-41C3-B35E-B13F55A758F4}" fullword wide
		 $s43= "{957A4EC0-E67B-4E86-A383-6AF7270B216A}" fullword wide
		 $s44= "{9E52AB10-F80D-49DF-ACB8-4330F5687855}" fullword wide
		 $s45= "{A1FE0698-609D-400F-BF10-F52238DD6475}" fullword wide
		 $s46= "{A4115719-D62E-491D-AA7C-E74B8BE3B067}" fullword wide
		 $s47= "{A58B51D1-89BF-4D88-939D-B6D0DB2EEB53}" fullword wide
		 $s48= "{A63293E8-664E-48DB-A079-DF759E0509F7}" fullword wide
		 $s49= "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}" fullword wide
		 $s50= "{AE50C081-EBD2-438A-8655-8A092E34987A}" fullword wide
		 $s51= "AI_DETECTED_OFFICE_EXCEL2003_PIA_VERSION" fullword wide
		 $s52= "AI_DETECTED_OFFICE_EXCEL2007_PIA_VERSION" fullword wide
		 $s53= "AI_DETECTED_OFFICE_EXCEL2010_PIA_VERSION" fullword wide
		 $s54= "AI_DETECTED_OFFICE_EXCEL_PIA_VERSION" fullword wide
		 $s55= "AI_DETECTED_OFFICE_INFOPATH2003_PIA_VERSION" fullword wide
		 $s56= "AI_DETECTED_OFFICE_INFOPATH2007_PIA_VERSION" fullword wide
		 $s57= "AI_DETECTED_OFFICE_INFOPATH2010_PIA_VERSION" fullword wide
		 $s58= "AI_DETECTED_OFFICE_INFOPATH_PIA_VERSION" fullword wide
		 $s59= "AI_DETECTED_OFFICE_INFOPATH_VERSION" fullword wide
		 $s60= "AI_DETECTED_OFFICE_MSFORMS2003_PIA_VERSION" fullword wide
		 $s61= "AI_DETECTED_OFFICE_MSFORMS2007_PIA_VERSION" fullword wide
		 $s62= "AI_DETECTED_OFFICE_MSFORMS2010_PIA_VERSION" fullword wide
		 $s63= "AI_DETECTED_OFFICE_MSFORMS_PIA_VERSION" fullword wide
		 $s64= "AI_DETECTED_OFFICE_MSGRAPH2003_PIA_VERSION" fullword wide
		 $s65= "AI_DETECTED_OFFICE_MSGRAPH2007_PIA_VERSION" fullword wide
		 $s66= "AI_DETECTED_OFFICE_MSGRAPH2010_PIA_VERSION" fullword wide
		 $s67= "AI_DETECTED_OFFICE_MSGRAPH_PIA_VERSION" fullword wide
		 $s68= "AI_DETECTED_OFFICE_MSPROJECT2007_PIA_VERSION" fullword wide
		 $s69= "AI_DETECTED_OFFICE_MSPROJECT2010_PIA_VERSION" fullword wide
		 $s70= "AI_DETECTED_OFFICE_MSPROJECT_PIA_VERSION" fullword wide
		 $s71= "AI_DETECTED_OFFICE_OUTLOOK2003_PIA_VERSION" fullword wide
		 $s72= "AI_DETECTED_OFFICE_OUTLOOK2007_PIA_VERSION" fullword wide
		 $s73= "AI_DETECTED_OFFICE_OUTLOOK2010_PIA_VERSION" fullword wide
		 $s74= "AI_DETECTED_OFFICE_OUTLOOK_PIA_VERSION" fullword wide
		 $s75= "AI_DETECTED_OFFICE_POWERPOINT2003_PIA_VERSION" fullword wide
		 $s76= "AI_DETECTED_OFFICE_POWERPOINT2007_PIA_VERSION" fullword wide
		 $s77= "AI_DETECTED_OFFICE_POWERPOINT2010_PIA_VERSION" fullword wide
		 $s78= "AI_DETECTED_OFFICE_POWERPOINT_PIA_VERSION" fullword wide
		 $s79= "AI_DETECTED_OFFICE_POWERPOINT_VERSION" fullword wide
		 $s80= "AI_DETECTED_OFFICE_PUBLISHER_VERSION" fullword wide
		 $s81= "AI_DETECTED_OFFICE_SHARED2007_PIA_VERSION" fullword wide
		 $s82= "AI_DETECTED_OFFICE_SHARED2010_PIA_VERSION" fullword wide
		 $s83= "AI_DETECTED_OFFICE_SHARED_PIA_VERSION" fullword wide
		 $s84= "AI_DETECTED_OFFICE_SHAREPOINT_VERSION" fullword wide
		 $s85= "AI_DETECTED_OFFICE_SKYDRIVEPRO_VERSION" fullword wide
		 $s86= "AI_DETECTED_OFFICE_SMARTTAG2003_PIA_VERSION" fullword wide
		 $s87= "AI_DETECTED_OFFICE_SMARTTAG2007_PIA_VERSION" fullword wide
		 $s88= "AI_DETECTED_OFFICE_SMARTTAG2010_PIA_VERSION" fullword wide
		 $s89= "AI_DETECTED_OFFICE_SMARTTAG_PIA_VERSION" fullword wide
		 $s90= "AI_DETECTED_OFFICE_VISIO2003_PIA_VERSION" fullword wide
		 $s91= "AI_DETECTED_OFFICE_VISIO2007_PIA_VERSION" fullword wide
		 $s92= "AI_DETECTED_OFFICE_VISIO2010_PIA_VERSION" fullword wide
		 $s93= "AI_DETECTED_OFFICE_VISIO_PIA_VERSION" fullword wide
		 $s94= "AI_DETECTED_OFFICE_WORD2003_PIA_VERSION" fullword wide
		 $s95= "AI_DETECTED_OFFICE_WORD2007_PIA_VERSION" fullword wide
		 $s96= "AI_DETECTED_OFFICE_WORD2010_PIA_VERSION" fullword wide
		 $s97= "AI_DETECTED_OFFICE_WORD_PIA_VERSION" fullword wide
		 $s98= "AI_DETECTED_SQLEXPRESS2008R2_VERSION" fullword wide
		 $s99= "AI_OVERRIDE_MIGRATED_FEATURE_STATES" fullword wide
		 $s100= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s101= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s102= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s103= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s104= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s105= "application/xml-external-parsed-entity" fullword wide
		 $s106= "{B2279272-3FD2-434D-B94E-E4E0F8561AC4}" fullword wide
		 $s107= "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" fullword wide
		 $s108= "{B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5}" fullword wide
		 $s109= "{B94237E7-57AC-4347-9151-B08C6C32D1F7}" fullword wide
		 $s110= "{B97D20BB-F46A-4C97-BA10-5E3608430854}" fullword wide
		 $s111= "{C1E59364-35F6-44B3-AF0F-FCA934C4B252}" fullword wide
		 $s112= "{C1F1028F-D91A-43E8-A117-4F7CAFD7A041}" fullword wide
		 $s113= "{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}" fullword wide
		 $s114= "{C5ABBF53-E17F-4121-8900-86626FC2C973}" fullword wide
		 $s115= ".cab=application/vnd.ms-cab-compressed" fullword wide
		 $s116= ">@CEIKNPQSTVXablmnopqrstuvxz|}" fullword wide
		 $s117= "__crt_strtox::floating_point_value::as_double" fullword wide
		 $s118= "__crt_strtox::floating_point_value::as_float" fullword wide
		 $s119= "{D0384E7D-BAC3-4797-8F14-CBA229B392B5}" fullword wide
		 $s120= "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}" fullword wide
		 $s121= "{D9DC8A3B-B784-432E-A781-5A1130A75963}" fullword wide
		 $s122= "D:(D;;GA;;;NU)(A;;FA;;;SY)(A;;0x0012019b;;;WD)" fullword wide
		 $s123= "D:(D;;GA;;;NU)(A;;FA;;;SY)(A;;0x0012019f;;;WD)" fullword wide
		 $s124= "{DE974D24-D9C6-4D3E-BF91-F4455120B917}" fullword wide
		 $s125= "{DFDF76A2-C82A-4D63-906A-5644AC457385}" fullword wide
		 $s126= "{EA7564AC-C67D-4868-BE5C-26E4FC2223FF}" fullword wide
		 $s127= "{ED4824AF-DCE4-45A8-81E2-FC7965083634}" fullword wide
		 $s128= "{ED569DB3-58C4-4463-971F-4AAABB6440BD}" fullword wide
		 $s129= "{EECBA6B8-3A62-44AD-99EB-8666265466F9}" fullword wide
		 $s130= "Extended_UNIX_Code_Fixed_Width_for_Japanese" fullword wide
		 $s131= "Extended_UNIX_Code_Packed_Format_for_Japanese" fullword wide
		 $s132= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s133= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s134= "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}" fullword wide
		 $s135= "{F1B5AE30-CB00-4DCF-978B-07D33B034ADB}" fullword wide
		 $s136= "{F38BF404-1D43-42F2-9305-67DE0B28FC23}" fullword wide
		 $s137= "{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}" fullword wide
		 $s138= "{FAB10E66-B22C-4274-8647-7CA1BA5EF30F}" fullword wide
		 $s139= "{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}" fullword wide
		 $s140= "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}" fullword wide
		 $s141= ".fml=application/x-file-mirror-list" fullword wide
		 $s142= "GlobalCplShutdown-8D5475ED-3A12-4f45-9ACE-23289E49C0DF" fullword wide
		 $s143= "GRP_RID_INCOMING_FOREST_TRUST_BUILDERS" fullword wide
		 $s144= "HKLMSoftwareAdobeAcrobat Reader10.0InstallPath" fullword wide
		 $s145= "HKLMSoftwareAdobeAcrobat Reader11.0InstallPath" fullword wide
		 $s146= "HKLMSoftwareAdobeAcrobat Reader5.0InstallPath" fullword wide
		 $s147= "HKLMSoftwareAdobeAcrobat Reader6.0InstallPath" fullword wide
		 $s148= "HKLMSoftwareAdobeAcrobat Reader7.0InstallPath" fullword wide
		 $s149= "HKLMSoftwareAdobeAcrobat Reader8.0InstallPath" fullword wide
		 $s150= "HKLMSoftwareAdobeAcrobat Reader9.0InstallPath" fullword wide
		 $s151= "HKLMSOFTWAREJavaSoftJDKCurrentVersion" fullword wide
		 $s152= "HKLMSOFTWAREJavaSoftJRECurrentVersion" fullword wide
		 $s153= "HKLMSOFTWAREMicrosoftDirectXVersion" fullword wide
		 $s154= "HKLMSOFTWAREMicrosoft.NETFrameworkpolicyv1.03705" fullword wide
		 $s155= "HKLMSOFTWAREMicrosoftPowerShell1Install" fullword wide
		 $s156= "HKLMSOFTWAREMicrosoftXNAFrameworkv1.0NativeLibraryPath" fullword wide
		 $s157= "HKLMSOFTWAREMicrosoftXNAFrameworkv2.0NativeLibraryPath" fullword wide
		 $s158= "HKLMSOFTWAREMicrosoftXNAFrameworkv3.0NativeLibraryPath" fullword wide
		 $s159= "HKLMSOFTWAREMicrosoftXNAFrameworkv3.1NativeLibraryPath" fullword wide
		 $s160= "HKLMSOFTWAREMicrosoftXNAFrameworkv4.0NativeLibraryPath" fullword wide
		 $s161= "HKLMSYSTEMCurrentControlSetServicesW3SVCDisplayName" fullword wide
		 $s162= "IsThemeBackgroundPartiallyTransparent" fullword wide
		 $s163= ".kpr=application/vnd.kde.kpresenter" fullword wide
		 $s164= ".kpt=application/vnd.kde.kpresenter" fullword wide
		 $s165= "[LocalAppDataFolder]ProgramsCommon" fullword wide
		 $s166= "minkernelcrtsucrtinccorecrt_internal_strtox.h" fullword wide
		 $s167= ".mjf=audio/x-vnd.AudioExplosion.MjuiceMediaFile" fullword wide
		 $s168= ".odb=application/vnd.oasis.opendocument.database" fullword wide
		 $s169= ".odc=application/vnd.oasis.opendocument.chart" fullword wide
		 $s170= ".odf=application/vnd.oasis.opendocument.formula" fullword wide
		 $s171= ".odg=application/vnd.oasis.opendocument.graphics" fullword wide
		 $s172= ".odi=application/vnd.oasis.opendocument.image" fullword wide
		 $s173= ".odm=application/vnd.oasis.opendocument.text-master" fullword wide
		 $s174= ".odp=application/vnd.oasis.opendocument.presentation" fullword wide
		 $s175= ".ods=application/vnd.oasis.opendocument.spreadsheet" fullword wide
		 $s176= ".odt=application/vnd.oasis.opendocument.text" fullword wide
		 $s177= ".otg=application/vnd.oasis.opendocument.graphics-template" fullword wide
		 $s178= ".oth=application/vnd.oasis.opendocument.text-web" fullword wide
		 $s179= ".otp=application/vnd.oasis.opendocument.presentation-template" fullword wide
		 $s180= ".ots=application/vnd.oasis.opendocument.spreadsheet-template" fullword wide
		 $s181= ".ott=application/vnd.oasis.opendocument.text-template" fullword wide
		 $s182= ".p7b=application/x-pkcs7-certificates" fullword wide
		 $s183= ".p7r=application/x-pkcs7-certreqresp" fullword wide
		 $s184= ".package=application/vnd.autopackage" fullword wide
		 $s185= "PEM_read_bio_NETSCAPE_CERT_SEQUENCE" fullword wide
		 $s186= "PEM_write_bio_NETSCAPE_CERT_SEQUENCE" fullword wide
		 $s187= "[ProgramFiles64Folder]Microsoft OfficeOffice14vviewer.dll" fullword wide
		 $s188= "[ProgramFiles64Folder]Microsoft OfficeOffice15lync.exe" fullword wide
		 $s189= "[ProgramFiles64Folder]Microsoft OfficeOffice15vviewer.dll" fullword wide
		 $s190= "[ProgramFilesFolder]Microsoft OfficeOffice14vviewer.dll" fullword wide
		 $s191= "[ProgramFilesFolder]Microsoft OfficeOffice15lync.exe" fullword wide
		 $s192= "[ProgramFilesFolder]Microsoft OfficeOffice15vviewer.dll" fullword wide
		 $s193= ".rjs=application/vnd.rn-realsystem-rjs" fullword wide
		 $s194= ".rmp=application/vnd.rn-rn_music_package" fullword wide
		 $s195= ".rmx=application/vnd.rn-realsystem-rmx" fullword wide
		 $s196= ".rpm=application/x-redhat-package-manager" fullword wide
		 $s197= ".sda=application/vnd.stardivision.draw" fullword wide
		 $s198= ".sdc=application/vnd.stardivision.calc" fullword wide
		 $s199= ".sdd=application/vnd.stardivision.impress" fullword wide
		 $s200= ".ser=application/java-serialized-object" fullword wide
		 $s201= ".setpay=application/set-payment-initiation" fullword wide
		 $s202= ".setreg=application/set-registration-initiation" fullword wide
		 $s203= ".smf=application/vnd.stardivision.math" fullword wide
		 $s204= "SoftwareCaphyonAdvanced Installer" fullword wide
		 $s205= "SoftwareMicrosoftWindows NTCurrentVersion" fullword wide
		 $s206= "SOFTWAREMicrosoftWindows NTCurrentVersionFontSubstitutes" fullword wide
		 $s207= "SoftwareOracleSun RayClientInfoAgentDisconnectActions" fullword wide
		 $s208= "SoftwareOracleSun RayClientInfoAgentReconnectActions" fullword wide
		 $s209= "SSL_CTX_set_default_passwd_cb_userdata" fullword wide
		 $s210= ".sst=application/vnd.ms-pki.certstore" fullword wide
		 $s211= ".stc=application/vnd.sun.xml.calc.template" fullword wide
		 $s212= ".std=application/vnd.sun.xml.draw.template" fullword wide
		 $s213= ".sti=application/vnd.sun.xml.impress.template" fullword wide
		 $s214= ".stw=application/vnd.sun.xml.writer.template" fullword wide
		 $s215= ".swf1=application/x-shockwave-flash" fullword wide
		 $s216= ".sxg=application/vnd.sun.xml.writer.global" fullword wide
		 $s217= ".sxi=application/vnd.sun.xml.impress" fullword wide
		 $s218= ".sxw=application/vnd.sun.xml.writer" fullword wide
		 $s219= "SYSTEMCurrentControlSetControlKeyboard Layouts" fullword wide
		 $s220= "SystemCurrentControlSetControlKeyboard Layouts%.8x" fullword wide
		 $s221= "SYSTEMCurrentControlSetControlProductOptions" fullword wide
		 $s222= "SYSTEMCurrentControlSetControlSession Manager" fullword wide
		 $s223= ".tbz2=application/x-bzip-compressed-tar" fullword wide
		 $s224= ".tbz=application/x-bzip-compressed-tar" fullword wide
		 $s225= "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" fullword wide
		 $s226= ".tlz=application/x-lzma-compressed-tar" fullword wide
		 $s227= ".txz=application/x-xz-compressed-tar" fullword wide
		 $s228= ".vor=application/vnd.stardivision.writer" fullword wide
		 $s229= ".wmlsc=application/vnd.wap.wmlscriptc" fullword wide
		 $s230= ".xps=application/vnd.ms-xpsdocument" fullword wide
		 $s231= ".xul=application/vnd.mozilla.xul+xml" fullword wide
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
		 $hex35= {24733130303d202261}
		 $hex36= {24733130313d202261}
		 $hex37= {24733130323d202261}
		 $hex38= {24733130333d202261}
		 $hex39= {24733130343d202261}
		 $hex40= {24733130353d202261}
		 $hex41= {24733130363d20227b}
		 $hex42= {24733130373d20227b}
		 $hex43= {24733130383d20227b}
		 $hex44= {24733130393d20227b}
		 $hex45= {247331303d20227b31}
		 $hex46= {24733131303d20227b}
		 $hex47= {24733131313d20227b}
		 $hex48= {24733131323d20227b}
		 $hex49= {24733131333d20227b}
		 $hex50= {24733131343d20227b}
		 $hex51= {24733131353d20222e}
		 $hex52= {24733131363d20223e}
		 $hex53= {24733131373d20225f}
		 $hex54= {24733131383d20225f}
		 $hex55= {24733131393d20227b}
		 $hex56= {247331313d20227b31}
		 $hex57= {24733132303d20227b}
		 $hex58= {24733132313d20227b}
		 $hex59= {24733132323d202244}
		 $hex60= {24733132333d202244}
		 $hex61= {24733132343d20227b}
		 $hex62= {24733132353d20227b}
		 $hex63= {24733132363d20227b}
		 $hex64= {24733132373d20227b}
		 $hex65= {24733132383d20227b}
		 $hex66= {24733132393d20227b}
		 $hex67= {247331323d20227b31}
		 $hex68= {24733133303d202245}
		 $hex69= {24733133313d202245}
		 $hex70= {24733133323d202265}
		 $hex71= {24733133333d202265}
		 $hex72= {24733133343d20227b}
		 $hex73= {24733133353d20227b}
		 $hex74= {24733133363d20227b}
		 $hex75= {24733133373d20227b}
		 $hex76= {24733133383d20227b}
		 $hex77= {24733133393d20227b}
		 $hex78= {247331333d20227b31}
		 $hex79= {24733134303d20227b}
		 $hex80= {24733134313d20222e}
		 $hex81= {24733134323d202247}
		 $hex82= {24733134333d202247}
		 $hex83= {24733134343d202248}
		 $hex84= {24733134353d202248}
		 $hex85= {24733134363d202248}
		 $hex86= {24733134373d202248}
		 $hex87= {24733134383d202248}
		 $hex88= {24733134393d202248}
		 $hex89= {247331343d20227b31}
		 $hex90= {24733135303d202248}
		 $hex91= {24733135313d202248}
		 $hex92= {24733135323d202248}
		 $hex93= {24733135333d202248}
		 $hex94= {24733135343d202248}
		 $hex95= {24733135353d202248}
		 $hex96= {24733135363d202248}
		 $hex97= {24733135373d202248}
		 $hex98= {24733135383d202248}
		 $hex99= {24733135393d202248}
		 $hex100= {247331353d20227b32}
		 $hex101= {24733136303d202248}
		 $hex102= {24733136313d202248}
		 $hex103= {24733136323d202249}
		 $hex104= {24733136333d20222e}
		 $hex105= {24733136343d20222e}
		 $hex106= {24733136353d20225b}
		 $hex107= {24733136363d20226d}
		 $hex108= {24733136373d20222e}
		 $hex109= {24733136383d20222e}
		 $hex110= {24733136393d20222e}
		 $hex111= {247331363d20227b32}
		 $hex112= {24733137303d20222e}
		 $hex113= {24733137313d20222e}
		 $hex114= {24733137323d20222e}
		 $hex115= {24733137333d20222e}
		 $hex116= {24733137343d20222e}
		 $hex117= {24733137353d20222e}
		 $hex118= {24733137363d20222e}
		 $hex119= {24733137373d20222e}
		 $hex120= {24733137383d20222e}
		 $hex121= {24733137393d20222e}
		 $hex122= {247331373d20227b33}
		 $hex123= {24733138303d20222e}
		 $hex124= {24733138313d20222e}
		 $hex125= {24733138323d20222e}
		 $hex126= {24733138333d20222e}
		 $hex127= {24733138343d20222e}
		 $hex128= {24733138353d202250}
		 $hex129= {24733138363d202250}
		 $hex130= {24733138373d20225b}
		 $hex131= {24733138383d20225b}
		 $hex132= {24733138393d20225b}
		 $hex133= {247331383d20227b33}
		 $hex134= {24733139303d20225b}
		 $hex135= {24733139313d20225b}
		 $hex136= {24733139323d20225b}
		 $hex137= {24733139333d20222e}
		 $hex138= {24733139343d20222e}
		 $hex139= {24733139353d20222e}
		 $hex140= {24733139363d20222e}
		 $hex141= {24733139373d20222e}
		 $hex142= {24733139383d20222e}
		 $hex143= {24733139393d20222e}
		 $hex144= {247331393d20227b33}
		 $hex145= {2473313d20222b2425}
		 $hex146= {24733230303d20222e}
		 $hex147= {24733230313d20222e}
		 $hex148= {24733230323d20222e}
		 $hex149= {24733230333d20222e}
		 $hex150= {24733230343d202253}
		 $hex151= {24733230353d202253}
		 $hex152= {24733230363d202253}
		 $hex153= {24733230373d202253}
		 $hex154= {24733230383d202253}
		 $hex155= {24733230393d202253}
		 $hex156= {247332303d20227b33}
		 $hex157= {24733231303d20222e}
		 $hex158= {24733231313d20222e}
		 $hex159= {24733231323d20222e}
		 $hex160= {24733231333d20222e}
		 $hex161= {24733231343d20222e}
		 $hex162= {24733231353d20222e}
		 $hex163= {24733231363d20222e}
		 $hex164= {24733231373d20222e}
		 $hex165= {24733231383d20222e}
		 $hex166= {24733231393d202253}
		 $hex167= {247332313d20227b33}
		 $hex168= {24733232303d202253}
		 $hex169= {24733232313d202253}
		 $hex170= {24733232323d202253}
		 $hex171= {24733232333d20222e}
		 $hex172= {24733232343d20222e}
		 $hex173= {24733232353d202274}
		 $hex174= {24733232363d20222e}
		 $hex175= {24733232373d20222e}
		 $hex176= {24733232383d20222e}
		 $hex177= {24733232393d20222e}
		 $hex178= {247332323d20227b33}
		 $hex179= {24733233303d20222e}
		 $hex180= {24733233313d20222e}
		 $hex181= {247332333d20227b34}
		 $hex182= {247332343d20227b34}
		 $hex183= {247332353d20227b34}
		 $hex184= {247332363d20227b35}
		 $hex185= {247332373d20227b35}
		 $hex186= {247332383d20227b35}
		 $hex187= {247332393d20227b36}
		 $hex188= {2473323d20227b3030}
		 $hex189= {247333303d20227b36}
		 $hex190= {247333313d20227b36}
		 $hex191= {247333323d20227b36}
		 $hex192= {247333333d20227b37}
		 $hex193= {247333343d20227b37}
		 $hex194= {247333353d20227b38}
		 $hex195= {247333363d20227b38}
		 $hex196= {247333373d20227b38}
		 $hex197= {247333383d20227b38}
		 $hex198= {247333393d20227b38}
		 $hex199= {2473333d20227b3031}
		 $hex200= {247334303d20227b38}
		 $hex201= {247334313d20227b39}
		 $hex202= {247334323d20227b39}
		 $hex203= {247334333d20227b39}
		 $hex204= {247334343d20227b39}
		 $hex205= {247334353d20227b41}
		 $hex206= {247334363d20227b41}
		 $hex207= {247334373d20227b41}
		 $hex208= {247334383d20227b41}
		 $hex209= {247334393d20227b41}
		 $hex210= {2473343d20227b3031}
		 $hex211= {247335303d20227b41}
		 $hex212= {247335313d20224149}
		 $hex213= {247335323d20224149}
		 $hex214= {247335333d20224149}
		 $hex215= {247335343d20224149}
		 $hex216= {247335353d20224149}
		 $hex217= {247335363d20224149}
		 $hex218= {247335373d20224149}
		 $hex219= {247335383d20224149}
		 $hex220= {247335393d20224149}
		 $hex221= {2473353d20222a2a2b}
		 $hex222= {247336303d20224149}
		 $hex223= {247336313d20224149}
		 $hex224= {247336323d20224149}
		 $hex225= {247336333d20224149}
		 $hex226= {247336343d20224149}
		 $hex227= {247336353d20224149}
		 $hex228= {247336363d20224149}
		 $hex229= {247336373d20224149}
		 $hex230= {247336383d20224149}
		 $hex231= {247336393d20224149}
		 $hex232= {2473363d20227b3034}
		 $hex233= {247337303d20224149}
		 $hex234= {247337313d20224149}
		 $hex235= {247337323d20224149}
		 $hex236= {247337333d20224149}
		 $hex237= {247337343d20224149}
		 $hex238= {247337353d20224149}
		 $hex239= {247337363d20224149}
		 $hex240= {247337373d20224149}
		 $hex241= {247337383d20224149}
		 $hex242= {247337393d20224149}
		 $hex243= {2473373d20227b3134}
		 $hex244= {247338303d20224149}
		 $hex245= {247338313d20224149}
		 $hex246= {247338323d20224149}
		 $hex247= {247338333d20224149}
		 $hex248= {247338343d20224149}
		 $hex249= {247338353d20224149}
		 $hex250= {247338363d20224149}
		 $hex251= {247338373d20224149}
		 $hex252= {247338383d20224149}
		 $hex253= {247338393d20224149}
		 $hex254= {2473383d20227b3137}
		 $hex255= {247339303d20224149}
		 $hex256= {247339313d20224149}
		 $hex257= {247339323d20224149}
		 $hex258= {247339333d20224149}
		 $hex259= {247339343d20224149}
		 $hex260= {247339353d20224149}
		 $hex261= {247339363d20224149}
		 $hex262= {247339373d20224149}
		 $hex263= {247339383d20224149}
		 $hex264= {247339393d20224149}
		 $hex265= {2473393d20227b3138}

	condition:
		33 of them
}
