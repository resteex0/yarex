
/*
   YARA Rule Set
   Author: resteex
   Identifier: Trojan_Ransom_Petya 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Trojan_Ransom_Petya {
	meta: 
		 description= "Trojan_Ransom_Petya Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-30-48" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "8ed9a60127aee45336102bf12059a850"

	strings:

	
 		 $s1= "A bad service request was received by the Machine Debug Manager service." fullword wide
		 $s2= "An error occurred while the debugger attempted to correct its registry." fullword wide
		 $s3= "An exception occurred. Process will be terminated." fullword wide
		 $s4= "A previous script debugger was installed, which unregistered 7.0 debugger components. The 7.0 compon" fullword wide
		 $s5= "binmscordmp.exe" fullword wide
		 $s6= "Copyright (C) Microsoft Corporation 1987-2002. All rights reserved." fullword wide
		 $s7= "DbgJITDebugLaunchSetting %s" fullword wide
		 $s8= "DbgManagedDebugger %s" fullword wide
		 $s9= "Debugger Users are non administrators who are allowed to use Visual Studio to debug processes, both " fullword wide
		 $s10= "+Driver '%s' doesn't support sql debugging." fullword wide
		 $s11= "/dumpjit: display current JIT (just-in-time) debugging settings" fullword wide
		 $s12= "ed, the debuggers will not function properly." fullword wide
		 $s13= "ents have been reregistered. " fullword wide
		 $s14= "FileDescription" fullword wide
		 $s15= "InprocServer32" fullword wide
		 $s16= "JIT Debug settings:" fullword wide
		 $s17= "locally and remotely. Only trusted users should be added to this group" fullword wide
		 $s18= "Machine Debug Manager" fullword wide
		 $s19= "Microsoft Corporation" fullword wide
		 $s20= "Microsoft (R) Machine Debug Manager (MDM)" fullword wide
		 $s21= "Microsoft Visual Studio Debugger" fullword wide
		 $s22= ".NET application" fullword wide
		 $s23= "OriginalFilename" fullword wide
		 $s24= "PrevDbgJITDebugLaunchSetting %s" fullword wide
		 $s25= "PrevDbgManagedDebugger %s" fullword wide
		 $s26= "PreVisualStudio7Auto %s" fullword wide
		 $s27= "PreVisualStudio7Debugger %s" fullword wide
		 $s28= "Remote Just-In-Time Debugging*The timeout value must be greater than %s.'The timeout value must be l" fullword wide
		 $s29= "SOFTWAREMicrosoft.NETFramework" fullword wide
		 $s30= "Supports local and remote debugging for Visual Studio and script debuggers. If this service is stopp" fullword wide
		 $s31= "The Machine Debug Manager service could not be installed." fullword wide
		 $s32= "The Machine Debug Manager service could not be uninstalled." fullword wide
		 $s33= "The Machine Debug Manager service is not installed properly. Please reinstall debugging services." fullword wide
		 $s34= "The timeout value is invalid." fullword wide
		 $s35= "Unable to load driver '%s'." fullword wide
		 $s36= "Unknown Win32 debugger" fullword wide
		 $s37= "usage: mdm [option]" fullword wide
		 $s38= "Visual Studio .NET" fullword wide
		 $s39= "VS_VERSION_INFO" fullword wide
		 $s40= "Win64 Microsoft Visual Studio DebuggerCAn unhandled exception has been caught by the VSW exception f" fullword wide
		 $a1= "b88c2344-30cb-11d3-b97b-00c04f6859ed" fullword ascii
		 $a2= "clsid{834128A2-51F4-11D0-8F20-00805F2CD064}LocalServer32" fullword ascii
		 $a3= "GetPrivateProfileSectionA" fullword ascii
		 $a4= "GetPrivateProfileSectionNamesA" fullword ascii
		 $a5= "GetSecurityDescriptorControl" fullword ascii
		 $a6= "GetSecurityDescriptorDacl" fullword ascii
		 $a7= "GetSecurityDescriptorGroup" fullword ascii
		 $a8= "GetSecurityDescriptorLength" fullword ascii
		 $a9= "GetSecurityDescriptorOwner" fullword ascii
		 $a10= "GetSecurityDescriptorSacl" fullword ascii
		 $a11= "GetUserObjectInformationA" fullword ascii
		 $a12= "InitializeCriticalSection" fullword ascii
		 $a13= "InitializeCriticalSectionAndSpinCount" fullword ascii
		 $a14= "InitializeSecurityDescriptor" fullword ascii
		 $a15= "InterlockedCompareExchange" fullword ascii
		 $a16= "IsValidSecurityDescriptor" fullword ascii
		 $a17= "I:VS70Builds3077vsbuiltretailBini386optmdm.pdb" fullword ascii
		 $a18= "n-6/oE='n}=?nU=wnM=One=Gnu=" fullword ascii
		 $a19= "RegisterServiceCtrlHandlerA" fullword ascii
		 $a20= "RpcBindingFromStringBindingA" fullword ascii
		 $a21= "s-3/lE6'o}6?oU6woM6Ooe6Go" fullword ascii
		 $a22= "%sDebuggerManagedDebuggeePIDs_%i" fullword ascii
		 $a23= "SetSecurityDescriptorDacl" fullword ascii
		 $a24= "SetSecurityDescriptorGroup" fullword ascii
		 $a25= "SetSecurityDescriptorOwner" fullword ascii
		 $a26= "SetSecurityDescriptorSacl" fullword ascii
		 $a27= "SetUnhandledExceptionFilter" fullword ascii
		 $a28= "SHGetSpecialFolderLocation" fullword ascii
		 $a29= "SoftwareClassesCLSID%sLocalServer32" fullword ascii
		 $a30= "SOFTWAREMicrosoft.NETFramework" fullword ascii
		 $a31= "SoftwareMicrosoftVisualStudio7.1" fullword ascii
		 $a32= "SoftwareMicrosoftVisualStudio7.1Debugger" fullword ascii
		 $a33= "StartServiceCtrlDispatcherA" fullword ascii
		 $a34= "WritePrivateProfileStringA" fullword ascii
		 $a35= "zInterface%sProxyStubClsid32" fullword ascii

		 $hex1= {246131303d20224765}
		 $hex2= {246131313d20224765}
		 $hex3= {246131323d2022496e}
		 $hex4= {246131333d2022496e}
		 $hex5= {246131343d2022496e}
		 $hex6= {246131353d2022496e}
		 $hex7= {246131363d20224973}
		 $hex8= {246131373d2022493a}
		 $hex9= {246131383d20226e2d}
		 $hex10= {246131393d20225265}
		 $hex11= {2461313d2022623838}
		 $hex12= {246132303d20225270}
		 $hex13= {246132313d2022732d}
		 $hex14= {246132323d20222573}
		 $hex15= {246132333d20225365}
		 $hex16= {246132343d20225365}
		 $hex17= {246132353d20225365}
		 $hex18= {246132363d20225365}
		 $hex19= {246132373d20225365}
		 $hex20= {246132383d20225348}
		 $hex21= {246132393d2022536f}
		 $hex22= {2461323d2022636c73}
		 $hex23= {246133303d2022534f}
		 $hex24= {246133313d2022536f}
		 $hex25= {246133323d2022536f}
		 $hex26= {246133333d20225374}
		 $hex27= {246133343d20225772}
		 $hex28= {246133353d20227a49}
		 $hex29= {2461333d2022476574}
		 $hex30= {2461343d2022476574}
		 $hex31= {2461353d2022476574}
		 $hex32= {2461363d2022476574}
		 $hex33= {2461373d2022476574}
		 $hex34= {2461383d2022476574}
		 $hex35= {2461393d2022476574}
		 $hex36= {247331303d20222b44}
		 $hex37= {247331313d20222f64}
		 $hex38= {247331323d20226564}
		 $hex39= {247331333d2022656e}
		 $hex40= {247331343d20224669}
		 $hex41= {247331353d2022496e}
		 $hex42= {247331363d20224a49}
		 $hex43= {247331373d20226c6f}
		 $hex44= {247331383d20224d61}
		 $hex45= {247331393d20224d69}
		 $hex46= {2473313d2022412062}
		 $hex47= {247332303d20224d69}
		 $hex48= {247332313d20224d69}
		 $hex49= {247332323d20222e4e}
		 $hex50= {247332333d20224f72}
		 $hex51= {247332343d20225072}
		 $hex52= {247332353d20225072}
		 $hex53= {247332363d20225072}
		 $hex54= {247332373d20225072}
		 $hex55= {247332383d20225265}
		 $hex56= {247332393d2022534f}
		 $hex57= {2473323d2022416e20}
		 $hex58= {247333303d20225375}
		 $hex59= {247333313d20225468}
		 $hex60= {247333323d20225468}
		 $hex61= {247333333d20225468}
		 $hex62= {247333343d20225468}
		 $hex63= {247333353d2022556e}
		 $hex64= {247333363d2022556e}
		 $hex65= {247333373d20227573}
		 $hex66= {247333383d20225669}
		 $hex67= {247333393d20225653}
		 $hex68= {2473333d2022416e20}
		 $hex69= {247334303d20225769}
		 $hex70= {2473343d2022412070}
		 $hex71= {2473353d202262696e}
		 $hex72= {2473363d2022436f70}
		 $hex73= {2473373d2022446267}
		 $hex74= {2473383d2022446267}
		 $hex75= {2473393d2022446562}

	condition:
		9 of them
}
