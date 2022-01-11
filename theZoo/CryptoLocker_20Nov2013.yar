
/*
   YARA Rule Set
   Author: resteex
   Identifier: CryptoLocker_20Nov2013 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_CryptoLocker_20Nov2013 {
	meta: 
		 description= "CryptoLocker_20Nov2013 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-25-44" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "7f9c454a2e016e533e181d53eba113bc"

	strings:

	
 		 $s1= "accDefaultAction" fullword wide
		 $s2= "accDoDefaultAction" fullword wide
		 $s3= "accKeyboardShortcut" fullword wide
		 $s4= "Bronto Software" fullword wide
		 $s5= "(c) Bronto Software" fullword wide
		 $s6= "FileDescription" fullword wide
		 $s7= "OriginalFilename" fullword wide
		 $s8= "temperatureSid.exe" fullword wide
		 $s9= "VS_VERSION_INFO" fullword wide
		 $a1= "abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a2= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" fullword ascii
		 $a3= ".?AV?$CMFCComObject@VCAccessibleProxy@ATL@@@@" fullword ascii
		 $a4= ".?AV?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@" fullword ascii
		 $a5= ".?AV_AFX_BASE_MODULE_STATE@@" fullword ascii
		 $a6= ".?AV_AFX_HTMLHELP_STATE@@" fullword ascii
		 $a7= ".?AVAFX_MODULE_THREAD_STATE@@" fullword ascii
		 $a8= ".?AVCAccessibleProxy@ATL@@" fullword ascii
		 $a9= ".?AVCDllIsolationWrapperBase@@" fullword ascii
		 $a10= ".?AVCInvalidArgException@@" fullword ascii
		 $a11= ".?AVCNotSupportedException@@" fullword ascii
		 $a12= ".?AVXAccessibleServer@CWnd@@" fullword ascii
		 $a13= "CreateDialogIndirectParamA" fullword ascii
		 $a14= "CreateStdAccessibleObject" fullword ascii
		 $a15= "f:ddvctoolsvc7libsshipatlmfcincludeafxwin1.inl" fullword ascii
		 $a16= "f:ddvctoolsvc7libsshipatlmfcincludeafxwin2.inl" fullword ascii
		 $a17= "f:ddvctoolsvc7libsshipatlmfcsrcmfcauxdata.cpp" fullword ascii
		 $a18= "GAIsProcessorFeaturePresent" fullword ascii
		 $a19= "GetMenuCheckMarkDimensions" fullword ascii
		 $a20= "GetUserObjectInformationA" fullword ascii
		 $a21= "InitializeCriticalSection" fullword ascii
		 $a22= "InitializeCriticalSectionAndSpinCount" fullword ascii
		 $a23= "JanFebMarAprMayJunJulAugSepOctNovDec" fullword ascii
		 $a24= ".PAVCInvalidArgException@@" fullword ascii
		 $a25= "SetUnhandledExceptionFilter" fullword ascii

		 $hex1= {246131303d20222e3f}
		 $hex2= {246131313d20222e3f}
		 $hex3= {246131323d20222e3f}
		 $hex4= {246131333d20224372}
		 $hex5= {246131343d20224372}
		 $hex6= {246131353d2022663a}
		 $hex7= {246131363d2022663a}
		 $hex8= {246131373d2022663a}
		 $hex9= {246131383d20224741}
		 $hex10= {246131393d20224765}
		 $hex11= {2461313d2022616263}
		 $hex12= {246132303d20224765}
		 $hex13= {246132313d2022496e}
		 $hex14= {246132323d2022496e}
		 $hex15= {246132333d20224a61}
		 $hex16= {246132343d20222e50}
		 $hex17= {246132353d20225365}
		 $hex18= {2461323d2022414243}
		 $hex19= {2461333d20222e3f41}
		 $hex20= {2461343d20222e3f41}
		 $hex21= {2461353d20222e3f41}
		 $hex22= {2461363d20222e3f41}
		 $hex23= {2461373d20222e3f41}
		 $hex24= {2461383d20222e3f41}
		 $hex25= {2461393d20222e3f41}
		 $hex26= {2473313d2022616363}
		 $hex27= {2473323d2022616363}
		 $hex28= {2473333d2022616363}
		 $hex29= {2473343d202242726f}
		 $hex30= {2473353d2022286329}
		 $hex31= {2473363d202246696c}
		 $hex32= {2473373d20224f7269}
		 $hex33= {2473383d202274656d}
		 $hex34= {2473393d202256535f}

	condition:
		4 of them
}
