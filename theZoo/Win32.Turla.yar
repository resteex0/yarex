
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Turla 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Turla {
	meta: 
		 description= "Win32_Turla Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-34-53" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2b47ad7df9902aaa19474723064ee76f"
		 hash2= "3c1a8991e96f4c56ae3e90fb6f0ae679"
		 hash3= "5f8f3cf46719afa7eb5f761cdd18b63d"
		 hash4= "aac56baff4be3db02378f11b9844dcb5"
		 hash5= "b46c792c8e051bc5c9d4cecab96e4c30"
		 hash6= "f57c84e22e9e6eaa6cbd9730d7c652dc"

	strings:

	
 		 $s1= "{a1d3d2d3-af20-4317-903f-78271c44b294}" fullword wide
		 $s2= "apisetschema.dll" fullword wide
		 $s3= "Microsoft Windows Server 2003" fullword wide
		 $s4= "Microsoft Windows XP" fullword wide
		 $s5= "REGISTRYMACHINESoftwareMicrosoftWindows NTCurrentVersion" fullword wide
		 $s6= "SeShutdownPrivilege" fullword wide
		 $s7= "tapisetschema.dll" fullword wide
		 $s8= "Windows Server (R) 2008" fullword wide
		 $s9= "Windows Vista (TM) Ultimate" fullword wide
		 $a1= "0123456789abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a2= "2%2,212;2C2O2U2^2e2k2t2{2" fullword ascii
		 $a3= "3@3D3H3L3P3T3X33`3d3h3l3" fullword ascii
		 $a4= "4D5L5P5T5X55`5d5h5l5p5t5x5|5" fullword ascii
		 $a5= "6@6D6H6L6P6T6X66`6d6h6l6p6t6x6|6" fullword ascii
		 $a6= "7@7D7H7L7P7T7X77`7d7h7p7t7x7|7" fullword ascii
		 $a7= "abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a8= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" fullword ascii
		 $a9= "application/vnd.ms-powerpoint" fullword ascii
		 $a10= "application/x-shockwave-flash" fullword ascii
		 $a11= "CO ti=%u st=%d so=%x ad=%s po=%u" fullword ascii
		 $a12= ";,;@;D;H;L;P;T;X;;`;d;h;l;p;t;x;|;" fullword ascii
		 $a13= "DisableThreadLibraryCalls" fullword ascii
		 $a14= "ExpandEnvironmentStringsW" fullword ascii
		 $a15= "FK ti=%u st=%d so=%x id=%u fl=%x bu=" fullword ascii
		 $a16= "GetFileInformationByHandle" fullword ascii
		 $a17= "GetUserObjectInformationA" fullword ascii
		 $a18= "Global{B93DFED5-9A3B-459b-A617-59FD9FAD693E}" fullword ascii
		 $a19= "Global{c2b99b50-5bf2-4c81-90d3-6c6c82ba5111}" fullword ascii
		 $a20= "ImpersonateNamedPipeClient" fullword ascii
		 $a21= "InitializeCriticalSection" fullword ascii
		 $a22= "InitializeCriticalSectionAndSpinCount" fullword ascii
		 $a23= "InitializeSecurityDescriptor" fullword ascii
		 $a24= "InterlockedCompareExchange" fullword ascii
		 $a25= "InternetQueryDataAvailable" fullword ascii
		 $a26= "InternetSetStatusCallback" fullword ascii
		 $a27= "JanFebMarAprMayJunJulAugSepOctNovDec" fullword ascii
		 $a28= "..libsceopensslcryptlib.c" fullword ascii
		 $a29= "..libsceopenssldhdh_lib.c" fullword ascii
		 $a30= "R2 ti=%u st=%d so=%x id=%u fl=%x si=%d da=" fullword ascii
		 $a31= "SetSecurityDescriptorDacl" fullword ascii
		 $a32= "SetSecurityDescriptorSacl" fullword ascii
		 $a33= "SetUnhandledExceptionFilter" fullword ascii
		 $a34= "tc_write_request_pipe_bufs" fullword ascii
		 $a35= "WR ti=%u st=%d so=%x id=%u fl=%x si=%d da=" fullword ascii
		 $a36= "ZwQueryInformationProcess" fullword ascii

		 $hex1= {246131303d20226170}
		 $hex2= {246131313d2022434f}
		 $hex3= {246131323d20223b2c}
		 $hex4= {246131333d20224469}
		 $hex5= {246131343d20224578}
		 $hex6= {246131353d2022464b}
		 $hex7= {246131363d20224765}
		 $hex8= {246131373d20224765}
		 $hex9= {246131383d2022476c}
		 $hex10= {246131393d2022476c}
		 $hex11= {2461313d2022303132}
		 $hex12= {246132303d2022496d}
		 $hex13= {246132313d2022496e}
		 $hex14= {246132323d2022496e}
		 $hex15= {246132333d2022496e}
		 $hex16= {246132343d2022496e}
		 $hex17= {246132353d2022496e}
		 $hex18= {246132363d2022496e}
		 $hex19= {246132373d20224a61}
		 $hex20= {246132383d20222e2e}
		 $hex21= {246132393d20222e2e}
		 $hex22= {2461323d2022322532}
		 $hex23= {246133303d20225232}
		 $hex24= {246133313d20225365}
		 $hex25= {246133323d20225365}
		 $hex26= {246133333d20225365}
		 $hex27= {246133343d20227463}
		 $hex28= {246133353d20225752}
		 $hex29= {246133363d20225a77}
		 $hex30= {2461333d2022334033}
		 $hex31= {2461343d2022344435}
		 $hex32= {2461353d2022364036}
		 $hex33= {2461363d2022374037}
		 $hex34= {2461373d2022616263}
		 $hex35= {2461383d2022414243}
		 $hex36= {2461393d2022617070}
		 $hex37= {2473313d20227b6131}
		 $hex38= {2473323d2022617069}
		 $hex39= {2473333d20224d6963}
		 $hex40= {2473343d20224d6963}
		 $hex41= {2473353d2022524547}
		 $hex42= {2473363d2022536553}
		 $hex43= {2473373d2022746170}
		 $hex44= {2473383d202257696e}
		 $hex45= {2473393d202257696e}

	condition:
		5 of them
}
