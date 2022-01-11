
/*
   YARA Rule Set
   Author: resteex
   Identifier: ZeusGameover_Feb2014 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_ZeusGameover_Feb2014 {
	meta: 
		 description= "ZeusGameover_Feb2014 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-36-12" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "19c68862d3a53ea1746180b40bf32226"
		 hash2= "7bc463a32d6c0fb888cd76cc07ee69b5"
		 hash3= "7fe11cfcd7c66f7727cfc4613e755389"
		 hash4= "b227e7c0d9995715f331592750d6ebc2"

	strings:

	
 		 $s1= "2q3wet Corporation" fullword wide
		 $s2= "2q3wet(R) Windows (R) 2000 Operating System" fullword wide
		 $s3= "&About Task Manager" fullword wide
		 $s4= "AVarFileInfoTranslation" fullword wide
		 $s5= "&Bring To Front" fullword wide
		 $s6= "CiceroUIWndFrame" fullword wide
		 $s7= "CLnnD{289228DE-A31E-11D1-A19C-0000F875B132}Version" fullword wide
		 $s8= "Commit Charge (K)" fullword wide
		 $s9= "ConsoleWindowClass" fullword wide
		 $s10= "Copyright (C) 2q3wet Corp. 1991-1999" fullword wide
		 $s11= "CPU Usage Display" fullword wide
		 $s12= "CPU Usage History" fullword wide
		 $s13= "CSeTcbPrivilege" fullword wide
		 $s14= "DavesFrameClass" fullword wide
		 $s15= "DrT1qjyuU1zyrdtBDZ8IEcA0PzoCWbJU9pMiKY6" fullword wide
		 $s16= "End Process &Tree" fullword wide
		 $s17= "E&xit Task Manager" fullword wide
		 $s18= "FileDescription" fullword wide
		 $s19= "Gsystem32cGcript.Gxe" fullword wide
		 $s20= "&Hide When Minimized" fullword wide
		 $s21= "Kernel Memory (K)" fullword wide
		 $s22= "Memory Usage Display" fullword wide
		 $s23= "Memory Usage History" fullword wide
		 $s24= "&Minimize On Use" fullword wide
		 $s25= "&New Task (Run..)" fullword wide
		 $s26= "&New Task (Run...)" fullword wide
		 $s27= "New Task (&Run...)" fullword wide
		 $s28= "&One Graph, All CPUs" fullword wide
		 $s29= "One Graph &Per CPU" fullword wide
		 $s30= "OriginalFilename" fullword wide
		 $s31= "Physical Memory (K)" fullword wide
		 $s32= "ProfileImagePath" fullword wide
		 $s33= "&Select Columns..." fullword wide
		 $s34= "SeSecurityPrivilege" fullword wide
		 $s35= "SeShutdownPrivilege" fullword wide
		 $s36= "Set &Affinity..." fullword wide
		 $s37= "&Show 16-bit tasks" fullword wide
		 $s38= "&Show Kernel Times" fullword wide
		 $s39= "&Show processes from all users" fullword wide
		 $s40= "S:(ML;CIOI;NRNWNX;;;LW)" fullword wide
		 $s41= "S:(ML;;NRNWNX;;;LW)" fullword wide
		 $s42= "SOFTWAREMicrosoftWindows NTCurrentVersionProfileList%s" fullword wide
		 $s43= "StringFileInfo%04x%04x%s" fullword wide
		 $s44= "SysTabControl32" fullword wide
		 $s45= "Task Manager &Help Topics" fullword wide
		 $s46= "Tile &Horizontally" fullword wide
		 $s47= "Tile &Vertically" fullword wide
		 $s48= "VS_VERSION_INFO" fullword wide
		 $s49= "Windows TaskManager" fullword wide
		 $a1= "|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[]^_`abcdefghijklmnopq" fullword ascii
		 $a2= ";$;);1;7;>;D;K;Q;X;^;g;l;};" fullword ascii
		 $a3= ">$>)>.>3>8>=>B>G>L>Q>V>]>b>p>u>}>" fullword ascii
		 $a4= ":$:):.:3:8:=:B:G:L:Q:V:[:`:e:j:o:t:y:~:" fullword ascii
		 $a5= "0!2S2F5J5N5R5V5Z5^5b5f5j5n5r5v5z5~5" fullword ascii
		 $a6= "3*3B3F3J3N3R3V3Z3^3b3f3j3n3r3v3z3~3e4r9" fullword ascii
		 $a7= "?#?'?+?/?3?7?;???C?G?K?O?S?W?[?_?c?" fullword ascii
		 $a8= "=#='=+=/=3=7=;=?=C=G=K=O=S=W=[=_=c=g=k=o=s=w={=" fullword ascii
		 $a9= "7$747D7P7T7X77`7d7h7l7p7t7x7|7" fullword ascii
		 $a10= "7P7T7X77`7d7h7l7p7t7x7|7" fullword ascii
		 $a11= "9d:j:&;,;2;8;>;D;K;R;Y;`;g;n;u;};" fullword ascii
		 $a12= "A,$$@fst8Zwx4n{$95$$I5>?-WBC)KFG" fullword ascii
		 $a13= "^_`abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a14= "abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a15= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" fullword ascii
		 $a16= "AVEAVFPFhuxlkzir_cmobjq*9&9R|iyFZ^VEkVTYPMI" fullword ascii
		 $a17= "bcdfghjklmnpqrstvwxzaeiouy" fullword ascii
		 $a18= "CertDeleteCertificateFromStore" fullword ascii
		 $a19= "CertDuplicateCertificateContext" fullword ascii
		 $a20= "CertEnumCertificatesInStore" fullword ascii
		 $a21= "ConvertStringSecurityDescriptorToSecurityDescriptorW" fullword ascii
		 $a22= ">@>D>H>L>P>T>X>>`>d>h>l>p>t>" fullword ascii
		 $a23= ">!>'>->;>D>K>Q>c>g>m>u>{>" fullword ascii
		 $a24= "ExpandEnvironmentStringsW" fullword ascii
		 $a25= "{FL_[LJ|lK@VJUH^MflUSZPGB" fullword ascii
		 $a26= "GdipCreateBitmapFromHBITMAP" fullword ascii
		 $a27= "GetFileInformationByHandle" fullword ascii
		 $a28= "GetFileInformationByHandleEx" fullword ascii
		 $a29= "GetSecurityDescriptorSacl" fullword ascii
		 $a30= "GetSystemDefaultUILanguage" fullword ascii
		 $a31= "GetUserObjectInformationW" fullword ascii
		 $a32= "GetVolumeNameForVolumeMountPointW" fullword ascii
		 $a33= "HPE_INVALID_CONTENT_LENGTH" fullword ascii
		 $a34= "HPE_INVALID_INTERNAL_STATE" fullword ascii
		 $a35= "InitializeCriticalSection" fullword ascii
		 $a36= "InitializeSecurityDescriptor" fullword ascii
		 $a37= "InitiateSystemShutdownExW" fullword ascii
		 $a38= "InternetQueryDataAvailable" fullword ascii
		 $a39= "InternetSetStatusCallbackA" fullword ascii
		 $a40= "InternetSetStatusCallbackW" fullword ascii
		 $a41= "Kv|ok|lzL{pfzexn}VBbyk}ndv#A}vkWK_I`mLVFPQJ" fullword ascii
		 $a42= "LI UL= ULA EL5 EL9 UL- UL" fullword ascii
		 $a43= "MsgWaitForMultipleObjects" fullword ascii
		 $a44= "NtQueryInformationProcess" fullword ascii
		 $a45= "REOGFP',)NYE@,N`eyE{gadFkw" fullword ascii
		 $a46= "SetFileInformationByHandle" fullword ascii
		 $a47= "SetSecurityDescriptorDacl" fullword ascii
		 $a48= "SetSecurityDescriptorSacl" fullword ascii
		 $a49= "SetUnhandledExceptionFilter" fullword ascii
		 $a50= "SHGetSpecialFolderLocation" fullword ascii
		 $a51= "tb~a|jyRXagndsv&Kiwg#qWS" fullword ascii
		 $a52= "]t{rpz{bta`Wzz{mj~bcc!Jm`koEabu]JI`" fullword ascii
		 $a53= "VugVprvculNixnOlnfjn`@ntlk" fullword ascii
		 $a54= "WTSGetActiveConsoleSessionId" fullword ascii

		 $hex1= {246131303d20223750}
		 $hex2= {246131313d20223964}
		 $hex3= {246131323d2022412c}
		 $hex4= {246131333d20225e5f}
		 $hex5= {246131343d20226162}
		 $hex6= {246131353d20224142}
		 $hex7= {246131363d20224156}
		 $hex8= {246131373d20226263}
		 $hex9= {246131383d20224365}
		 $hex10= {246131393d20224365}
		 $hex11= {2461313d20227c2424}
		 $hex12= {246132303d20224365}
		 $hex13= {246132313d2022436f}
		 $hex14= {246132323d20223e40}
		 $hex15= {246132333d20223e21}
		 $hex16= {246132343d20224578}
		 $hex17= {246132353d20227b46}
		 $hex18= {246132363d20224764}
		 $hex19= {246132373d20224765}
		 $hex20= {246132383d20224765}
		 $hex21= {246132393d20224765}
		 $hex22= {2461323d20223b243b}
		 $hex23= {246133303d20224765}
		 $hex24= {246133313d20224765}
		 $hex25= {246133323d20224765}
		 $hex26= {246133333d20224850}
		 $hex27= {246133343d20224850}
		 $hex28= {246133353d2022496e}
		 $hex29= {246133363d2022496e}
		 $hex30= {246133373d2022496e}
		 $hex31= {246133383d2022496e}
		 $hex32= {246133393d2022496e}
		 $hex33= {2461333d20223e243e}
		 $hex34= {246134303d2022496e}
		 $hex35= {246134313d20224b76}
		 $hex36= {246134323d20224c49}
		 $hex37= {246134333d20224d73}
		 $hex38= {246134343d20224e74}
		 $hex39= {246134353d20225245}
		 $hex40= {246134363d20225365}
		 $hex41= {246134373d20225365}
		 $hex42= {246134383d20225365}
		 $hex43= {246134393d20225365}
		 $hex44= {2461343d20223a243a}
		 $hex45= {246135303d20225348}
		 $hex46= {246135313d20227462}
		 $hex47= {246135323d20225d74}
		 $hex48= {246135333d20225675}
		 $hex49= {246135343d20225754}
		 $hex50= {2461353d2022302132}
		 $hex51= {2461363d2022332a33}
		 $hex52= {2461373d20223f233f}
		 $hex53= {2461383d20223d233d}
		 $hex54= {2461393d2022372437}
		 $hex55= {247331303d2022436f}
		 $hex56= {247331313d20224350}
		 $hex57= {247331323d20224350}
		 $hex58= {247331333d20224353}
		 $hex59= {247331343d20224461}
		 $hex60= {247331353d20224472}
		 $hex61= {247331363d2022456e}
		 $hex62= {247331373d20224526}
		 $hex63= {247331383d20224669}
		 $hex64= {247331393d20224773}
		 $hex65= {2473313d2022327133}
		 $hex66= {247332303d20222648}
		 $hex67= {247332313d20224b65}
		 $hex68= {247332323d20224d65}
		 $hex69= {247332333d20224d65}
		 $hex70= {247332343d2022264d}
		 $hex71= {247332353d2022264e}
		 $hex72= {247332363d2022264e}
		 $hex73= {247332373d20224e65}
		 $hex74= {247332383d2022264f}
		 $hex75= {247332393d20224f6e}
		 $hex76= {2473323d2022327133}
		 $hex77= {247333303d20224f72}
		 $hex78= {247333313d20225068}
		 $hex79= {247333323d20225072}
		 $hex80= {247333333d20222653}
		 $hex81= {247333343d20225365}
		 $hex82= {247333353d20225365}
		 $hex83= {247333363d20225365}
		 $hex84= {247333373d20222653}
		 $hex85= {247333383d20222653}
		 $hex86= {247333393d20222653}
		 $hex87= {2473333d2022264162}
		 $hex88= {247334303d2022533a}
		 $hex89= {247334313d2022533a}
		 $hex90= {247334323d2022534f}
		 $hex91= {247334333d20225374}
		 $hex92= {247334343d20225379}
		 $hex93= {247334353d20225461}
		 $hex94= {247334363d20225469}
		 $hex95= {247334373d20225469}
		 $hex96= {247334383d20225653}
		 $hex97= {247334393d20225769}
		 $hex98= {2473343d2022415661}
		 $hex99= {2473353d2022264272}
		 $hex100= {2473363d2022436963}
		 $hex101= {2473373d2022434c6e}
		 $hex102= {2473383d2022436f6d}
		 $hex103= {2473393d2022436f6e}

	condition:
		12 of them
}
