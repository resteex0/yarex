
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Invicea_Tunnel 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Invicea_Tunnel {
	meta: 
		 description= "Win32_Invicea_Tunnel Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-32-42" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "ad44a7c5e18e9958dda66ccfc406cd44"

	strings:

	
 		 $s1= "-create-e4j-log" fullword wide
		 $s2= "/create-e4j-log" fullword wide
		 $s3= "&-create-i4j-log" fullword wide
		 $s4= "/create-i4j-log" fullword wide
		 $s5= "@MSG_ERROR_DIALOG_CAPTION@" fullword wide
		 $s6= "@MSG_ERROR_DIALOG_OK@" fullword wide
		 $s7= "@MSG_ERROR_DIALOG_TEXT@" fullword wide
		 $a1= "${EXE4J_PATHLIST_SEPARATOR}" fullword ascii
		 $a2= "${INSTALL4J_PATHLIST_SEPARATOR}" fullword ascii
		 $a3= "${launcher:sys.launcherDirectory}" fullword ascii
		 $a4= "${launcher:sys.launcherTempDirectory}" fullword ascii
		 $a5= "${launcher:sys.pathlistSeparator}" fullword ascii
		 $a6= "@22_IO_istream_withassign" fullword ascii
		 $a7= "@22_IO_ostream_withassign" fullword ascii
		 $a8= "com/exe4j/runtime/Exe4JController" fullword ascii
		 $a9= "com/exe4j/runtime/WinLauncher" fullword ascii
		 $a10= "com/install4j/runtime/launcher/FirstRun" fullword ascii
		 $a11= "com/install4j/runtime/launcher/WinLauncher" fullword ascii
		 $a12= "C:Usershannesdevprojinstall4jbuildsrccwindowsJavaVMLauncher.cpp" fullword ascii
		 $a13= "exe4jlib.jar;i4jdel.exe;client.jar;" fullword ascii
		 $a14= "%EXE4J_PATHLIST_SEPARATOR%" fullword ascii
		 $a15= "exe4j.unextractedPosition" fullword ascii
		 $a16= "InitializeCriticalSection" fullword ascii
		 $a17= ".install4ji4jruntime.jar" fullword ascii
		 $a18= "%INSTALL4J_PATHLIST_SEPARATOR%" fullword ascii
		 $a19= "SetUnhandledExceptionFilter" fullword ascii
		 $a20= "SOFTWAREej-technologiesexe4jjvms" fullword ascii
		 $a21= "SOFTWAREej-technologiesexe4jlocatedjvms" fullword ascii
		 $a22= "SOFTWAREej-technologiesexe4jpids" fullword ascii
		 $a23= "SOFTWAREej-technologiesinstall4jinstallations" fullword ascii
		 $a24= "../../../src/mingw/mthr_stub.c" fullword ascii

		 $hex1= {246131303d2022636f}
		 $hex2= {246131313d2022636f}
		 $hex3= {246131323d2022433a}
		 $hex4= {246131333d20226578}
		 $hex5= {246131343d20222545}
		 $hex6= {246131353d20226578}
		 $hex7= {246131363d2022496e}
		 $hex8= {246131373d20222e69}
		 $hex9= {246131383d20222549}
		 $hex10= {246131393d20225365}
		 $hex11= {2461313d2022247b45}
		 $hex12= {246132303d2022534f}
		 $hex13= {246132313d2022534f}
		 $hex14= {246132323d2022534f}
		 $hex15= {246132333d2022534f}
		 $hex16= {246132343d20222e2e}
		 $hex17= {2461323d2022247b49}
		 $hex18= {2461333d2022247b6c}
		 $hex19= {2461343d2022247b6c}
		 $hex20= {2461353d2022247b6c}
		 $hex21= {2461363d2022403232}
		 $hex22= {2461373d2022403232}
		 $hex23= {2461383d2022636f6d}
		 $hex24= {2461393d2022636f6d}
		 $hex25= {2473313d20222d6372}
		 $hex26= {2473323d20222f6372}
		 $hex27= {2473333d2022262d63}
		 $hex28= {2473343d20222f6372}
		 $hex29= {2473353d2022404d53}
		 $hex30= {2473363d2022404d53}
		 $hex31= {2473373d2022404d53}

	condition:
		3 of them
}
