
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_StrongPity 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_StrongPity {
	meta: 
		 description= "Win32_StrongPity Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-33-54" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "a4d3b78941da8b6f4edad7cb6f35134b"
		 hash2= "cab76ac00e342f77bdfec3e85b6b85a9"

	strings:

	
 		 $s1= "Aapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s2= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s3= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s5= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s6= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s7= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s8= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s9= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s10= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s11= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s12= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s13= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s14= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s15= "cmd.exe /C ping 3.5.6.6 -n 4" fullword wide
		 $s16= "cmd.exe /C ping 6.6.3.3 -n 5 " fullword wide
		 $s17= "Connection: close" fullword wide
		 $s18= "Content-Length: %lu" fullword wide
		 $s19= "Content-Type: application/x-www-form-urlencoded" fullword wide
		 $s20= "Content-Type: multipart/form-data; boundary=----Boundary%08X" fullword wide
		 $s21= "Copyright (C) 2015" fullword wide
		 $s22= "Copyright (C) 2019 Digest Security" fullword wide
		 $s23= "dddd, MMMM dd, yyyy" fullword wide
		 $s24= "Digest Printer Server" fullword wide
		 $s25= "Digest Security" fullword wide
		 $s26= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s27= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s28= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s29= "FileDescription" fullword wide
		 $s30= "Mozilla/5.0 (Windows NT 6.1; Win64; rv:46.0)" fullword wide
		 $s31= "OriginalFilename" fullword wide
		 $s32= "VS_VERSION_INFO" fullword wide
		 $a1= ">$>+>2>9>@>G>N>U>]>e>m>y>" fullword ascii
		 $a2= "2@2D2H2L2X33`3d3h3l3p3t3x3|3" fullword ascii
		 $a3= "?*?.?2?6?:?>?B?F?J?N?R?V?" fullword ascii
		 $a4= "2H3L3P3T3X33`3d3h3l3p3t3x3|3" fullword ascii
		 $a5= "abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a6= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" fullword ascii
		 $a7= ".?AVbad_array_new_length@std@@" fullword ascii
		 $a8= "contact@digestsecurity.com1" fullword ascii
		 $a9= "InitializeCriticalSectionAndSpinCount" fullword ascii
		 $a10= "InitializeCriticalSectionEx" fullword ascii
		 $a11= "IsProcessorFeaturePresent" fullword ascii
		 $a12= "name=%ls&delete=WinHttpWriteDataWinHttpQueryHeadWinHttpCloseHandWinHttpReceiveReWinHttpOpenRequeWinH" fullword ascii
		 $a13= "SetUnhandledExceptionFilter" fullword ascii
		 $a14= "ttpQueryOptiWinHttpSetOption" fullword ascii

		 $hex1= {246131303d2022496e}
		 $hex2= {246131313d20224973}
		 $hex3= {246131323d20226e61}
		 $hex4= {246131333d20225365}
		 $hex5= {246131343d20227474}
		 $hex6= {2461313d20223e243e}
		 $hex7= {2461323d2022324032}
		 $hex8= {2461333d20223f2a3f}
		 $hex9= {2461343d2022324833}
		 $hex10= {2461353d2022616263}
		 $hex11= {2461363d2022414243}
		 $hex12= {2461373d20222e3f41}
		 $hex13= {2461383d2022636f6e}
		 $hex14= {2461393d2022496e69}
		 $hex15= {247331303d20226170}
		 $hex16= {247331313d20226170}
		 $hex17= {247331323d20226170}
		 $hex18= {247331333d20226170}
		 $hex19= {247331343d20226170}
		 $hex20= {247331353d2022636d}
		 $hex21= {247331363d2022636d}
		 $hex22= {247331373d2022436f}
		 $hex23= {247331383d2022436f}
		 $hex24= {247331393d2022436f}
		 $hex25= {2473313d2022416170}
		 $hex26= {247332303d2022436f}
		 $hex27= {247332313d2022436f}
		 $hex28= {247332323d2022436f}
		 $hex29= {247332333d20226464}
		 $hex30= {247332343d20224469}
		 $hex31= {247332353d20224469}
		 $hex32= {247332363d20226578}
		 $hex33= {247332373d20226578}
		 $hex34= {247332383d20226578}
		 $hex35= {247332393d20224669}
		 $hex36= {2473323d2022617069}
		 $hex37= {247333303d20224d6f}
		 $hex38= {247333313d20224f72}
		 $hex39= {247333323d20225653}
		 $hex40= {2473333d2022617069}
		 $hex41= {2473343d2022617069}
		 $hex42= {2473353d2022617069}
		 $hex43= {2473363d2022617069}
		 $hex44= {2473373d2022617069}
		 $hex45= {2473383d2022617069}
		 $hex46= {2473393d2022617069}

	condition:
		5 of them
}
