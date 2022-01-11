
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Triton 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Triton {
	meta: 
		 description= "Win32_Triton Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-34-53" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "1904cad4927541e47d453becbd934bf0"

	strings:

	
 		 $s1= "netexec.exe.svc" fullword wide
		 $a1= "abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a2= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" fullword ascii
		 $a3= "GetUserObjectInformationA" fullword ascii
		 $a4= "InitializeCriticalSectionAndSpinCount" fullword ascii
		 $a5= "JanFebMarAprMayJunJulAugSepOctNovDec" fullword ascii
		 $a6= "NtQueryInformationProcess" fullword ascii
		 $a7= "SetUnhandledExceptionFilter" fullword ascii

		 $hex1= {2461313d2022616263}
		 $hex2= {2461323d2022414243}
		 $hex3= {2461333d2022476574}
		 $hex4= {2461343d2022496e69}
		 $hex5= {2461353d20224a616e}
		 $hex6= {2461363d20224e7451}
		 $hex7= {2461373d2022536574}
		 $hex8= {2473313d20226e6574}

	condition:
		1 of them
}
