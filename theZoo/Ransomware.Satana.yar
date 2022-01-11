
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Satana 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Satana {
	meta: 
		 description= "Ransomware_Satana Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-29-16" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "108756f41d114eb93e136ba2feb838d0"
		 hash2= "46bfd4f1d581d7c0121d2b19a005d3df"

	strings:

	
 		 $s1= "#%d End Encode %s" fullword wide
		 $s2= "Error CreateFileMapping: 0x%X, size: %d, %s" fullword wide
		 $s3= "MicrosoftWindows" fullword wide
		 $s4= "%PROCESSOR_ARCHITECTURE%" fullword wide
		 $s5= "%PROCESSOR_IDENTIFIER%" fullword wide
		 $s6= "%PROCESSOR_LEVEL%" fullword wide
		 $s7= "%PROCESSOR_REVISION%" fullword wide
		 $s8= "%s: NET RES FOUND: %s" fullword wide
		 $s9= "%sVSSADMIN.EXE" fullword wide
		 $s10= "threadAdminFlood: %s %s %s " fullword wide
		 $a1= "?3?9?@?F?M?S?Z?`?g?m?t?z?" fullword ascii
		 $a2= "4PGwFQU@Q4vXUW_V[U4FP4cPGpQ" fullword ascii
		 $a3= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" fullword ascii
		 $a4= "C4Yf]UuAWF4dZ9>l@AY4Dmenq" fullword ascii
		 $a5= "d:lbetwmwyuijeuqplfwub.pdb" fullword ascii
		 $a6= "=======EEEEEEEEEEEEEE=========" fullword ascii
		 $a7= "ExpandEnvironmentStringsW" fullword ascii
		 $a8= "%G|YAA]c4WyS^]@Es4ULPUURZv4swZd" fullword ascii
		 $a9= "InitializeCriticalSection" fullword ascii
		 $a10= "jmenfrhmjebkjhainycnyvrdfclb" fullword ascii
		 $a11= "MyUnhandledExceptionFilter" fullword ascii
		 $a12= "NtQueryInformationProcess" fullword ascii
		 $a13= "PXX444Z6fQSeAQ4FMbUXAQq>L" fullword ascii
		 $a14= "SetUnhandledExceptionFilter" fullword ascii
		 $a15= "}Z]@]$UX]N79Gp]4USZ[G@]W4y[PQqZUV0XQ6KgQ@uG4GQF@rXUS6G0%ADx[Sy" fullword ascii

		 $hex1= {246131303d20226a6d}
		 $hex2= {246131313d20224d79}
		 $hex3= {246131323d20224e74}
		 $hex4= {246131333d20225058}
		 $hex5= {246131343d20225365}
		 $hex6= {246131353d20227d5a}
		 $hex7= {2461313d20223f333f}
		 $hex8= {2461323d2022345047}
		 $hex9= {2461333d2022414243}
		 $hex10= {2461343d2022433459}
		 $hex11= {2461353d2022643a6c}
		 $hex12= {2461363d20223d3d3d}
		 $hex13= {2461373d2022457870}
		 $hex14= {2461383d202225477c}
		 $hex15= {2461393d2022496e69}
		 $hex16= {247331303d20227468}
		 $hex17= {2473313d2022232564}
		 $hex18= {2473323d2022457272}
		 $hex19= {2473333d20224d6963}
		 $hex20= {2473343d2022255052}
		 $hex21= {2473353d2022255052}
		 $hex22= {2473363d2022255052}
		 $hex23= {2473373d2022255052}
		 $hex24= {2473383d202225733a}
		 $hex25= {2473393d2022257356}

	condition:
		3 of them
}
