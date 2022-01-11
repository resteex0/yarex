
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Caphaw_Shylock 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Caphaw_Shylock {
	meta: 
		 description= "Win32_Caphaw_Shylock Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-32-08" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "c98fe7df44cded5981af4ec565c29a2e"
		 hash2= "ca0403ea24fe2a7771b99cea55826c9b"
		 hash3= "e63fead91fe788dac57601d2c77713f9"

	strings:

	
 		 $s1= "??C:WindowsSystem32" fullword wide
		 $s2= "DosDevices%C:" fullword wide
		 $s3= "Drivernsiproxy" fullword wide
		 $s4= "Driverservise.sys" fullword wide
		 $s5= "??PhysicalDrive0" fullword wide
		 $s6= "??PhysicalDrive%d" fullword wide
		 $s7= "PsCreateSystemThread" fullword wide
		 $s8= "REGISTRYMACHINESOFTWAREMicrosoftWindowsCurrentVersionPoliciesSystem" fullword wide
		 $a1= "GetUserObjectInformationA" fullword ascii
		 $a2= "MmGetSystemRoutineAddress" fullword ascii
		 $a3= "ObReferenceObjectByHandle" fullword ascii
		 $a4= "RtlAnsiStringToUnicodeString" fullword ascii
		 $a5= "RtlUnicodeStringToAnsiString" fullword ascii
		 $a6= "ZwQueryInformationProcess" fullword ascii

		 $hex1= {2461313d2022476574}
		 $hex2= {2461323d20224d6d47}
		 $hex3= {2461333d20224f6252}
		 $hex4= {2461343d202252746c}
		 $hex5= {2461353d202252746c}
		 $hex6= {2461363d20225a7751}
		 $hex7= {2473313d20223f3f43}
		 $hex8= {2473323d2022446f73}
		 $hex9= {2473333d2022447269}
		 $hex10= {2473343d2022447269}
		 $hex11= {2473353d20223f3f50}
		 $hex12= {2473363d20223f3f50}
		 $hex13= {2473373d2022507343}
		 $hex14= {2473383d2022524547}

	condition:
		1 of them
}
