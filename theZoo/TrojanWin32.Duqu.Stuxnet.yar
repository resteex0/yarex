
/*
   YARA Rule Set
   Author: resteex
   Identifier: TrojanWin32_Duqu_Stuxnet 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_TrojanWin32_Duqu_Stuxnet {
	meta: 
		 description= "TrojanWin32_Duqu_Stuxnet Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-30-54" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "c9a31ea148232b201fe7cb7db5c75f5e"

	strings:

	
 		 $s1= "(C) Copyright IBM Corp. 1994, 2002." fullword wide
		 $s2= "DosDevicesGpdDev" fullword wide
		 $s3= "FileDescription" fullword wide
		 $s4= "IBM Corporation " fullword wide
		 $s5= "IBM ServeRAID Contoller" fullword wide
		 $s6= "IBM ServeRAID Controller Driver" fullword wide
		 $s7= "InternalCopyright" fullword wide
		 $s8= "OriginalFilename" fullword wide
		 $s9= "VS_VERSION_INFO" fullword wide
		 $s10= "ZwQuerySystemInformation" fullword wide
		 $a1= ";#;(;-;2;7;=;C;L;T;Z;a;t;|;" fullword ascii
		 $a2= "IoAttachDeviceToDeviceStack" fullword ascii
		 $a3= "IoRegisterDriverReinitialization" fullword ascii
		 $a4= "MmGetSystemRoutineAddress" fullword ascii
		 $a5= "PsLookupProcessByProcessId" fullword ascii
		 $a6= "RtlDeleteElementGenericTable" fullword ascii
		 $a7= "RtlInitializeGenericTable" fullword ascii
		 $a8= "RtlInsertElementGenericTable" fullword ascii
		 $a9= "RtlLookupElementGenericTable" fullword ascii
		 $a10= "ZwQueryInformationProcess" fullword ascii

		 $hex1= {246131303d20225a77}
		 $hex2= {2461313d20223b233b}
		 $hex3= {2461323d2022496f41}
		 $hex4= {2461333d2022496f52}
		 $hex5= {2461343d20224d6d47}
		 $hex6= {2461353d202250734c}
		 $hex7= {2461363d202252746c}
		 $hex8= {2461373d202252746c}
		 $hex9= {2461383d202252746c}
		 $hex10= {2461393d202252746c}
		 $hex11= {247331303d20225a77}
		 $hex12= {2473313d2022284329}
		 $hex13= {2473323d2022446f73}
		 $hex14= {2473333d202246696c}
		 $hex15= {2473343d202249424d}
		 $hex16= {2473353d202249424d}
		 $hex17= {2473363d202249424d}
		 $hex18= {2473373d2022496e74}
		 $hex19= {2473383d20224f7269}
		 $hex20= {2473393d202256535f}

	condition:
		2 of them
}
