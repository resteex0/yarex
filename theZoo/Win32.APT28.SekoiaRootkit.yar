
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_APT28_SekoiaRootkit 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_APT28_SekoiaRootkit {
	meta: 
		 description= "Win32_APT28_SekoiaRootkit Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-31-47" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "f8c8f6456c5a52ef24aa426e6b121685"

	strings:

	
 		 $s1= "??C:WindowsSystem32sysprepCRYPTBASE.dll" fullword wide
		 $s2= "FsFltParametersc1" fullword wide
		 $s3= "FsFltParametersc3" fullword wide
		 $s4= "REGISTRYMACHINESYSTEMCurrentControlSetservicesFsFltParametersc4" fullword wide
		 $s5= "REGISTRYMACHINESYSTEMCurrentControlSetservicesFsFltParametersc5" fullword wide
		 $a1= "d:!worketchideinstaller_kis2013BinDebugwin7x64fsflt.pdb" fullword ascii
		 $a2= "FltDoCompletionProcessingWhenSafe" fullword ascii
		 $a3= "FltGetFileNameInformation" fullword ascii
		 $a4= "FltReleaseFileNameInformation" fullword ascii
		 $a5= "MmMapLockedPagesSpecifyCache" fullword ascii
		 $a6= "ObReferenceObjectByHandle" fullword ascii
		 $a7= "PsLookupProcessByProcessId" fullword ascii
		 $a8= "PsReferenceProcessFilePointer" fullword ascii
		 $a9= "PsSetCreateProcessNotifyRoutine" fullword ascii
		 $a10= "ZwCreateTransactionManager" fullword ascii

		 $hex1= {246131303d20225a77}
		 $hex2= {2461313d2022643a21}
		 $hex3= {2461323d2022466c74}
		 $hex4= {2461333d2022466c74}
		 $hex5= {2461343d2022466c74}
		 $hex6= {2461353d20224d6d4d}
		 $hex7= {2461363d20224f6252}
		 $hex8= {2461373d202250734c}
		 $hex9= {2461383d2022507352}
		 $hex10= {2461393d2022507353}
		 $hex11= {2473313d20223f3f43}
		 $hex12= {2473323d2022467346}
		 $hex13= {2473333d2022467346}
		 $hex14= {2473343d2022524547}
		 $hex15= {2473353d2022524547}

	condition:
		1 of them
}
