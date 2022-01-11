
/*
   YARA Rule Set
   Author: resteex
   Identifier: EquationGroup_GROK 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_EquationGroup_GROK {
	meta: 
		 description= "EquationGroup_GROK Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-25-57" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "24a6ec8ebf9c0867ed1c097f4a653b8d"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "Microsoft Corporation" fullword wide
		 $s3= "Microsoft Corporation. All rights reserved." fullword wide
		 $s4= "MSRTdv interface driver" fullword wide
		 $s5= "Operating System" fullword wide
		 $s6= "OriginalFilename" fullword wide
		 $s7= "registrymachinesoftwareMicrosoftWindows NTCurrentVersion" fullword wide
		 $s8= "registrymachineSYSTEMControlSet001ControlSession ManagerEnvironment" fullword wide
		 $s9= "VS_VERSION_INFO" fullword wide
		 $a1= "c:usersrmgree5costandalonegrok_2.1.1.1gk_drivergk_sa_driverobjfre_wnet_amd64amd64SaGk.pdb" fullword ascii
		 $a2= "ExAcquireResourceExclusiveLite" fullword ascii
		 $a3= "IoRegisterShutdownNotification" fullword ascii
		 $a4= "IoUnregisterShutdownNotification" fullword ascii
		 $a5= "KeAcquireSpinLockAtDpcLevel" fullword ascii
		 $a6= "KeReleaseSpinLockFromDpcLevel" fullword ascii
		 $a7= "MmGetSystemRoutineAddress" fullword ascii
		 $a8= "ObReferenceObjectByHandle" fullword ascii
		 $a9= "PsLookupProcessByProcessId" fullword ascii
		 $a10= "ZwQueryInformationProcess" fullword ascii

		 $hex1= {246131303d20225a77}
		 $hex2= {2461313d2022633a75}
		 $hex3= {2461323d2022457841}
		 $hex4= {2461333d2022496f52}
		 $hex5= {2461343d2022496f55}
		 $hex6= {2461353d20224b6541}
		 $hex7= {2461363d20224b6552}
		 $hex8= {2461373d20224d6d47}
		 $hex9= {2461383d20224f6252}
		 $hex10= {2461393d202250734c}
		 $hex11= {2473313d202246696c}
		 $hex12= {2473323d20224d6963}
		 $hex13= {2473333d20224d6963}
		 $hex14= {2473343d20224d5352}
		 $hex15= {2473353d20224f7065}
		 $hex16= {2473363d20224f7269}
		 $hex17= {2473373d2022726567}
		 $hex18= {2473383d2022726567}
		 $hex19= {2473393d202256535f}

	condition:
		2 of them
}
