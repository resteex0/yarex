
/*
   YARA Rule Set
   Author: resteex
   Identifier: EquationGroup_EquationDrug 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_EquationGroup_EquationDrug {
	meta: 
		 description= "EquationGroup_EquationDrug Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-25-54" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "4556ce5eb007af1de5bd3b457f0b216d"

	strings:

	
 		 $s1= "CcnFormSyncExFBC" fullword wide
		 $s2= "system32win32k.sys" fullword wide
		 $a1= "InitializeSecurityDescriptor" fullword ascii
		 $a2= "MmBuildMdlForNonPagedPool" fullword ascii
		 $a3= "MmMapLockedPagesSpecifyCache" fullword ascii
		 $a4= "PsDereferencePrimaryToken" fullword ascii
		 $a5= "RtlImageDirectoryEntryToData" fullword ascii
		 $a6= "SetSecurityDescriptorDacl" fullword ascii
		 $a7= "SetSecurityDescriptorGroup" fullword ascii
		 $a8= "SetSecurityDescriptorOwner" fullword ascii

		 $hex1= {2461313d2022496e69}
		 $hex2= {2461323d20224d6d42}
		 $hex3= {2461333d20224d6d4d}
		 $hex4= {2461343d2022507344}
		 $hex5= {2461353d202252746c}
		 $hex6= {2461363d2022536574}
		 $hex7= {2461373d2022536574}
		 $hex8= {2461383d2022536574}
		 $hex9= {2473313d202243636e}
		 $hex10= {2473323d2022737973}

	condition:
		1 of them
}
