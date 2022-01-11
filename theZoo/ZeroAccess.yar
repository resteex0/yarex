
/*
   YARA Rule Set
   Author: resteex
   Identifier: ZeroAccess 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_ZeroAccess {
	meta: 
		 description= "ZeroAccess Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-35-49" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "a2611095f689fadffd3068e0d4e3e7ed"
		 hash2= "fe756584b159fd24dc4b6a572917354c"

	strings:

	
 		 $s1= "$%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x" fullword wide
		 $s2= "BaseNamedObjectsRestricted{0C5AB9CD-2F90-6754-8374-21D4DAB28CC1}" fullword wide
		 $s3= "BaseNamedObjectsRestricted{A3D35150-6823-4462-8C6E-7417FF841D77}" fullword wide
		 $s4= "BaseNamedObjectsRestricted{A3D35150-6823-4462-8C6E-7417FF841D78}" fullword wide
		 $s5= "BaseNamedObjectsRestricted{A3D35150-6823-4462-8C6E-7417FF841D79}" fullword wide
		 $s6= "c:windowssystem32z" fullword wide
		 $s7= "Microsoft Base Cryptographic Provider v1.0" fullword wide
		 $s8= "wbemfastprox.dll" fullword wide
		 $a1= "CMP_WaitNoPendingInstallEvents" fullword ascii
		 $a2= "DisableThreadLibraryCalls" fullword ascii
		 $a3= "InitializeCriticalSection" fullword ascii
		 $a4= "InterlockedCompareExchange" fullword ascii
		 $a5= "LdrProcessRelocationBlock" fullword ascii
		 $a6= "RtlConvertSidToUnicodeString" fullword ascii
		 $a7= "RtlImageDirectoryEntryToData" fullword ascii
		 $a8= "RtlInterlockedPopEntrySList" fullword ascii
		 $a9= "RtlInterlockedPushEntrySList" fullword ascii
		 $a10= "RtlTimeToSecondsSince1980" fullword ascii
		 $a11= "SetUnhandledExceptionFilter" fullword ascii
		 $a12= "SetupDiGetDeviceRegistryPropertyW" fullword ascii
		 $a13= "ZwQueryVolumeInformationFile" fullword ascii
		 $a14= "ZwSetHighWaitLowEventPair" fullword ascii

		 $hex1= {246131303d20225274}
		 $hex2= {246131313d20225365}
		 $hex3= {246131323d20225365}
		 $hex4= {246131333d20225a77}
		 $hex5= {246131343d20225a77}
		 $hex6= {2461313d2022434d50}
		 $hex7= {2461323d2022446973}
		 $hex8= {2461333d2022496e69}
		 $hex9= {2461343d2022496e74}
		 $hex10= {2461353d20224c6472}
		 $hex11= {2461363d202252746c}
		 $hex12= {2461373d202252746c}
		 $hex13= {2461383d202252746c}
		 $hex14= {2461393d202252746c}
		 $hex15= {2473313d2022242530}
		 $hex16= {2473323d2022426173}
		 $hex17= {2473333d2022426173}
		 $hex18= {2473343d2022426173}
		 $hex19= {2473353d2022426173}
		 $hex20= {2473363d2022633a77}
		 $hex21= {2473373d20224d6963}
		 $hex22= {2473383d2022776265}

	condition:
		2 of them
}
