
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Win32_Unknown_SpectreMeltdown 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Win32_Unknown_SpectreMeltdown {
	meta: 
		 description= "theZoo_Win32_Unknown_SpectreMeltdown Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-37-01" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "b6b9c196d7a9b0058330b998f461ee52"

	strings:

	
 		 $a1= "GUID_PROCESSOR_CORE_PARKING_AFFINITY_HISTORY_DECREASE_FACTOR" fullword ascii
		 $a2= "GUID_PROCESSOR_CORE_PARKING_OVER_UTILIZATION_HISTORY_THRESHOLD" fullword ascii

		 $hex1= {2461313d2022475549}
		 $hex2= {2461323d2022475549}

	condition:
		1 of them
}
