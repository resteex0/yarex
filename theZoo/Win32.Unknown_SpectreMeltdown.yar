
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Unknown_SpectreMeltdown 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Unknown_SpectreMeltdown {
	meta: 
		 description= "Win32_Unknown_SpectreMeltdown Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-45-10" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "b6b9c196d7a9b0058330b998f461ee52"

	strings:

	
 		 $a1= "./debian/tmp/usr/x86_64-w64-mingw32/include/psdk_inc" fullword ascii
		 $a2= "GUID_PROCESSOR_CORE_PARKING_AFFINITY_HISTORY_DECREASE_FACTOR" fullword ascii
		 $a3= "GUID_PROCESSOR_CORE_PARKING_AFFINITY_HISTORY_THRESHOLD" fullword ascii
		 $a4= "GUID_PROCESSOR_CORE_PARKING_OVER_UTILIZATION_HISTORY_THRESHOLD" fullword ascii
		 $a5= "GUID_PROCESSOR_CORE_PARKING_OVER_UTILIZATION_THRESHOLD" fullword ascii
		 $a6= "GUID_PROCESSOR_CORE_PARKING_OVER_UTILIZATION_WEIGHTING" fullword ascii

		 $hex1= {2461313d20222e2f64}
		 $hex2= {2461323d2022475549}
		 $hex3= {2461333d2022475549}
		 $hex4= {2461343d2022475549}
		 $hex5= {2461353d2022475549}
		 $hex6= {2461363d2022475549}

	condition:
		4 of them
}
