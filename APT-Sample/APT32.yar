
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_APT32 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_APT32 {
	meta: 
		 description= "APT_Sample_APT32 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-22_17-55-05" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "5bc6fb202698bad5d9d0b0b4ea65e402"
		 hash2= "94823e75f54f5ec69ede7e15951c9c60"
		 hash3= "c212074b43b6ef811f2a8fb72e670e0c"
		 hash4= "d18df4fc918e7490979750497d306fc5"
		 hash5= "e0e15fa6ac800ed8511ed775cf59bfc6"

	strings:

	
 		 $a1= ".?AVCancellationTokenRegistration_TaskProc@details@Concurrency@@" fullword ascii
		 $a2= ".?AVinvalid_scheduler_policy_thread_specification@Concurrency@@" fullword ascii
		 $a3= "httpswww.welivesecurity.com20180313oceanlotus-ships-new-backdoor" fullword ascii

		 $hex1= {2461313d20222e3f41}
		 $hex2= {2461323d20222e3f41}
		 $hex3= {2461333d2022687474}

	condition:
		2 of them
}
