
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win64_Trojan_GreenBug 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win64_Trojan_GreenBug {
	meta: 
		 description= "Win64_Trojan_GreenBug Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-45-19" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "786e61331a1e84b7fe26c254de0280ad"

	strings:

	
 		 $s1= "MicrosoftWindowsCRMFiles" fullword wide
		 $s2= "MicrosoftwindowsTmp98871" fullword wide
		 $s3= "MicrosoftWindowsTmp9932u1.bat" fullword wide
		 $s4= "MicrosoftWindowsTmpFiles" fullword wide
		 $s5= "MicrosoftWindowsTmpFiles" fullword wide
		 $s6= "MicrosoftWindowsTmpFiles" fullword wide
		 $s7= "spanish-dominican republic" fullword wide
		 $a1= ".?AUTopologyObject@GlobalCore@details@Concurrency@@" fullword ascii
		 $a2= ".?AUTopologyObject@GlobalNode@details@Concurrency@@" fullword ascii
		 $a3= ".?AVCacheLocalScheduleGroupSegment@details@Concurrency@@" fullword ascii
		 $a4= ".?AV_CancellationTokenRegistration@details@Concurrency@@" fullword ascii
		 $a5= ".?AVCancellationTokenRegistration_TaskProc@details@Concurrency@@" fullword ascii
		 $a6= ".?AVFairScheduleGroupSegment@details@Concurrency@@" fullword ascii
		 $a7= ".?AVinvalid_scheduler_policy_thread_specification@Concurrency@@" fullword ascii
		 $a8= ".?AVScheduleGroupSegmentBase@details@Concurrency@@" fullword ascii
		 $a9= ".?AVscheduler_resource_allocation_error@Concurrency@@" fullword ascii
		 $a10= "C:UsersVoidDesktopwmiPrvv 10.0.197x64Releaseswchost.pdb" fullword ascii
		 $a11= "rem %localappdata%MicrosoftWindowsTmp765643.txt#1;" fullword ascii

		 $hex1= {246131303d2022433a}
		 $hex2= {246131313d20227265}
		 $hex3= {2461313d20222e3f41}
		 $hex4= {2461323d20222e3f41}
		 $hex5= {2461333d20222e3f41}
		 $hex6= {2461343d20222e3f41}
		 $hex7= {2461353d20222e3f41}
		 $hex8= {2461363d20222e3f41}
		 $hex9= {2461373d20222e3f41}
		 $hex10= {2461383d20222e3f41}
		 $hex11= {2461393d20222e3f41}
		 $hex12= {2473313d20224d6963}
		 $hex13= {2473323d20224d6963}
		 $hex14= {2473333d20224d6963}
		 $hex15= {2473343d20224d6963}
		 $hex16= {2473353d20224d6963}
		 $hex17= {2473363d20224d6963}
		 $hex18= {2473373d2022737061}

	condition:
		12 of them
}
