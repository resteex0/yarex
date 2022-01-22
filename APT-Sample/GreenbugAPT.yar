
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_GreenbugAPT 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_GreenbugAPT {
	meta: 
		 description= "APT_Sample_GreenbugAPT Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-22_17-56-01" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "39ae8ced52d5b7b93e79c8727b5dd51c"
		 hash2= "73b2cfc5590ca3f431c8482d27f8e268"
		 hash3= "891f5fd5d09ea31df9a83449eae1500c"
		 hash4= "e0175eecf8d31a6f32da076d22ecbdff"
		 hash5= "f5ef3b060fb476253f9a7638f82940d9"

	strings:

	
 		 $s1= "MicrosoftWindowsCRMFiles" fullword wide
		 $s2= "MicrosoftWindowsTempFiles" fullword wide
		 $s3= "MicrosoftWindowsTempFiles" fullword wide
		 $s4= "MicrosoftWindowsTempFiles" fullword wide
		 $s5= "MicrosoftwindowsTmp98871" fullword wide
		 $s6= "MicrosoftWindowsTmp9932u1.bat" fullword wide
		 $s7= "MicrosoftwindowsTmp998871" fullword wide
		 $s8= "MicrosoftWindowsTmpFiles" fullword wide
		 $s9= "MicrosoftWindowsTmpFiles" fullword wide
		 $s10= "MicrosoftWindowsTmpFiles" fullword wide
		 $s11= "spanish-dominican republic" fullword wide
		 $a1= ".?AVCancellationTokenRegistration_TaskProc@details@Concurrency@@" fullword ascii
		 $a2= ".?AVinvalid_scheduler_policy_thread_specification@Concurrency@@" fullword ascii
		 $a3= "C:UsersVoidDesktopwmiPrvv 10.0.197x64Releaseswchost.pdb" fullword ascii

		 $hex1= {2461313d20222e3f41}
		 $hex2= {2461323d20222e3f41}
		 $hex3= {2461333d2022433a55}
		 $hex4= {247331303d20224d69}
		 $hex5= {247331313d20227370}
		 $hex6= {2473313d20224d6963}
		 $hex7= {2473323d20224d6963}
		 $hex8= {2473333d20224d6963}
		 $hex9= {2473343d20224d6963}
		 $hex10= {2473353d20224d6963}
		 $hex11= {2473363d20224d6963}
		 $hex12= {2473373d20224d6963}
		 $hex13= {2473383d20224d6963}
		 $hex14= {2473393d20224d6963}

	condition:
		9 of them
}
