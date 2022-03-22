
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
		 date = "2022-03-22_12-20-29" 
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

		 $hex1= {2e3f415643616e6365}
		 $hex2= {2e3f4156696e76616c}
		 $hex3= {433a5573657273566f}
		 $hex4= {4d6963726f736f6674}
		 $hex5= {7370616e6973682d64}

	condition:
		1 of them
}
