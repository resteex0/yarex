
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Win64_Trojan_GreenBug 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Win64_Trojan_GreenBug {
	meta: 
		 description= "theZoo_Win64_Trojan_GreenBug Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-37-09" 
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
		 $a1= ".?AVCancellationTokenRegistration_TaskProc@details@Concurrency@@" fullword ascii
		 $a2= ".?AVinvalid_scheduler_policy_thread_specification@Concurrency@@" fullword ascii
		 $a3= "C:UsersVoidDesktopwmiPrvv 10.0.197x64Releaseswchost.pdb" fullword ascii

		 $hex1= {2461313d20222e3f41}
		 $hex2= {2461323d20222e3f41}
		 $hex3= {2461333d2022433a55}
		 $hex4= {2473313d20224d6963}
		 $hex5= {2473323d20224d6963}
		 $hex6= {2473333d20224d6963}
		 $hex7= {2473343d20224d6963}
		 $hex8= {2473353d20224d6963}
		 $hex9= {2473363d20224d6963}
		 $hex10= {2473373d2022737061}

	condition:
		6 of them
}
