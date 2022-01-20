
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_ZeroCleare 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_ZeroCleare {
	meta: 
		 description= "Win32_ZeroCleare Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-45-15" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1a69a02b0cd10b1764521fec4b7376c9"
		 hash2= "33f98b613b331b49e272512274669844"
		 hash3= "8afa8a59eebf43ef223be52e08fcdc67"
		 hash4= "c04236b5678af08c8b70a7aa696f87d5"
		 hash5= "f5f8160fe8468a77b6a495155c3dacea"

	strings:

	
 		 $s1= "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		 $s2= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s3= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-file-l1-2-2" fullword wide
		 $s5= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s6= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s7= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s8= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s9= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s10= "@api-ms-win-core-synch-l1-2-0.dll" fullword wide
		 $s11= "api-ms-win-core-synch-l1-2-0.dll" fullword wide
		 $s12= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s13= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s14= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s15= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s16= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s17= "Capi-ms-win-core-datetime-l1-1-1" fullword wide
		 $s18= "Capi-ms-win-core-fibers-l1-1-1" fullword wide
		 $s19= "C:windowssystem32cmd.exe" fullword wide
		 $s20= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s21= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s22= "SoftwareOracleVirtualBox" fullword wide
		 $s23= "spanish-dominican republic" fullword wide
		 $s24= "SystemCurrentControlSetControlNetworkProviderOrder" fullword wide
		 $a1= ".?AUTopologyObject@GlobalCore@details@Concurrency@@" fullword ascii
		 $a2= ".?AUTopologyObject@GlobalNode@details@Concurrency@@" fullword ascii
		 $a3= ".?AVCacheLocalScheduleGroupSegment@details@Concurrency@@" fullword ascii
		 $a4= ".?AV_CancellationTokenRegistration@details@Concurrency@@" fullword ascii
		 $a5= ".?AVCancellationTokenRegistration_TaskProc@details@Concurrency@@" fullword ascii
		 $a6= ".?AVFairScheduleGroupSegment@details@Concurrency@@" fullword ascii
		 $a7= ".?AVinvalid_scheduler_policy_thread_specification@Concurrency@@" fullword ascii
		 $a8= ".?AVScheduleGroupSegmentBase@details@Concurrency@@" fullword ascii
		 $a9= ".?AVscheduler_resource_allocation_error@Concurrency@@" fullword ascii
		 $a10= ".?AVstl_condition_variable_concrt@details@Concurrency@@" fullword ascii
		 $a11= ".?AVstl_condition_variable_interface@details@Concurrency@@" fullword ascii
		 $a12= ".?AVstl_condition_variable_vista@details@Concurrency@@" fullword ascii
		 $a13= ".?AVstl_condition_variable_win7@details@Concurrency@@" fullword ascii
		 $a14= ".?AVstl_critical_section_concrt@details@Concurrency@@" fullword ascii
		 $a15= ".?AVstl_critical_section_interface@details@Concurrency@@" fullword ascii
		 $a16= ".?AVstl_critical_section_vista@details@Concurrency@@" fullword ascii
		 $a17= ".?AVstl_critical_section_win7@details@Concurrency@@" fullword ascii
		 $a18= "C:UsersAdminDesktopDustmanFurutakadrvagent.plain.pdb" fullword ascii
		 $a19= "C:UsersAdminDesktopDustmanx64ReleaseDustman.pdb" fullword ascii
		 $a20= "@ng}@F@EBCAG@@EA*g}AF@EBCAGA@EA*@'A{@yvs%tvcr25Ai@gvs%tzc`7" fullword ascii
		 $a21= "P31@ng}@GABBGADCGAG*g}A@ABBGADCGAG*@+A{@yvs%tvcr45Ae@cvs%tzc|" fullword ascii

		 $hex1= {246131303d20222e3f}
		 $hex2= {246131313d20222e3f}
		 $hex3= {246131323d20222e3f}
		 $hex4= {246131333d20222e3f}
		 $hex5= {246131343d20222e3f}
		 $hex6= {246131353d20222e3f}
		 $hex7= {246131363d20222e3f}
		 $hex8= {246131373d20222e3f}
		 $hex9= {246131383d2022433a}
		 $hex10= {246131393d2022433a}
		 $hex11= {2461313d20222e3f41}
		 $hex12= {246132303d2022406e}
		 $hex13= {246132313d20225033}
		 $hex14= {2461323d20222e3f41}
		 $hex15= {2461333d20222e3f41}
		 $hex16= {2461343d20222e3f41}
		 $hex17= {2461353d20222e3f41}
		 $hex18= {2461363d20222e3f41}
		 $hex19= {2461373d20222e3f41}
		 $hex20= {2461383d20222e3f41}
		 $hex21= {2461393d20222e3f41}
		 $hex22= {247331303d20224061}
		 $hex23= {247331313d20226170}
		 $hex24= {247331323d20226170}
		 $hex25= {247331333d20226170}
		 $hex26= {247331343d20226170}
		 $hex27= {247331353d20226170}
		 $hex28= {247331363d20226170}
		 $hex29= {247331373d20224361}
		 $hex30= {247331383d20224361}
		 $hex31= {247331393d2022433a}
		 $hex32= {2473313d2022617069}
		 $hex33= {247332303d20226578}
		 $hex34= {247332313d20226578}
		 $hex35= {247332323d2022536f}
		 $hex36= {247332333d20227370}
		 $hex37= {247332343d20225379}
		 $hex38= {2473323d2022617069}
		 $hex39= {2473333d2022617069}
		 $hex40= {2473343d2022617069}
		 $hex41= {2473353d2022617069}
		 $hex42= {2473363d2022617069}
		 $hex43= {2473373d2022617069}
		 $hex44= {2473383d2022617069}
		 $hex45= {2473393d2022617069}

	condition:
		30 of them
}
