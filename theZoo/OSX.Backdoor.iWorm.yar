
/*
   YARA Rule Set
   Author: resteex
   Identifier: OSX_Backdoor_iWorm 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_OSX_Backdoor_iWorm {
	meta: 
		 description= "OSX_Backdoor_iWorm Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-26-52" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "126e7840a978ae90dfa731a66afbe9be"

	strings:

	
 		 $a1= "_AuthorizationExecuteWithPrivileges" fullword ascii
		 $a2= "_CFBundleCopyExecutableURL" fullword ascii
		 $a3= "_CFStringGetSystemEncoding" fullword ascii
		 $a4= "__dyld_make_delayed_module_initializer_calls" fullword ascii
		 $a5= "___keymgr_dwarf2_register_sections" fullword ascii
		 $a6= "/System/Library/Frameworks/Carbon.framework/Versions/A/Carbon" fullword ascii
		 $a7= "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation" fullword ascii
		 $a8= "/System/Library/Frameworks/Security.framework/Versions/A/Security" fullword ascii
		 $a9= "/usr/lib/libgcc_s.1.dylib" fullword ascii
		 $a10= "/usr/lib/libstdc++.6.dylib" fullword ascii
		 $a11= "/usr/lib/libSystem.B.dylib" fullword ascii

		 $hex1= {246131303d20222f75}
		 $hex2= {246131313d20222f75}
		 $hex3= {2461313d20225f4175}
		 $hex4= {2461323d20225f4346}
		 $hex5= {2461333d20225f4346}
		 $hex6= {2461343d20225f5f64}
		 $hex7= {2461353d20225f5f5f}
		 $hex8= {2461363d20222f5379}
		 $hex9= {2461373d20222f5379}
		 $hex10= {2461383d20222f5379}
		 $hex11= {2461393d20222f7573}

	condition:
		1 of them
}
