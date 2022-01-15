
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_BigBang 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_BigBang {
	meta: 
		 description= "Win32_BigBang Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_22-52-08" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "18864d22331fc6503641f128226aaea8"
		 hash2= "87d7d314f86f61a9099a51c269b4ec78"
		 hash3= "a233d90b8e5c19c4b3373bb76eb11428"
		 hash4= "a3dc31c456508df7dfac8349eb0d2b65"

	strings:

	
 		 $s1= "__acrt_copy_path_to_wide_string" fullword wide
		 $s2= "__acrt_DownlevelLCIDToLocaleName" fullword wide
		 $s3= "__acrt_fp_strflt_to_string" fullword wide
		 $s4= "__acrt_get_qualified_locale" fullword wide
		 $s5= "__acrt_lowio_ensure_fh_exists" fullword wide
		 $s6= "__acrt_report_runtime_error" fullword wide
		 $s7= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s8= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s9= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s10= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s11= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s12= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s13= "api-ms-win-core-registry-l1-1-0.dll" fullword wide
		 $s14= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s15= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s16= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s17= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s18= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s19= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s20= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s21= "char>::unget" fullword wide
		 $s22= "char>::validate" fullword wide
		 $s23= "common_assert_to_message_box_build_string" fullword wide
		 $s24= "common_expand_argv_wildcards" fullword wide
		 $s25= "common_refill_and_read_nolock" fullword wide
		 $s26= "common_set_variable_in_environment_nolock" fullword wide
		 $s27= "construct_environment_block" fullword wide
		 $s28= "copy_and_add_argument_to_buffer" fullword wide
		 $s29= ")_CrtIsValidHeapPointer(block)" fullword wide
		 $s30= "__crt_strtox::floating_point_value::as_double" fullword wide
		 $s31= "__crt_strtox::floating_point_value::as_float" fullword wide
		 $s32= "__crt_strtox::parse_integer" fullword wide
		 $s33= "DocumentSummaryInformation" fullword wide
		 $s34= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s35= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s36= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s37= "f:ddvctoolscrtvcruntimeincinternal_shared.h" fullword wide
		 $s38= "f:ddvctoolscrtvcruntimesrcehstd_exception.cpp" fullword wide
		 $s39= "f:ddvctoolscrtvcruntimesrcinternalwinapi_downlevel.cpp" fullword wide
		 $s40= "f:ddvctoolscrtvcstartupsrcmiscthread_safe_statics.cpp" fullword wide
		 $s41= "fp_format_nan_or_infinity" fullword wide
		 $s42= "_get_stream_buffer_pointers" fullword wide
		 $s43= "Iapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s44= "Iapi-ms-win-core-fibers-l1-1-1" fullword wide
		 $s45= "InterenetAssistant Updater" fullword wide
		 $s46= "is_block_type_valid(header->_block_use)" fullword wide
		 $s47= "isleadbyte(_dbcsBuffer(fh))" fullword wide
		 $s48= "Japi-ms-win-core-fibers-l1-1-1" fullword wide
		 $s49= "Japi-ms-win-core-synch-l1-2-0.dll" fullword wide
		 $s50= "Kapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s51= "Lapi-ms-win-core-synch-l1-2-0.dll" fullword wide
		 $s52= "minkernelcrtsucrtinccorecrt_internal_big_integer.h" fullword wide
		 $s53= "minkernelcrtsucrtinccorecrt_internal_stdio.h" fullword wide
		 $s54= "minkernelcrtsucrtinccorecrt_internal_stdio_output.h" fullword wide
		 $s55= "minkernelcrtsucrtinccorecrt_internal_string_templates.h" fullword wide
		 $s56= "minkernelcrtsucrtinccorecrt_internal_strtox.h" fullword wide
		 $s57= "minkernelcrtsucrtsrcappcrtconvertcfout.cpp" fullword wide
		 $s58= "minkernelcrtsucrtsrcappcrtconvertcvt.cpp" fullword wide
		 $s59= "minkernelcrtsucrtsrcappcrtconvert_fptostr.cpp" fullword wide
		 $s60= "minkernelcrtsucrtsrcappcrtconvertisctype.cpp" fullword wide
		 $s61= "minkernelcrtsucrtsrcappcrtconvertmbstowcs.cpp" fullword wide
		 $s62= "minkernelcrtsucrtsrcappcrtconvertmbtowc.cpp" fullword wide
		 $s63= "minkernelcrtsucrtsrcappcrtconvertwcstombs.cpp" fullword wide
		 $s64= "minkernelcrtsucrtsrcappcrtconvertwctomb.cpp" fullword wide
		 $s65= "minkernelcrtsucrtsrcappcrtconvertxtoa.cpp" fullword wide
		 $s66= "minkernelcrtsucrtsrcappcrtfilesystemwaccess.cpp" fullword wide
		 $s67= "minkernelcrtsucrtsrcappcrtheapdebug_heap.cpp" fullword wide
		 $s68= "minkernelcrtsucrtsrcappcrtheapexpand.cpp" fullword wide
		 $s69= "minkernelcrtsucrtsrcappcrtheapnew_mode.cpp" fullword wide
		 $s70= "minkernelcrtsucrtsrcappcrtinternalstring_utilities.cpp" fullword wide
		 $s71= "minkernelcrtsucrtsrcappcrtinternalwinapi_thunks.cpp" fullword wide
		 $s72= "minkernelcrtsucrtsrcappcrtlocalecomparestringa.cpp" fullword wide
		 $s73= "minkernelcrtsucrtsrcappcrtlocalegetlocaleinfoa.cpp" fullword wide
		 $s74= "minkernelcrtsucrtsrcappcrtlocaleget_qualified_locale.cpp" fullword wide
		 $s75= "minkernelcrtsucrtsrcappcrtlocaleinitctype.cpp" fullword wide
		 $s76= "minkernelcrtsucrtsrcappcrtlocaleinitmon.cpp" fullword wide
		 $s77= "minkernelcrtsucrtsrcappcrtlocaleinitnum.cpp" fullword wide
		 $s78= "minkernelcrtsucrtsrcappcrtlocaleinittime.cpp" fullword wide
		 $s79= "minkernelcrtsucrtsrcappcrtlocalelcidtoname_downlevel.cpp" fullword wide
		 $s80= "minkernelcrtsucrtsrcappcrtlocalelocale_refcounting.cpp" fullword wide
		 $s81= "minkernelcrtsucrtsrcappcrtlocalesetlocale.cpp" fullword wide
		 $s82= "minkernelcrtsucrtsrcappcrtlocalewsetlocale.cpp" fullword wide
		 $s83= "minkernelcrtsucrtsrcappcrtlowioclose.cpp" fullword wide
		 $s84= "minkernelcrtsucrtsrcappcrtlowiocommit.cpp" fullword wide
		 $s85= "minkernelcrtsucrtsrcappcrtlowioisatty.cpp" fullword wide
		 $s86= "minkernelcrtsucrtsrcappcrtlowiolseek.cpp" fullword wide
		 $s87= "minkernelcrtsucrtsrcappcrtlowioopen.cpp" fullword wide
		 $s88= "minkernelcrtsucrtsrcappcrtlowioosfinfo.cpp" fullword wide
		 $s89= "minkernelcrtsucrtsrcappcrtlowioread.cpp" fullword wide
		 $s90= "minkernelcrtsucrtsrcappcrtlowiosetmode.cpp" fullword wide
		 $s91= "minkernelcrtsucrtsrcappcrtlowiowrite.cpp" fullword wide
		 $s92= "minkernelcrtsucrtsrcappcrtmiscdbgrpt.cpp" fullword wide
		 $s93= "minkernelcrtsucrtsrcappcrtmiscdbgrptt.cpp" fullword wide
		 $s94= "minkernelcrtsucrtsrcappcrtmiscset_error_mode.cpp" fullword wide
		 $s95= "minkernelcrtsucrtsrcappcrtmiscsignal.cpp" fullword wide
		 $s96= "minkernelcrtsucrtsrcappcrtstartupargv_parsing.cpp" fullword wide
		 $s97= "minkernelcrtsucrtsrcappcrtstartupargv_wildcards.cpp" fullword wide
		 $s98= "minkernelcrtsucrtsrcappcrtstartupassert.cpp" fullword wide
		 $s99= "minkernelcrtsucrtsrcappcrtstdiofclose.cpp" fullword wide
		 $s100= "minkernelcrtsucrtsrcappcrtstdiofgetc.cpp" fullword wide
		 $s101= "minkernelcrtsucrtsrcappcrtstdiofgetpos.cpp" fullword wide
		 $s102= "minkernelcrtsucrtsrcappcrtstdiofgets.cpp" fullword wide
		 $s103= "minkernelcrtsucrtsrcappcrtstdio_filbuf.cpp" fullword wide
		 $s104= "minkernelcrtsucrtsrcappcrtstdio_file.cpp" fullword wide
		 $s105= "minkernelcrtsucrtsrcappcrtstdiofileno.cpp" fullword wide
		 $s106= "minkernelcrtsucrtsrcappcrtstdio_flsbuf.cpp" fullword wide
		 $s107= "minkernelcrtsucrtsrcappcrtstdiofopen.cpp" fullword wide
		 $s108= "minkernelcrtsucrtsrcappcrtstdiofputc.cpp" fullword wide
		 $s109= "minkernelcrtsucrtsrcappcrtstdiofputs.cpp" fullword wide
		 $s110= "minkernelcrtsucrtsrcappcrtstdiofread.cpp" fullword wide
		 $s111= "minkernelcrtsucrtsrcappcrtstdio_freebuf.cpp" fullword wide
		 $s112= "minkernelcrtsucrtsrcappcrtstdiofseek.cpp" fullword wide
		 $s113= "minkernelcrtsucrtsrcappcrtstdiofsetpos.cpp" fullword wide
		 $s114= "minkernelcrtsucrtsrcappcrtstdioftell.cpp" fullword wide
		 $s115= "minkernelcrtsucrtsrcappcrtstdiofwrite.cpp" fullword wide
		 $s116= "minkernelcrtsucrtsrcappcrtstdio_getbuf.cpp" fullword wide
		 $s117= "minkernelcrtsucrtsrcappcrtstdioopenfile.cpp" fullword wide
		 $s118= "minkernelcrtsucrtsrcappcrtstdiooutput.cpp" fullword wide
		 $s119= "minkernelcrtsucrtsrcappcrtstdiorewind.cpp" fullword wide
		 $s120= "minkernelcrtsucrtsrcappcrtstdiosetvbuf.cpp" fullword wide
		 $s121= "minkernelcrtsucrtsrcappcrtstdio_sftbuf.cpp" fullword wide
		 $s122= "minkernelcrtsucrtsrcappcrtstdioungetc.cpp" fullword wide
		 $s123= "minkernelcrtsucrtsrcappcrtstdlibqsort.cpp" fullword wide
		 $s124= "minkernelcrtsucrtsrcappcrtstringstrnicmp.cpp" fullword wide
		 $s125= "minkernelcrtsucrtsrcappcrtstringstrnicol.cpp" fullword wide
		 $s126= "minkernelcrtsucrtsrcappcrtstringwcsdup.cpp" fullword wide
		 $s127= "minkernelcrtsucrtsrcappcrtstringwcsicmp.cpp" fullword wide
		 $s128= "minkernelcrtsucrtsrcappcrtstringwcsnicmp.cpp" fullword wide
		 $s129= "minkernelcrtsucrtsrcappcrtstringwmemcpy_s.cpp" fullword wide
		 $s130= "minkernelcrtsucrtsrcappcrttimegmtime.cpp" fullword wide
		 $s131= "minkernelcrtsucrtsrcappcrttimelocaltime.cpp" fullword wide
		 $s132= "minkernelcrtsucrtsrcappcrttimestrftime.cpp" fullword wide
		 $s133= "minkernelcrtsucrtsrcappcrttimetime.cpp" fullword wide
		 $s134= "minkernelcrtsucrtsrcappcrttimetimeset.cpp" fullword wide
		 $s135= "minkernelcrtsucrtsrcappcrttimetzset.cpp" fullword wide
		 $s136= "minkernelcrtsucrtsrcappcrttimewcsftime.cpp" fullword wide
		 $s137= "minkernelcrtsucrtsrcappcrttrancontrlfp.c" fullword wide
		 $s138= "minkernelcrtsucrtsrcappcrttranfrexp.c" fullword wide
		 $s139= "minkernelcrtsucrtsrcdesktopcrtenvgetenv.cpp" fullword wide
		 $s140= "minkernelcrtsucrtsrcdesktopcrtenvsetenv.cpp" fullword wide
		 $s141= "minkernelcrtsucrtsrcdesktopcrtexecspawnv.cpp" fullword wide
		 $s142= "minkernelcrtsucrtsrcdesktopcrtexecspawnvp.cpp" fullword wide
		 $s143= "minkernelcrtsucrtsrcdesktopcrtexecsystem.cpp" fullword wide
		 $s144= "minkernelcrtsucrtsrcdesktopcrtmbstringmbsdec.cpp" fullword wide
		 $s145= "Oapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s146= "pminkernelcrtsucrtsrcdesktopcrtexeccenvarg.cpp" fullword wide
		 $s147= "Program: %hs%ls%ls%hs%ls%hs%ls%hs%ls%ls%hs%ls" fullword wide
		 $s148= "SOFTWAREMicrosoftWindows NTCurrentVersion" fullword wide
		 $s149= "SOFTWAREWow6432NodeMicrosoftVisualStudio14.0SetupVC" fullword wide
		 $s150= "spanish-dominican republic" fullword wide
		 $s151= "state_case_normal_common()" fullword wide
		 $s152= "tzset_from_environment_nolock" fullword wide
		 $s153= "wchar_t>::unget" fullword wide
		 $s154= "wchar_t>::validate" fullword wide
		 $a1= "char>::unget" fullword ascii
		 $a2= "char>::validate" fullword ascii
		 $a3= "f:ddvctoolscrtvcruntimesrcehstd_exception.cpp" fullword ascii
		 $a4= "f:ddvctoolscrtvcruntimesrcinternalwinapi_downlevel.cpp" fullword ascii
		 $a5= "f:ddvctoolscrtvcstartupsrcmiscthread_safe_statics.cpp" fullword ascii
		 $a6= "minkernelcrtsucrtinccorecrt_internal_big_integer.h" fullword ascii
		 $a7= "minkernelcrtsucrtinccorecrt_internal_stdio_output.h" fullword ascii
		 $a8= "minkernelcrtsucrtinccorecrt_internal_string_templates.h" fullword ascii
		 $a9= "minkernelcrtsucrtsrcappcrtconvert_fptostr.cpp" fullword ascii
		 $a10= "minkernelcrtsucrtsrcappcrtconvertisctype.cpp" fullword ascii
		 $a11= "minkernelcrtsucrtsrcappcrtconvertmbstowcs.cpp" fullword ascii
		 $a12= "minkernelcrtsucrtsrcappcrtconvertwcstombs.cpp" fullword ascii
		 $a13= "minkernelcrtsucrtsrcappcrtfilesystemwaccess.cpp" fullword ascii
		 $a14= "minkernelcrtsucrtsrcappcrtheapdebug_heap.cpp" fullword ascii
		 $a15= "minkernelcrtsucrtsrcappcrtinternalstring_utilities.cpp" fullword ascii
		 $a16= "minkernelcrtsucrtsrcappcrtinternalwinapi_thunks.cpp" fullword ascii
		 $a17= "minkernelcrtsucrtsrcappcrtlocalecomparestringa.cpp" fullword ascii
		 $a18= "minkernelcrtsucrtsrcappcrtlocalegetlocaleinfoa.cpp" fullword ascii
		 $a19= "minkernelcrtsucrtsrcappcrtlocaleget_qualified_locale.cpp" fullword ascii
		 $a20= "minkernelcrtsucrtsrcappcrtlocaleinitctype.cpp" fullword ascii
		 $a21= "minkernelcrtsucrtsrcappcrtlocaleinittime.cpp" fullword ascii
		 $a22= "minkernelcrtsucrtsrcappcrtlocalelcidtoname_downlevel.cpp" fullword ascii
		 $a23= "minkernelcrtsucrtsrcappcrtlocalelocale_refcounting.cpp" fullword ascii
		 $a24= "minkernelcrtsucrtsrcappcrtlocalesetlocale.cpp" fullword ascii
		 $a25= "minkernelcrtsucrtsrcappcrtlocalewsetlocale.cpp" fullword ascii
		 $a26= "minkernelcrtsucrtsrcappcrtmiscset_error_mode.cpp" fullword ascii
		 $a27= "minkernelcrtsucrtsrcappcrtstartupargv_parsing.cpp" fullword ascii
		 $a28= "minkernelcrtsucrtsrcappcrtstartupargv_wildcards.cpp" fullword ascii
		 $a29= "minkernelcrtsucrtsrcappcrtstringstrnicmp.cpp" fullword ascii
		 $a30= "minkernelcrtsucrtsrcappcrtstringstrnicol.cpp" fullword ascii
		 $a31= "minkernelcrtsucrtsrcappcrtstringwcsnicmp.cpp" fullword ascii
		 $a32= "minkernelcrtsucrtsrcappcrtstringwmemcpy_s.cpp" fullword ascii
		 $a33= "minkernelcrtsucrtsrcdesktopcrtexecspawnv.cpp" fullword ascii
		 $a34= "minkernelcrtsucrtsrcdesktopcrtexecspawnvp.cpp" fullword ascii
		 $a35= "minkernelcrtsucrtsrcdesktopcrtexecsystem.cpp" fullword ascii
		 $a36= "minkernelcrtsucrtsrcdesktopcrtmbstringmbsdec.cpp" fullword ascii
		 $a37= "pminkernelcrtsucrtsrcdesktopcrtexeccenvarg.cpp" fullword ascii
		 $a38= "SOFTWAREWow6432NodeMicrosoftVisualStudio14.0SetupVC" fullword ascii
		 $a39= "wchar_t>::unget" fullword ascii
		 $a40= "wchar_t>::validate" fullword ascii

		 $hex1= {246131303d20226d69}
		 $hex2= {246131313d20226d69}
		 $hex3= {246131323d20226d69}
		 $hex4= {246131333d20226d69}
		 $hex5= {246131343d20226d69}
		 $hex6= {246131353d20226d69}
		 $hex7= {246131363d20226d69}
		 $hex8= {246131373d20226d69}
		 $hex9= {246131383d20226d69}
		 $hex10= {246131393d20226d69}
		 $hex11= {2461313d2022636861}
		 $hex12= {246132303d20226d69}
		 $hex13= {246132313d20226d69}
		 $hex14= {246132323d20226d69}
		 $hex15= {246132333d20226d69}
		 $hex16= {246132343d20226d69}
		 $hex17= {246132353d20226d69}
		 $hex18= {246132363d20226d69}
		 $hex19= {246132373d20226d69}
		 $hex20= {246132383d20226d69}
		 $hex21= {246132393d20226d69}
		 $hex22= {2461323d2022636861}
		 $hex23= {246133303d20226d69}
		 $hex24= {246133313d20226d69}
		 $hex25= {246133323d20226d69}
		 $hex26= {246133333d20226d69}
		 $hex27= {246133343d20226d69}
		 $hex28= {246133353d20226d69}
		 $hex29= {246133363d20226d69}
		 $hex30= {246133373d2022706d}
		 $hex31= {246133383d2022534f}
		 $hex32= {246133393d20227763}
		 $hex33= {2461333d2022663a64}
		 $hex34= {246134303d20227763}
		 $hex35= {2461343d2022663a64}
		 $hex36= {2461353d2022663a64}
		 $hex37= {2461363d20226d696e}
		 $hex38= {2461373d20226d696e}
		 $hex39= {2461383d20226d696e}
		 $hex40= {2461393d20226d696e}
		 $hex41= {24733130303d20226d}
		 $hex42= {24733130313d20226d}
		 $hex43= {24733130323d20226d}
		 $hex44= {24733130333d20226d}
		 $hex45= {24733130343d20226d}
		 $hex46= {24733130353d20226d}
		 $hex47= {24733130363d20226d}
		 $hex48= {24733130373d20226d}
		 $hex49= {24733130383d20226d}
		 $hex50= {24733130393d20226d}
		 $hex51= {247331303d20226170}
		 $hex52= {24733131303d20226d}
		 $hex53= {24733131313d20226d}
		 $hex54= {24733131323d20226d}
		 $hex55= {24733131333d20226d}
		 $hex56= {24733131343d20226d}
		 $hex57= {24733131353d20226d}
		 $hex58= {24733131363d20226d}
		 $hex59= {24733131373d20226d}
		 $hex60= {24733131383d20226d}
		 $hex61= {24733131393d20226d}
		 $hex62= {247331313d20226170}
		 $hex63= {24733132303d20226d}
		 $hex64= {24733132313d20226d}
		 $hex65= {24733132323d20226d}
		 $hex66= {24733132333d20226d}
		 $hex67= {24733132343d20226d}
		 $hex68= {24733132353d20226d}
		 $hex69= {24733132363d20226d}
		 $hex70= {24733132373d20226d}
		 $hex71= {24733132383d20226d}
		 $hex72= {24733132393d20226d}
		 $hex73= {247331323d20226170}
		 $hex74= {24733133303d20226d}
		 $hex75= {24733133313d20226d}
		 $hex76= {24733133323d20226d}
		 $hex77= {24733133333d20226d}
		 $hex78= {24733133343d20226d}
		 $hex79= {24733133353d20226d}
		 $hex80= {24733133363d20226d}
		 $hex81= {24733133373d20226d}
		 $hex82= {24733133383d20226d}
		 $hex83= {24733133393d20226d}
		 $hex84= {247331333d20226170}
		 $hex85= {24733134303d20226d}
		 $hex86= {24733134313d20226d}
		 $hex87= {24733134323d20226d}
		 $hex88= {24733134333d20226d}
		 $hex89= {24733134343d20226d}
		 $hex90= {24733134353d20224f}
		 $hex91= {24733134363d202270}
		 $hex92= {24733134373d202250}
		 $hex93= {24733134383d202253}
		 $hex94= {24733134393d202253}
		 $hex95= {247331343d20226170}
		 $hex96= {24733135303d202273}
		 $hex97= {24733135313d202273}
		 $hex98= {24733135323d202274}
		 $hex99= {24733135333d202277}
		 $hex100= {24733135343d202277}
		 $hex101= {247331353d20226170}
		 $hex102= {247331363d20226170}
		 $hex103= {247331373d20226170}
		 $hex104= {247331383d20226170}
		 $hex105= {247331393d20226170}
		 $hex106= {2473313d20225f5f61}
		 $hex107= {247332303d20226170}
		 $hex108= {247332313d20226368}
		 $hex109= {247332323d20226368}
		 $hex110= {247332333d2022636f}
		 $hex111= {247332343d2022636f}
		 $hex112= {247332353d2022636f}
		 $hex113= {247332363d2022636f}
		 $hex114= {247332373d2022636f}
		 $hex115= {247332383d2022636f}
		 $hex116= {247332393d2022295f}
		 $hex117= {2473323d20225f5f61}
		 $hex118= {247333303d20225f5f}
		 $hex119= {247333313d20225f5f}
		 $hex120= {247333323d20225f5f}
		 $hex121= {247333333d2022446f}
		 $hex122= {247333343d20226578}
		 $hex123= {247333353d20226578}
		 $hex124= {247333363d20226578}
		 $hex125= {247333373d2022663a}
		 $hex126= {247333383d2022663a}
		 $hex127= {247333393d2022663a}
		 $hex128= {2473333d20225f5f61}
		 $hex129= {247334303d2022663a}
		 $hex130= {247334313d20226670}
		 $hex131= {247334323d20225f67}
		 $hex132= {247334333d20224961}
		 $hex133= {247334343d20224961}
		 $hex134= {247334353d2022496e}
		 $hex135= {247334363d20226973}
		 $hex136= {247334373d20226973}
		 $hex137= {247334383d20224a61}
		 $hex138= {247334393d20224a61}
		 $hex139= {2473343d20225f5f61}
		 $hex140= {247335303d20224b61}
		 $hex141= {247335313d20224c61}
		 $hex142= {247335323d20226d69}
		 $hex143= {247335333d20226d69}
		 $hex144= {247335343d20226d69}
		 $hex145= {247335353d20226d69}
		 $hex146= {247335363d20226d69}
		 $hex147= {247335373d20226d69}
		 $hex148= {247335383d20226d69}
		 $hex149= {247335393d20226d69}
		 $hex150= {2473353d20225f5f61}
		 $hex151= {247336303d20226d69}
		 $hex152= {247336313d20226d69}
		 $hex153= {247336323d20226d69}
		 $hex154= {247336333d20226d69}
		 $hex155= {247336343d20226d69}
		 $hex156= {247336353d20226d69}
		 $hex157= {247336363d20226d69}
		 $hex158= {247336373d20226d69}
		 $hex159= {247336383d20226d69}
		 $hex160= {247336393d20226d69}
		 $hex161= {2473363d20225f5f61}
		 $hex162= {247337303d20226d69}
		 $hex163= {247337313d20226d69}
		 $hex164= {247337323d20226d69}
		 $hex165= {247337333d20226d69}
		 $hex166= {247337343d20226d69}
		 $hex167= {247337353d20226d69}
		 $hex168= {247337363d20226d69}
		 $hex169= {247337373d20226d69}
		 $hex170= {247337383d20226d69}
		 $hex171= {247337393d20226d69}
		 $hex172= {2473373d2022617069}
		 $hex173= {247338303d20226d69}
		 $hex174= {247338313d20226d69}
		 $hex175= {247338323d20226d69}
		 $hex176= {247338333d20226d69}
		 $hex177= {247338343d20226d69}
		 $hex178= {247338353d20226d69}
		 $hex179= {247338363d20226d69}
		 $hex180= {247338373d20226d69}
		 $hex181= {247338383d20226d69}
		 $hex182= {247338393d20226d69}
		 $hex183= {2473383d2022617069}
		 $hex184= {247339303d20226d69}
		 $hex185= {247339313d20226d69}
		 $hex186= {247339323d20226d69}
		 $hex187= {247339333d20226d69}
		 $hex188= {247339343d20226d69}
		 $hex189= {247339353d20226d69}
		 $hex190= {247339363d20226d69}
		 $hex191= {247339373d20226d69}
		 $hex192= {247339383d20226d69}
		 $hex193= {247339393d20226d69}
		 $hex194= {2473393d2022617069}

	condition:
		129 of them
}
