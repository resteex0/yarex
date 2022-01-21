
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Win32_BigBang 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Win32_BigBang {
	meta: 
		 description= "theZoo_Win32_BigBang Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-36-16" 
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
		 $a1= ".?AVCancellationTokenRegistration_TaskProc@details@Concurrency@@" fullword ascii
		 $a2= ".?AVinvalid_scheduler_policy_thread_specification@Concurrency@@" fullword ascii
		 $a3= "aW5zdGFsbCBwcm9nOiBUaGVyZSBpcyBubyBvbGQgZmlsZSBpbiB0ZW1wLg==" fullword ascii
		 $a4= "f:ddvctoolscrtvcruntimesrcinternalper_thread_data.cpp" fullword ascii
		 $a5= "minkernelcrtsucrtsrcappcrtinternalstring_utilities.cpp" fullword ascii

		 $hex1= {2461313d20222e3f41}
		 $hex2= {2461323d20222e3f41}
		 $hex3= {2461333d2022615735}
		 $hex4= {2461343d2022663a64}
		 $hex5= {2461353d20226d696e}
		 $hex6= {24733130303d20226d}
		 $hex7= {24733130313d20226d}
		 $hex8= {24733130323d20226d}
		 $hex9= {24733130333d20226d}
		 $hex10= {24733130343d20226d}
		 $hex11= {24733130353d20226d}
		 $hex12= {24733130363d20226d}
		 $hex13= {24733130373d20226d}
		 $hex14= {24733130383d20226d}
		 $hex15= {24733130393d20226d}
		 $hex16= {247331303d20226170}
		 $hex17= {24733131303d20226d}
		 $hex18= {24733131313d20226d}
		 $hex19= {24733131323d20226d}
		 $hex20= {24733131333d20226d}
		 $hex21= {24733131343d20226d}
		 $hex22= {24733131353d20226d}
		 $hex23= {24733131363d20226d}
		 $hex24= {24733131373d20226d}
		 $hex25= {24733131383d20226d}
		 $hex26= {24733131393d20226d}
		 $hex27= {247331313d20226170}
		 $hex28= {24733132303d20226d}
		 $hex29= {24733132313d20226d}
		 $hex30= {24733132323d20226d}
		 $hex31= {24733132333d20226d}
		 $hex32= {24733132343d20226d}
		 $hex33= {24733132353d20226d}
		 $hex34= {24733132363d20226d}
		 $hex35= {24733132373d20226d}
		 $hex36= {24733132383d20226d}
		 $hex37= {24733132393d20226d}
		 $hex38= {247331323d20226170}
		 $hex39= {24733133303d20226d}
		 $hex40= {24733133313d20226d}
		 $hex41= {24733133323d20226d}
		 $hex42= {24733133333d20226d}
		 $hex43= {24733133343d20226d}
		 $hex44= {24733133353d20226d}
		 $hex45= {24733133363d20226d}
		 $hex46= {24733133373d20226d}
		 $hex47= {24733133383d20226d}
		 $hex48= {24733133393d20226d}
		 $hex49= {247331333d20226170}
		 $hex50= {24733134303d20226d}
		 $hex51= {24733134313d20226d}
		 $hex52= {24733134323d20226d}
		 $hex53= {24733134333d20226d}
		 $hex54= {24733134343d20226d}
		 $hex55= {24733134353d20224f}
		 $hex56= {24733134363d202270}
		 $hex57= {24733134373d202250}
		 $hex58= {24733134383d202253}
		 $hex59= {24733134393d202253}
		 $hex60= {247331343d20226170}
		 $hex61= {24733135303d202273}
		 $hex62= {24733135313d202273}
		 $hex63= {24733135323d202274}
		 $hex64= {24733135333d202277}
		 $hex65= {24733135343d202277}
		 $hex66= {247331353d20226170}
		 $hex67= {247331363d20226170}
		 $hex68= {247331373d20226170}
		 $hex69= {247331383d20226170}
		 $hex70= {247331393d20226170}
		 $hex71= {2473313d20225f5f61}
		 $hex72= {247332303d20226170}
		 $hex73= {247332313d20226368}
		 $hex74= {247332323d20226368}
		 $hex75= {247332333d2022636f}
		 $hex76= {247332343d2022636f}
		 $hex77= {247332353d2022636f}
		 $hex78= {247332363d2022636f}
		 $hex79= {247332373d2022636f}
		 $hex80= {247332383d2022636f}
		 $hex81= {247332393d2022295f}
		 $hex82= {2473323d20225f5f61}
		 $hex83= {247333303d20225f5f}
		 $hex84= {247333313d20225f5f}
		 $hex85= {247333323d20225f5f}
		 $hex86= {247333333d2022446f}
		 $hex87= {247333343d20226578}
		 $hex88= {247333353d20226578}
		 $hex89= {247333363d20226578}
		 $hex90= {247333373d2022663a}
		 $hex91= {247333383d2022663a}
		 $hex92= {247333393d2022663a}
		 $hex93= {2473333d20225f5f61}
		 $hex94= {247334303d2022663a}
		 $hex95= {247334313d20226670}
		 $hex96= {247334323d20225f67}
		 $hex97= {247334333d20224961}
		 $hex98= {247334343d20224961}
		 $hex99= {247334353d2022496e}
		 $hex100= {247334363d20226973}
		 $hex101= {247334373d20226973}
		 $hex102= {247334383d20224a61}
		 $hex103= {247334393d20224a61}
		 $hex104= {2473343d20225f5f61}
		 $hex105= {247335303d20224b61}
		 $hex106= {247335313d20224c61}
		 $hex107= {247335323d20226d69}
		 $hex108= {247335333d20226d69}
		 $hex109= {247335343d20226d69}
		 $hex110= {247335353d20226d69}
		 $hex111= {247335363d20226d69}
		 $hex112= {247335373d20226d69}
		 $hex113= {247335383d20226d69}
		 $hex114= {247335393d20226d69}
		 $hex115= {2473353d20225f5f61}
		 $hex116= {247336303d20226d69}
		 $hex117= {247336313d20226d69}
		 $hex118= {247336323d20226d69}
		 $hex119= {247336333d20226d69}
		 $hex120= {247336343d20226d69}
		 $hex121= {247336353d20226d69}
		 $hex122= {247336363d20226d69}
		 $hex123= {247336373d20226d69}
		 $hex124= {247336383d20226d69}
		 $hex125= {247336393d20226d69}
		 $hex126= {2473363d20225f5f61}
		 $hex127= {247337303d20226d69}
		 $hex128= {247337313d20226d69}
		 $hex129= {247337323d20226d69}
		 $hex130= {247337333d20226d69}
		 $hex131= {247337343d20226d69}
		 $hex132= {247337353d20226d69}
		 $hex133= {247337363d20226d69}
		 $hex134= {247337373d20226d69}
		 $hex135= {247337383d20226d69}
		 $hex136= {247337393d20226d69}
		 $hex137= {2473373d2022617069}
		 $hex138= {247338303d20226d69}
		 $hex139= {247338313d20226d69}
		 $hex140= {247338323d20226d69}
		 $hex141= {247338333d20226d69}
		 $hex142= {247338343d20226d69}
		 $hex143= {247338353d20226d69}
		 $hex144= {247338363d20226d69}
		 $hex145= {247338373d20226d69}
		 $hex146= {247338383d20226d69}
		 $hex147= {247338393d20226d69}
		 $hex148= {2473383d2022617069}
		 $hex149= {247339303d20226d69}
		 $hex150= {247339313d20226d69}
		 $hex151= {247339323d20226d69}
		 $hex152= {247339333d20226d69}
		 $hex153= {247339343d20226d69}
		 $hex154= {247339353d20226d69}
		 $hex155= {247339363d20226d69}
		 $hex156= {247339373d20226d69}
		 $hex157= {247339383d20226d69}
		 $hex158= {247339393d20226d69}
		 $hex159= {2473393d2022617069}

	condition:
		106 of them
}
