
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Darkside 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Darkside {
	meta: 
		 description= "vx_underground2_Darkside Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-54-39" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "04fde4340cc79cd9e61340d4c1e8ddfb"
		 hash2= "0e178c4808213ce50c2540468ce409d3"
		 hash3= "0ed51a595631e9b4d60896ab5573332f"
		 hash4= "130220f4457b9795094a21482d5f104b"
		 hash5= "1a700f845849e573ab3148daef1a3b0b"
		 hash6= "1c33dc87c6fdb80725d732a5323341f9"
		 hash7= "222792d2e75782516d653d5cccfcf33b"
		 hash8= "29bcd459f5ddeeefad26fc098304e786"
		 hash9= "3fd9b0117a0e79191859630148dcdc6d"
		 hash10= "47a4420ad26f60bb6bba5645326fa963"
		 hash11= "4c99af42d102c863bbae84db9f133a82"
		 hash12= "4d419dc50e3e4824c096f298e0fa885a"
		 hash13= "5ff75d33080bb97a8e6b54875c221777"
		 hash14= "66ddb290df3d510a6001365c3a694de2"
		 hash15= "68ada5f6aa8e3c3969061e905ceb204c"
		 hash16= "69ec3d1368adbe75f3766fc88bc64afc"
		 hash17= "6a7fdab1c7f6c5a5482749be5c4bf1a4"
		 hash18= "84c1567969b86089cc33dccf41562bcd"
		 hash19= "885fc8fb590b899c1db7b42fe83dddc3"
		 hash20= "91e2807955c5004f13006ff795cb803c"
		 hash21= "9d418ecc0f3bf45029263b0944236884"
		 hash22= "9e779da82d86bcd4cc43ab29f929f73f"
		 hash23= "a3d964aaf642d626474f02ba3ae4f49b"
		 hash24= "b0fd45162c2219e14bdccab76f33946e"
		 hash25= "b278d7ec3681df16a541cf9e34d3b70a"
		 hash26= "b9d04060842f71d1a8f3444316dc1843"
		 hash27= "c2764be55336f83a59aa0f63a0b36732"
		 hash28= "c4f1a1b73e4af0fbb63af8ee89a5a7fe"
		 hash29= "c81dae5c67fb72a2c2f24b178aea50b7"
		 hash30= "c830512579b0e08f40bc1791fc10c582"
		 hash31= "cfcfb68901ffe513e9f0d76b17d02f96"
		 hash32= "d6634959e4f9b42dfc02b270324fa6d9"
		 hash33= "e44450150e8683a0addd5c686cd4d202"
		 hash34= "f75ba194742c978239da2892061ba1b4"
		 hash35= "f87a2e1c3d148a67eaeb696b1ab69133"
		 hash36= "f913d43ba0a9f921b1376b26cd30fa34"
		 hash37= "f9fc1a1a95d5723c140c2a8effc93722"

	strings:

	
 		 $s1= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s2= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s3= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s4= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s5= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s6= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s7= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s8= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s9= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s10= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s11= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s12= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s13= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s14= "Bapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s15= "Bapi-ms-win-core-fibers-l1-1-1" fullword wide
		 $s16= "BDRemovalToolLauncher_x64.exe" fullword wide
		 $s17= "BDRemovalToolLauncher_x86.exe" fullword wide
		 $s18= "BD_UNIFIED_REMOVAL_TOOL_MUTEX" fullword wide
		 $s19= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s20= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s21= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s22= "GetModuleFileName failed." fullword wide
		 $s23= "RemovalToolUnifiedDropper.exe" fullword wide
		 $s24= "spanish-dominican republic" fullword wide
		 $a1= "N5boost10wrapexceptINS_15program_options15multiple_valuesEEE" fullword ascii
		 $a2= "N5boost10wrapexceptINS_15program_options15required_optionEEE" fullword ascii
		 $a3= "N5boost10wrapexceptINS_15program_options16ambiguous_optionEEE" fullword ascii
		 $a4= "N5boost10wrapexceptINS_15program_options16validation_errorEEE" fullword ascii
		 $a5= "N5boost10wrapexceptINS_3log12v2s_mt_posix16limitation_errorEEE" fullword ascii
		 $a6= "N5boost15program_options33too_many_positional_options_errorE" fullword ascii
		 $a7= "N5boost16exception_detail10clone_implINS0_14bad_exception_EEE" fullword ascii
		 $a8= "N5boost3log12v2s_mt_posix10attributes17current_thread_id4implE" fullword ascii
		 $a9= "N5boost3log12v2s_mt_posix10attributes20attribute_value_implIjEE" fullword ascii
		 $a10= "N5boost3log12v2s_mt_posix10attributes20attribute_value_implISsEE" fullword ascii
		 $a11= "N5boost3log12v2s_mt_posix3aux25default_formatter_factoryIcEE" fullword ascii
		 $a12= "N5boost3log12v2s_mt_posix3aux25default_formatter_factoryIwEE" fullword ascii
		 $a13= "N5boost3log12v2s_mt_posix3aux27date_format_parser_callbackIcEE" fullword ascii
		 $a14= "N5boost3log12v2s_mt_posix3aux27time_format_parser_callbackIcEE" fullword ascii
		 $a15= "*N5boost3log12v2s_mt_posix5sinks12_GLOBAL__N_114file_collectorE" fullword ascii
		 $a16= "N8CryptoPP12AbstractRingINS_7IntegerEE20MultiplicativeGroupTE" fullword ascii
		 $a17= "N8CryptoPP15BlockCipherImplINS_8RC2_InfoENS_11BlockCipherEEE" fullword ascii
		 $a18= "N8CryptoPP16BlockCipherFinalILNS_9CipherDirE0ENS_3RC23EncEEE" fullword ascii
		 $a19= "N8CryptoPP17DL_PrivateKey_GFPINS_22DL_GroupParameters_DSAEEE" fullword ascii
		 $a20= "N8CryptoPP17DL_PrivateKeyImplINS_22DL_GroupParameters_DSAEEE" fullword ascii
		 $a21= "N8CryptoPP24DL_Algorithm_DSA_RFC6979INS_7IntegerENS_4SHA1EEE" fullword ascii
		 $a22= "N8CryptoPP24DL_Algorithm_DSA_RFC6979INS_7IntegerENS_6SHA224EEE" fullword ascii
		 $a23= "N8CryptoPP24DL_Algorithm_DSA_RFC6979INS_7IntegerENS_6SHA256EEE" fullword ascii
		 $a24= "N8CryptoPP24DL_Algorithm_DSA_RFC6979INS_7IntegerENS_6SHA384EEE" fullword ascii
		 $a25= "N8CryptoPP24DL_Algorithm_DSA_RFC6979INS_7IntegerENS_6SHA512EEE" fullword ascii
		 $a26= "N8CryptoPP27AlgorithmParametersTemplateIPKNS_13PrimeSelectorEEE" fullword ascii
		 $a27= "N8CryptoPP30PK_FixedLengthCryptoSystemImplINS_12PK_DecryptorEEE" fullword ascii
		 $a28= "N8CryptoPP30PK_FixedLengthCryptoSystemImplINS_12PK_EncryptorEEE" fullword ascii
		 $a29= "N8CryptoPP32DL_ElgamalLikeSignatureAlgorithmINS_8ECPPointEEE" fullword ascii
		 $a30= "N8CryptoPP32DL_ElgamalLikeSignatureAlgorithmINS_9EC2NPointEEE" fullword ascii
		 $a31= "PN8CryptoPP16DL_PublicKeyImplINS_22DL_GroupParameters_DSAEEE" fullword ascii
		 $a32= "PN8CryptoPP17DL_PrivateKeyImplINS_22DL_GroupParameters_DSAEEE" fullword ascii
		 $a33= "SaIN5boost3log12v2s_mt_posix10attributes17named_scope_entryEE" fullword ascii
		 $a34= "_ZN8CryptoPP11UnflushableINS_6FilterEE12ChannelFlushERKSsbib" fullword ascii
		 $a35= "_ZN8CryptoPP18DL_GroupParametersINS_8ECPPointEE10PrecomputeEj" fullword ascii
		 $a36= "_ZN8CryptoPP18DL_GroupParametersINS_9EC2NPointEE10PrecomputeEj" fullword ascii
		 $a37= "_ZN8CryptoPP27BlockOrientedCipherModeBase13ResynchronizeEPKhi" fullword ascii
		 $a38= "_ZNK8CryptoPP11UnflushableINS_6FilterEE18InputBufferIsEmptyEv" fullword ascii
		 $a39= "_ZNK8CryptoPP12AbstractRingINS_7IntegerEE12ExponentiateERKS1_S4_" fullword ascii
		 $a40= "_ZNK8CryptoPP12AbstractRingINS_7IntegerEE19MultiplicativeGroupEv" fullword ascii
		 $a41= "_ZNK8CryptoPP12DL_PublicKeyINS_7IntegerEE16GetPublicElementEv" fullword ascii
		 $a42= "_ZNK8CryptoPP12DL_PublicKeyINS_9EC2NPointEE16GetPublicElementEv" fullword ascii
		 $a43= "_ZNK8CryptoPP13AbstractGroupINS_7IntegerEE15InversionIsFastEv" fullword ascii
		 $a44= "_ZNK8CryptoPP13AbstractGroupINS_8ECPPointEE15InversionIsFastEv" fullword ascii
		 $a45= "_ZNK8CryptoPP13AbstractGroupINS_9EC2NPointEE15InversionIsFastEv" fullword ascii
		 $a46= "_ZNK8CryptoPP17ModularArithmetic26IsMontgomeryRepresentationEv" fullword ascii
		 $a47= "_ZNK8CryptoPP18DL_GroupParametersINS_7IntegerEE11GetCofactorEv" fullword ascii
		 $a48= "_ZNK8CryptoPP20StreamTransformation23GetOptimalBlockSizeUsedEv" fullword ascii
		 $a49= "_ZNK8CryptoPP21DL_GroupParameters_ECINS_3ECPEE14GetMaxExponentEv" fullword ascii
		 $a50= "_ZNK8CryptoPP21KeyDerivationFunction20IsValidDerivedLengthEm" fullword ascii
		 $a51= "_ZNK8CryptoPP24MontgomeryRepresentation9ConvertInERKNS_7IntegerE" fullword ascii
		 $a52= "_ZNK8CryptoPP31DL_GroupParameters_IntegerBased13GetGroupOrderEv" fullword ascii
		 $a53= "_ZNSt13basic_ostreamIwSt11char_traitsIwEE9_M_insertIbEERS2_T_" fullword ascii
		 $a54= "_ZNSt13basic_ostreamIwSt11char_traitsIwEE9_M_insertIdEERS2_T_" fullword ascii
		 $a55= "_ZNSt13basic_ostreamIwSt11char_traitsIwEE9_M_insertIeEERS2_T_" fullword ascii
		 $a56= "_ZNSt13basic_ostreamIwSt11char_traitsIwEE9_M_insertIlEERS2_T_" fullword ascii
		 $a57= "_ZNSt13basic_ostreamIwSt11char_traitsIwEE9_M_insertImEERS2_T_" fullword ascii
		 $a58= "_ZNSt13basic_ostreamIwSt11char_traitsIwEE9_M_insertIxEERS2_T_" fullword ascii
		 $a59= "_ZNSt13basic_ostreamIwSt11char_traitsIwEE9_M_insertIyEERS2_T_" fullword ascii
		 $a60= "_ZNSt15basic_streambufIcSt11char_traitsIcEE5imbueERKSt6locale" fullword ascii
		 $a61= "_ZNSt15basic_streambufIwSt11char_traitsIwEE5imbueERKSt6locale" fullword ascii
		 $a62= "_ZNSt15basic_stringbufIcSt11char_traitsIcESaIcEE7_M_syncEPcmm" fullword ascii
		 $a63= "_ZNSt6thread15_M_start_threadESt10shared_ptrINS_10_Impl_baseEE" fullword ascii
		 $a64= "_ZSt28_Rb_tree_rebalance_for_erasePSt18_Rb_tree_node_baseRS_" fullword ascii

		 $hex1= {246131303d20224e35}
		 $hex2= {246131313d20224e35}
		 $hex3= {246131323d20224e35}
		 $hex4= {246131333d20224e35}
		 $hex5= {246131343d20224e35}
		 $hex6= {246131353d20222a4e}
		 $hex7= {246131363d20224e38}
		 $hex8= {246131373d20224e38}
		 $hex9= {246131383d20224e38}
		 $hex10= {246131393d20224e38}
		 $hex11= {2461313d20224e3562}
		 $hex12= {246132303d20224e38}
		 $hex13= {246132313d20224e38}
		 $hex14= {246132323d20224e38}
		 $hex15= {246132333d20224e38}
		 $hex16= {246132343d20224e38}
		 $hex17= {246132353d20224e38}
		 $hex18= {246132363d20224e38}
		 $hex19= {246132373d20224e38}
		 $hex20= {246132383d20224e38}
		 $hex21= {246132393d20224e38}
		 $hex22= {2461323d20224e3562}
		 $hex23= {246133303d20224e38}
		 $hex24= {246133313d2022504e}
		 $hex25= {246133323d2022504e}
		 $hex26= {246133333d20225361}
		 $hex27= {246133343d20225f5a}
		 $hex28= {246133353d20225f5a}
		 $hex29= {246133363d20225f5a}
		 $hex30= {246133373d20225f5a}
		 $hex31= {246133383d20225f5a}
		 $hex32= {246133393d20225f5a}
		 $hex33= {2461333d20224e3562}
		 $hex34= {246134303d20225f5a}
		 $hex35= {246134313d20225f5a}
		 $hex36= {246134323d20225f5a}
		 $hex37= {246134333d20225f5a}
		 $hex38= {246134343d20225f5a}
		 $hex39= {246134353d20225f5a}
		 $hex40= {246134363d20225f5a}
		 $hex41= {246134373d20225f5a}
		 $hex42= {246134383d20225f5a}
		 $hex43= {246134393d20225f5a}
		 $hex44= {2461343d20224e3562}
		 $hex45= {246135303d20225f5a}
		 $hex46= {246135313d20225f5a}
		 $hex47= {246135323d20225f5a}
		 $hex48= {246135333d20225f5a}
		 $hex49= {246135343d20225f5a}
		 $hex50= {246135353d20225f5a}
		 $hex51= {246135363d20225f5a}
		 $hex52= {246135373d20225f5a}
		 $hex53= {246135383d20225f5a}
		 $hex54= {246135393d20225f5a}
		 $hex55= {2461353d20224e3562}
		 $hex56= {246136303d20225f5a}
		 $hex57= {246136313d20225f5a}
		 $hex58= {246136323d20225f5a}
		 $hex59= {246136333d20225f5a}
		 $hex60= {246136343d20225f5a}
		 $hex61= {2461363d20224e3562}
		 $hex62= {2461373d20224e3562}
		 $hex63= {2461383d20224e3562}
		 $hex64= {2461393d20224e3562}
		 $hex65= {247331303d20226170}
		 $hex66= {247331313d20226170}
		 $hex67= {247331323d20226170}
		 $hex68= {247331333d20226170}
		 $hex69= {247331343d20224261}
		 $hex70= {247331353d20224261}
		 $hex71= {247331363d20224244}
		 $hex72= {247331373d20224244}
		 $hex73= {247331383d20224244}
		 $hex74= {247331393d20226578}
		 $hex75= {2473313d2022617069}
		 $hex76= {247332303d20226578}
		 $hex77= {247332313d20226578}
		 $hex78= {247332323d20224765}
		 $hex79= {247332333d20225265}
		 $hex80= {247332343d20227370}
		 $hex81= {2473323d2022617069}
		 $hex82= {2473333d2022617069}
		 $hex83= {2473343d2022617069}
		 $hex84= {2473353d2022617069}
		 $hex85= {2473363d2022617069}
		 $hex86= {2473373d2022617069}
		 $hex87= {2473383d2022617069}
		 $hex88= {2473393d2022617069}

	condition:
		58 of them
}
