
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_MacOS_Convuster 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_MacOS_Convuster {
	meta: 
		 description= "vx_underground2_MacOS_Convuster Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-08-42" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "12e7af714b80b8ca7539c76801160f76"
		 hash2= "196878757f2e301fdf0e40600f2760cc"
		 hash3= "1baa17183df02bb8f367fb913dc11e80"
		 hash4= "341f6c548763397bcdde1c52a534c4ba"
		 hash5= "44a135d96a4d06baa4ff73e2e9953e23"
		 hash6= "7776b7551fe96bbb850190c8194df1ac"
		 hash7= "7a35cb74459f38cd44c8672b40482539"
		 hash8= "80253edf1ceef5030e3fa7cf55c7fb92"
		 hash9= "82303c6caeb68820890173f359bbfe7c"
		 hash10= "d34ac81bd6acbe58d0e34d58a328c548"
		 hash11= "e94dc192942a132b01a07eb8bfb92385"
		 hash12= "ffba668ca384ac30fa3ff928cb3ad7a0"

	strings:

	
 		 $s1= "!$&(+,.026CEFJR]^lqstuwy}" fullword wide
		 $s2= "!$'+.158;?BEILOSVY]`cgjmqtw{~" fullword wide
		 $s3= "#%+,6=>?@BCFGHKLPSTUWX[]_`cdehijkrty{|}" fullword wide
		 $a1= "_$s14SwiftShellCore21InstallerScriptRunnerC08downloaddE0yyFTo" fullword ascii
		 $a2= "_$s14SwiftShellCore21InstallerScriptRunnerC08downloaddE0yyFTq" fullword ascii
		 $a3= "_$sSn10FoundationSS5IndexVRszrlE_2inSnyACGSgSo8_NSRangeV_SShtcfC" fullword ascii
		 $a4= "_$sSo17NSWindowStyleMaskVs10SetAlgebraSCsACP11subtractingyxxFTW" fullword ascii
		 $a5= "_$sSo17NSWindowStyleMaskVs10SetAlgebraSCsACP12intersectionyxxFTW" fullword ascii
		 $a6= "_$sSo17NSWindowStyleMaskVs10SetAlgebraSCsACP8isSubset2ofSbx_tFTW" fullword ascii
		 $a7= "_$sSo17NSWindowStyleMaskVs10SetAlgebraSCsACP9formUnionyyxnFTW" fullword ascii
		 $a8= "4_$LT$std..net..tcp..TcpListener$u20$as$u20$std..sys_common.." fullword ascii
		 $a9= "7adapter9reseeding4fork16get_fork_counter17h64ae589356632910E" fullword ascii
		 $a10= "8datetime13NaiveDateTime18checked_add_signed17h2da127deaed32781E" fullword ascii
		 $a11= "9Formatter17write_char_escape10HEX_DIGITS17h28f605cbd39397ecE" fullword ascii
		 $a12= "application:didFailToRegisterForRemoteNotificationsWithError:" fullword ascii
		 $a13= "application:didRegisterForRemoteNotificationsWithDeviceToken:" fullword ascii
		 $a14= "basic_scheduler..Shared$u20$as$u20$tokio..util..wake..Wake$GT$" fullword ascii
		 $a15= "bool$u20$as$u20$core..fmt..Display$GT$3fmt17h50024c1682486244E" fullword ascii
		 $a16= "cAcBcCcDcFcJcKcNcRcScTcXc[cecfclcmcqctcucxc|c}c" fullword ascii
		 $a17= "eyusttemberemberdaynesdayrsdayurdaygmtutedtestcdtcstmdtmstpdtpst" fullword ascii
		 $a18= "_json..read..SliceRead$u20$as$u20$serde_json..read..Read$GT$1" fullword ascii
		 $a19= "/Library/Caches/com.apple.xbs/Sources/arclite/arclite-76/source/" fullword ascii
		 $a20= "__MACOSX/Contents/Frameworks/._libswiftCoreFoundation.dylibUT" fullword ascii
		 $a21= "mio..net..tcp..TcpStream$u20$as$u20$mio..event_imp..Evented$GT$" fullword ascii
		 $a22= "__OBJC_$_PROTOCOL_INSTANCE_METHODS___ARCLiteKeyedSubscripting__" fullword ascii
		 $a23= "__OBJC_$_PROTOCOL_METHOD_TYPES___ARCLiteIndexedSubscripting__" fullword ascii
		 $a24= "O.O1O`O3O5O7O9O;O>O@OBOHOIOKOLOROTOVOXO_OcOjOlOnOqOwOxOyOzO}O~O" fullword ascii
		 $a25= "park..thread..CachedParkThread$u20$as$u20$tokio..park..Park$GT$" fullword ascii
		 $a26= "r$r+r/r4r8r9rArBrCrErNrOrPrSrUrVrZrr^r`rcrhrkrnrorqrwrxr{r|r" fullword ascii
		 $a27= "__swift_FORCE_LOAD_$_swiftCompatibility50_$_FzVaI0BgX1NBW2NKU" fullword ascii
		 $a28= "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit" fullword ascii
		 $a29= "UnknownContinuationWindowUpdateGoAwayPushPromiseResetHeaders" fullword ascii
		 $a30= "u u!u$u'u)u*u/u6u9u=u>u?u@uCuGuHuNuPuRuWu^u_uauouquyuzu{u|u}u~u" fullword ascii
		 $a31= "Y!Y#Y$Y(Y/Y0Y3Y5Y6Y?YCYFYRYSYYY[Y]Y^Y_YaYcYkYmYoYrYuYvYyY{Y|Y" fullword ascii
		 $a32= "y y%y'y)y-y1y4y5y;y=y?yDyEyFyJyKyOyQyTyXy[yygyiykyryyy{y|y~y" fullword ascii
		 $a33= "__ZGVZL30add_image_hook_autoreleasepoolPK11mach_headerlE7patches" fullword ascii
		 $a34= "__ZL36__arclite_object_setInstanceVariableP11objc_objectPKcPv" fullword ascii
		 $a35= "__ZL43__arclite_objc_retainAutoreleaseReturnValueP11objc_object" fullword ascii
		 $a36= "__ZL44__arclite_objc_retainAutoreleasedReturnValueP11objc_object" fullword ascii
		 $a37= "__ZN12unicode_bidi9char_data10bidi_class17h4412ecf31ea81269E" fullword ascii
		 $a38= "__ZN2h25frame7go_away6GoAway14last_stream_id17h1323242eb17d34dcE" fullword ascii
		 $a39= "__ZN2h25share11FlowControl16release_capacity17h65312c68945e586fE" fullword ascii
		 $a40= "__ZN3mio4poll12SetReadiness13set_readiness17h4352442f3d144874E" fullword ascii
		 $a41= "__ZN5alloc6string6String15from_utf8_lossy17h259871253a21f720E" fullword ascii
		 $a42= "__ZN5bytes5bytes22PROMOTABLE_EVEN_VTABLE17h5833236ed24267beE" fullword ascii
		 $a43= "__ZN5hyper5proto2h221decode_content_length17h0fab309136c9949bE" fullword ascii
		 $a44= "__ZN5hyper7headers21connection_keep_alive17h2766e7505c135955E" fullword ascii
		 $a45= "__ZN5tokio7runtime7context12spawn_handle17hbe5dc3179298cd4dE" fullword ascii
		 $a46= "__ZN6chrono5naive9internals13YEAR_TO_FLAGS17hee091267055210f1E" fullword ascii
		 $a47= "__ZN7socket26socket6Socket15into_tcp_stream17h943010359ab68590E" fullword ascii
		 $a48= "__ZN9hashbrown3raw23bucket_mask_to_capacity17haa615dd173424d7cE" fullword ascii
		 $a49= "__ZZL30add_image_hook_autoreleasepoolPK11mach_headerlE7patches" fullword ascii

		 $hex1= {246131303d20223864}
		 $hex2= {246131313d20223946}
		 $hex3= {246131323d20226170}
		 $hex4= {246131333d20226170}
		 $hex5= {246131343d20226261}
		 $hex6= {246131353d2022626f}
		 $hex7= {246131363d20226341}
		 $hex8= {246131373d20226579}
		 $hex9= {246131383d20225f6a}
		 $hex10= {246131393d20222f4c}
		 $hex11= {2461313d20225f2473}
		 $hex12= {246132303d20225f5f}
		 $hex13= {246132313d20226d69}
		 $hex14= {246132323d20225f5f}
		 $hex15= {246132333d20225f5f}
		 $hex16= {246132343d20224f2e}
		 $hex17= {246132353d20227061}
		 $hex18= {246132363d20227224}
		 $hex19= {246132373d20225f5f}
		 $hex20= {246132383d20222f53}
		 $hex21= {246132393d2022556e}
		 $hex22= {2461323d20225f2473}
		 $hex23= {246133303d20227520}
		 $hex24= {246133313d20225921}
		 $hex25= {246133323d20227920}
		 $hex26= {246133333d20225f5f}
		 $hex27= {246133343d20225f5f}
		 $hex28= {246133353d20225f5f}
		 $hex29= {246133363d20225f5f}
		 $hex30= {246133373d20225f5f}
		 $hex31= {246133383d20225f5f}
		 $hex32= {246133393d20225f5f}
		 $hex33= {2461333d20225f2473}
		 $hex34= {246134303d20225f5f}
		 $hex35= {246134313d20225f5f}
		 $hex36= {246134323d20225f5f}
		 $hex37= {246134333d20225f5f}
		 $hex38= {246134343d20225f5f}
		 $hex39= {246134353d20225f5f}
		 $hex40= {246134363d20225f5f}
		 $hex41= {246134373d20225f5f}
		 $hex42= {246134383d20225f5f}
		 $hex43= {246134393d20225f5f}
		 $hex44= {2461343d20225f2473}
		 $hex45= {2461353d20225f2473}
		 $hex46= {2461363d20225f2473}
		 $hex47= {2461373d20225f2473}
		 $hex48= {2461383d2022345f24}
		 $hex49= {2461393d2022376164}
		 $hex50= {2473313d2022212426}
		 $hex51= {2473323d2022212427}
		 $hex52= {2473333d202223252b}

	condition:
		34 of them
}
