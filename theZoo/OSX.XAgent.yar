
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_OSX_XAgent 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_OSX_XAgent {
	meta: 
		 description= "theZoo_OSX_XAgent Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-35-10" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "27ff86999bf2cbd5afbad94f8a9bb696"
		 hash2= "4fe4b9560e99e33dabca553e2eeee510"
		 hash3= "fbcfeeacc711310395da6ef87e34a616"

	strings:

	
 		 $a1= "___42+[NSURLConnectionDelegateWrapper wrappers]_block_invoke" fullword ascii
		 $a2= "application:didFailToRegisterForRemoteNotificationsWithError:" fullword ascii
		 $a3= "application:didRegisterForRemoteNotificationsWithDeviceToken:" fullword ascii
		 $a4= "-[NSString(FTPManagerNSStringAdditions) stringWithoutProtocol]" fullword ascii
		 $a5= "-[NSURLConnectionDelegateWrapper connection:didFailWithError:]" fullword ascii
		 $a6= "-[NSURLConnectionDelegateWrapper connectionDidFinishLoading:]" fullword ascii
		 $a7= "-[NSURLConnectionDelegateWrapper connection:didReceiveData:]" fullword ascii
		 $a8= "-[NSURLConnectionDelegateWrapper connection:didReceiveResponse:]" fullword ascii
		 $a9= "-[NSURLConnectionDelegateWrapper connection:willCacheResponse:]" fullword ascii
		 $a10= "+[SBJsonStreamParserStateArrayGotValue sharedInstance].state" fullword ascii
		 $a11= "+[SBJsonStreamParserStateArrayNeedValue sharedInstance].state" fullword ascii
		 $a12= "-[SBJsonStreamParserStateArrayStart parser:shouldAcceptToken:]" fullword ascii
		 $a13= "-[SBJsonStreamParserStateArrayStart parser:shouldTransitionTo:]" fullword ascii
		 $a14= "-[SBJsonStreamParserStateObjectGotKey parser:shouldAcceptToken:]" fullword ascii
		 $a15= "+[SBJsonStreamParserStateObjectGotValue sharedInstance].state" fullword ascii
		 $a16= "+[SBJsonStreamParserStateObjectNeedKey sharedInstance].state" fullword ascii
		 $a17= "+[SBJsonStreamParserStateObjectSeparator sharedInstance].state" fullword ascii
		 $a18= "-[SBJsonStreamParserStateObjectStart parser:shouldAcceptToken:]" fullword ascii
		 $a19= "-[SBJsonStreamParserStateObjectStart parser:shouldTransitionTo:]" fullword ascii
		 $a20= "scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:" fullword ascii
		 $a21= "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit" fullword ascii
		 $a22= "/System/Library/Frameworks/Carbon.framework/Versions/A/Carbon" fullword ascii
		 $a23= "__ZL32__arclite_objc_allocateClassPairP18glue_swift_class_tPKcm" fullword ascii
		 $a24= "__ZL36__arclite_object_setInstanceVariableP11objc_objectPKcPv" fullword ascii
		 $a25= "__ZL43__arclite_objc_retainAutoreleaseReturnValueP11objc_object" fullword ascii
		 $a26= "__ZL44__arclite_objc_retainAutoreleasedReturnValueP11objc_object" fullword ascii
		 $a27= "@__ZNKSt3__120__vector_base_commonILb1EE20__throw_length_errorEv" fullword ascii
		 $a28= "__ZNKSt3__120__vector_base_commonILb1EE20__throw_length_errorEv" fullword ascii

		 $hex1= {246131303d20222b5b}
		 $hex2= {246131313d20222b5b}
		 $hex3= {246131323d20222d5b}
		 $hex4= {246131333d20222d5b}
		 $hex5= {246131343d20222d5b}
		 $hex6= {246131353d20222b5b}
		 $hex7= {246131363d20222b5b}
		 $hex8= {246131373d20222b5b}
		 $hex9= {246131383d20222d5b}
		 $hex10= {246131393d20222d5b}
		 $hex11= {2461313d20225f5f5f}
		 $hex12= {246132303d20227363}
		 $hex13= {246132313d20222f53}
		 $hex14= {246132323d20222f53}
		 $hex15= {246132333d20225f5f}
		 $hex16= {246132343d20225f5f}
		 $hex17= {246132353d20225f5f}
		 $hex18= {246132363d20225f5f}
		 $hex19= {246132373d2022405f}
		 $hex20= {246132383d20225f5f}
		 $hex21= {2461323d2022617070}
		 $hex22= {2461333d2022617070}
		 $hex23= {2461343d20222d5b4e}
		 $hex24= {2461353d20222d5b4e}
		 $hex25= {2461363d20222d5b4e}
		 $hex26= {2461373d20222d5b4e}
		 $hex27= {2461383d20222d5b4e}
		 $hex28= {2461393d20222d5b4e}

	condition:
		18 of them
}
