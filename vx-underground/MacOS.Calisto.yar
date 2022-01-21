
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_MacOS_Calisto 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_MacOS_Calisto {
	meta: 
		 description= "vx_underground2_MacOS_Calisto Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-08-39" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2f38b201f6b368d587323a1bec516e5d"
		 hash2= "d7ac1b8113c94567be4a26d214964119"

	strings:

	
 		 $a1= "application:didFailToRegisterForRemoteNotificationsWithError:" fullword ascii
		 $a2= "application:didRegisterForRemoteNotificationsWithDeviceToken:" fullword ascii
		 $a3= "/Library/Application Support/Google/Chrome/Default/Bookmarks" fullword ascii
		 $a4= "scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:" fullword ascii
		 $a5= "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit" fullword ascii
		 $a6= "@__TF10Foundation22_convertArrayToNSArrayurFGSaq__CSo7NSArray" fullword ascii
		 $a7= "__TF10Foundation22_convertArrayToNSArrayurFGSaq__CSo7NSArray" fullword ascii
		 $a8= "__TF10Foundation22_convertNSArrayToArrayurFGSqCSo7NSArray_GSaq__" fullword ascii
		 $a9= "@__TF10Foundation24_convertNSStringToStringFGSqCSo8NSString_SS" fullword ascii
		 $a10= "__TF10Foundation24_convertNSStringToStringFGSqCSo8NSString_SS" fullword ascii
		 $a11= "@__TFE10FoundationSSCfMSSFT4dataCSo6NSData8encodingSu_GSqSS_" fullword ascii
		 $a12= "@__TFSs15_print_unlockedu0_Rq0_Ss16OutputStreamType_FTq_Rq0__T_" fullword ascii
		 $a13= "__TFSs15_print_unlockedu0_Rq0_Ss16OutputStreamType_FTq_Rq0__T_" fullword ascii
		 $a14= "@__TTSf4s___TFSS23_bridgeToObjectiveCImplfSSFT_PSs9AnyObject_" fullword ascii
		 $a15= "__TTSf4s___TFSS23_bridgeToObjectiveCImplfSSFT_PSs9AnyObject_" fullword ascii

		 $hex1= {246131303d20225f5f}
		 $hex2= {246131313d2022405f}
		 $hex3= {246131323d2022405f}
		 $hex4= {246131333d20225f5f}
		 $hex5= {246131343d2022405f}
		 $hex6= {246131353d20225f5f}
		 $hex7= {2461313d2022617070}
		 $hex8= {2461323d2022617070}
		 $hex9= {2461333d20222f4c69}
		 $hex10= {2461343d2022736368}
		 $hex11= {2461353d20222f5379}
		 $hex12= {2461363d2022405f5f}
		 $hex13= {2461373d20225f5f54}
		 $hex14= {2461383d20225f5f54}
		 $hex15= {2461393d2022405f5f}

	condition:
		10 of them
}
