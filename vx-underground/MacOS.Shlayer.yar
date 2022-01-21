
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_MacOS_Shlayer 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_MacOS_Shlayer {
	meta: 
		 description= "vx_underground2_MacOS_Shlayer Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-10-20" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0990f967610ec161ebb11bd4dad47652"
		 hash2= "3803d9dd1d4e6c7c4587ce7f80088ec9"
		 hash3= "3aa5fb43788f305ebb2b3c7fa4a425e1"
		 hash4= "47e5fa673370cec483492b1ed282966d"
		 hash5= "4b3ab1a5dccac06cc67856cde9b78885"
		 hash6= "7ceb17c99a30d642438d4cf336160634"
		 hash7= "8a4ce1973b7a1208b82b4e016462903c"
		 hash8= "9059044f5b2362a03d2eccecf1bcad87"
		 hash9= "b490bdd3899fa6dc06787d49cb64b405"
		 hash10= "b7a66df8b280cef879de978501cbd12f"
		 hash11= "cb304cb44c087efd874ebedfd2315301"
		 hash12= "d1fa75b3137b3f215a32092fb4772eb5"

	strings:

	
 		 $a1= "___38-[InstallerAgent monitorInstallations]_block_invoke.163" fullword ascii
		 $a2= "___38-[InstallerAgent monitorInstallations]_block_invoke.175" fullword ascii
		 $a3= "___38-[InstallerAgent monitorInstallations]_block_invoke.198" fullword ascii
		 $a4= "___38-[InstallerAgent monitorInstallations]_block_invoke.240" fullword ascii
		 $a5= "___38-[InstallerChecker sendInstallerLogs:]_block_invoke.234" fullword ascii
		 $a6= "3OltwllUp8nWcIVct93NlLlqBefGDItX2M/3aDRYsiRB0pXmKRljB2n8D+35cKJL" fullword ascii
		 $a7= "___44-[InstallerAgent offerExistsForInstallation]_block_invoke" fullword ascii
		 $a8= "___44-[InstallerAgent offerExistsForInstallation]_block_invoke_2" fullword ascii
		 $a9= "___44-[InstallerCore progressCheckOnInstallation]_block_invoke" fullword ascii
		 $a10= "___46-[InstallerCore setupInstallerAgentOnMachine:]_block_invoke" fullword ascii
		 $a11= "-[AppDelegate applicationShouldTerminateAfterLastWindowClosed:]" fullword ascii
		 $a12= "application:didFailToRegisterForRemoteNotificationsWithError:" fullword ascii
		 $a13= "application:didRegisterForRemoteNotificationsWithDeviceToken:" fullword ascii
		 $a14= "-[CoreAPI logEvent:eventName:eventStatus:fixedParams:callback:]" fullword ascii
		 $a15= "-[CoreAPI sendsInstallerLog:eventSource:block:]_block_invoke" fullword ascii
		 $a16= "-[CROffer URLSession:downloadTask:didFinishDownloadingToURL:]" fullword ascii
		 $a17= "-[InstallerAgent sendLogEvent:productID:status:]_block_invoke" fullword ascii
		 $a18= "Installer.app/Contents/Resources/Base.lproj/Main.storyboardc/UX" fullword ascii
		 $a19= "-[InstallerChecker sendLogEvent:productID:status:]_block_invoke" fullword ascii
		 $a20= "/Library/Caches/com.apple.xbs/Sources/arclite/arclite-66/source/" fullword ascii
		 $a21= "stringByReplacingOccurrencesOfString:withString:options:range:" fullword ascii
		 $a22= "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit" fullword ascii
		 $a23= "/System/Library/Frameworks/WebKit.framework/Versions/A/WebKit" fullword ascii
		 $a24= "URLSession:downloadTask:didResumeAtOffset:expectedTotalBytes:" fullword ascii
		 $a25= "webView:willPerformClientRedirectToURL:delay:fireDate:forFrame:" fullword ascii
		 $a26= "__ZGVZL30add_image_hook_autoreleasepoolPK11mach_headerlE7patches" fullword ascii
		 $a27= "__ZL36__arclite_object_setInstanceVariableP11objc_objectPKcPv" fullword ascii
		 $a28= "__ZL43__arclite_objc_retainAutoreleaseReturnValueP11objc_object" fullword ascii
		 $a29= "__ZL44__arclite_objc_retainAutoreleasedReturnValueP11objc_object" fullword ascii
		 $a30= "__ZZL30add_image_hook_autoreleasepoolPK11mach_headerlE7patches" fullword ascii

		 $hex1= {246131303d20225f5f}
		 $hex2= {246131313d20222d5b}
		 $hex3= {246131323d20226170}
		 $hex4= {246131333d20226170}
		 $hex5= {246131343d20222d5b}
		 $hex6= {246131353d20222d5b}
		 $hex7= {246131363d20222d5b}
		 $hex8= {246131373d20222d5b}
		 $hex9= {246131383d2022496e}
		 $hex10= {246131393d20222d5b}
		 $hex11= {2461313d20225f5f5f}
		 $hex12= {246132303d20222f4c}
		 $hex13= {246132313d20227374}
		 $hex14= {246132323d20222f53}
		 $hex15= {246132333d20222f53}
		 $hex16= {246132343d20225552}
		 $hex17= {246132353d20227765}
		 $hex18= {246132363d20225f5f}
		 $hex19= {246132373d20225f5f}
		 $hex20= {246132383d20225f5f}
		 $hex21= {246132393d20225f5f}
		 $hex22= {2461323d20225f5f5f}
		 $hex23= {246133303d20225f5f}
		 $hex24= {2461333d20225f5f5f}
		 $hex25= {2461343d20225f5f5f}
		 $hex26= {2461353d20225f5f5f}
		 $hex27= {2461363d2022334f6c}
		 $hex28= {2461373d20225f5f5f}
		 $hex29= {2461383d20225f5f5f}
		 $hex30= {2461393d20225f5f5f}

	condition:
		20 of them
}
