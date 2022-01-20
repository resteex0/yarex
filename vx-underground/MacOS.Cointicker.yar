
/*
   YARA Rule Set
   Author: resteex
   Identifier: MacOS_Cointicker 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_MacOS_Cointicker {
	meta: 
		 description= "MacOS_Cointicker Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_11-17-18" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "67d70e7d5831cc3ea6188abbce135b46"
		 hash2= "6e90da7669304722c9a06db0e32554ef"

	strings:

	
 		 $a1= "application:didFailToRegisterForRemoteNotificationsWithError:" fullword ascii
		 $a2= "application:didRegisterForRemoteNotificationsWithDeviceToken:" fullword ascii
		 $a3= "captureStillImageAsynchronouslyFromConnection:completionHandler:" fullword ascii
		 $a4= "CoinTicker.app/Contents/Frameworks/libswiftCoreGraphics.dylibUX" fullword ascii
		 $a5= "CoinTicker.app/Contents/Frameworks/libswiftCoreImage.dylibUX" fullword ascii
		 $a6= "CoinTicker.app/Contents/Frameworks/libswiftFoundation.dylibUX" fullword ascii
		 $a7= "CoinTicker.app/Contents/Frameworks/libswiftObjectiveC.dylibUX" fullword ascii
		 $a8= "CoinTicker.app/Contents/Frameworks/libswiftQuartzCore.dylibUX" fullword ascii
		 $a9= "CoinTicker.app/Contents/Resources/en.lproj/Localizable.stringsUX" fullword ascii
		 $a10= "CoinTicker.app/Contents/Resources/Fonts/cryptocoins-icons.ttfUX" fullword ascii
		 $a11= "CoinTicker.app/Contents/Resources/ja.lproj/Localizable.stringsUX" fullword ascii
		 $a12= "CoinTicker.app/Contents/Resources/ko.lproj/Localizable.stringsUX" fullword ascii
		 $a13= "com.alamofire.networking.session.download.file-manager-error" fullword ascii
		 $a14= "downloadTaskWithRequest:progress:destination:completionHandler:" fullword ascii
		 $a15= "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit" fullword ascii
		 $a16= "URLSession:downloadTask:didResumeAtOffset:expectedTotalBytes:" fullword ascii

		 $hex1= {246131303d2022436f}
		 $hex2= {246131313d2022436f}
		 $hex3= {246131323d2022436f}
		 $hex4= {246131333d2022636f}
		 $hex5= {246131343d2022646f}
		 $hex6= {246131353d20222f53}
		 $hex7= {246131363d20225552}
		 $hex8= {2461313d2022617070}
		 $hex9= {2461323d2022617070}
		 $hex10= {2461333d2022636170}
		 $hex11= {2461343d2022436f69}
		 $hex12= {2461353d2022436f69}
		 $hex13= {2461363d2022436f69}
		 $hex14= {2461373d2022436f69}
		 $hex15= {2461383d2022436f69}
		 $hex16= {2461393d2022436f69}

	condition:
		8 of them
}
