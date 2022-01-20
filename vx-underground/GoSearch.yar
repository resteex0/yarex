
/*
   YARA Rule Set
   Author: resteex
   Identifier: GoSearch 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_GoSearch {
	meta: 
		 description= "GoSearch Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_11-05-32" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "b11ec6531ec25cedf67e2e1d9dbc0136"

	strings:

	
 		 $a1= "application:didFailToRegisterForRemoteNotificationsWithError:" fullword ascii
		 $a2= "application:didRegisterForRemoteNotificationsWithDeviceToken:" fullword ascii
		 $a3= "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit" fullword ascii

		 $hex1= {2461313d2022617070}
		 $hex2= {2461323d2022617070}
		 $hex3= {2461333d20222f5379}

	condition:
		1 of them
}
