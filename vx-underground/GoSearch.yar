
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_GoSearch 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_GoSearch {
	meta: 
		 description= "vx_underground2_GoSearch Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-57-28" 
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
		2 of them
}
