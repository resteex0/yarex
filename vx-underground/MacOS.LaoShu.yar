
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_MacOS_LaoShu 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_MacOS_LaoShu {
	meta: 
		 description= "vx_underground2_MacOS_LaoShu Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-10-08" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "d2e9a83cae848c0da467fe11fa229d15"
		 hash2= "ddc4ea5b58aaa4df31dac0a7b00869ff"

	strings:

	
 		 $a1= "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X" fullword ascii
		 $a2= "application:didFailToRegisterForRemoteNotificationsWithError:" fullword ascii
		 $a3= "application:didRegisterForRemoteNotificationsWithDeviceToken:" fullword ascii
		 $a4= "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit" fullword ascii

		 $hex1= {2461313d2022253032}
		 $hex2= {2461323d2022617070}
		 $hex3= {2461333d2022617070}
		 $hex4= {2461343d20222f5379}

	condition:
		2 of them
}
