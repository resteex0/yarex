
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_MacOS_Kitm 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_MacOS_Kitm {
	meta: 
		 description= "vx_underground2_MacOS_Kitm Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-10-07" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "3aa9c558d4d5f1b2a6d3ce47aa26315f"
		 hash2= "6b06baec43171a3f1c6ac9c3fb143a06"
		 hash3= "7505197b6b30d5800ffdc4427576780c"
		 hash4= "a3156b9071c1a322c5b1236dc467e47f"
		 hash5= "d19b484a31b6cbe1b9b41cb6046e0172"
		 hash6= "e11c6ca1e3515a5e977dc9175cdb229a"
		 hash7= "f9fabd1637d190e0e0a5c117c71921fc"

	strings:

	
 		 $a1= "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X" fullword ascii
		 $a2= "http://torqspot.org/App/MacADV/up.php?cname=%@&file=%@&res=%@" fullword ascii
		 $a3= "scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:" fullword ascii
		 $a4= "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit" fullword ascii
		 $a5= "T@,N,SsetDownloadProgressDelegate:,VdownloadProgressDelegate" fullword ascii

		 $hex1= {2461313d2022253032}
		 $hex2= {2461323d2022687474}
		 $hex3= {2461333d2022736368}
		 $hex4= {2461343d20222f5379}
		 $hex5= {2461353d202254402c}

	condition:
		3 of them
}
