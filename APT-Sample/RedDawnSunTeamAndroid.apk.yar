
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_RedDawnSunTeamAndroid_apk 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_RedDawnSunTeamAndroid_apk {
	meta: 
		 description= "APT_Sample_RedDawnSunTeamAndroid_apk Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-29_06-37-53" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "3e36d7056812d0c1852e7b8f446b7e0f"

	strings:

	
 		 $s1= "com.security01.android.fastapplock" fullword wide

		 $hex1= {63??6f??6d??2e??73??65??63??75??72??69??74??79??30??31??2e??61??6e??64??72??6f??69??64??2e??66??61??73??74??61??70??70??}

	condition:
		1 of them
}
