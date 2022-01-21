
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Android_Skygofree 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Android_Skygofree {
	meta: 
		 description= "theZoo_Android_Skygofree Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-34-37" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "39fca709b416d8da592de3a3f714dce8"
		 hash2= "708445b8d358c254e861effffd4f819b"

	strings:

	
 		 $a1= ";;common_google_play_services_notification_needs_update_title" fullword ascii
		 $a2= ";;res/drawable/common_google_signin_btn_icon_dark_focused.xml" fullword ascii
		 $a3= "res/drawable/common_google_signin_btn_icon_dark_focused.xmlmR" fullword ascii
		 $a4= "res/drawable/common_google_signin_btn_icon_dark_focused.xmlPK" fullword ascii
		 $a5= "::res/drawable/common_google_signin_btn_icon_dark_normal.xml" fullword ascii
		 $a6= "res/drawable/common_google_signin_btn_icon_dark_normal.xmlmQ" fullword ascii
		 $a7= "res/drawable/common_google_signin_btn_icon_dark_normal.xmlPK" fullword ascii
		 $a8= "res/drawable/common_google_signin_btn_icon_light_focused.xml" fullword ascii
		 $a9= "res/drawable/common_google_signin_btn_icon_light_focused.xmlmR=O" fullword ascii
		 $a10= "res/drawable/common_google_signin_btn_icon_light_focused.xmlPK" fullword ascii
		 $a11= ";;res/drawable/common_google_signin_btn_icon_light_normal.xml" fullword ascii
		 $a12= "res/drawable/common_google_signin_btn_icon_light_normal.xmlmQ" fullword ascii
		 $a13= "res/drawable/common_google_signin_btn_icon_light_normal.xmlPK" fullword ascii
		 $a14= ";;res/drawable/common_google_signin_btn_text_dark_focused.xml" fullword ascii
		 $a15= "res/drawable/common_google_signin_btn_text_dark_focused.xmlmR" fullword ascii
		 $a16= "res/drawable/common_google_signin_btn_text_dark_focused.xmlPK" fullword ascii
		 $a17= "::res/drawable/common_google_signin_btn_text_dark_normal.xml" fullword ascii
		 $a18= "res/drawable/common_google_signin_btn_text_dark_normal.xmlPK" fullword ascii
		 $a19= "res/drawable/common_google_signin_btn_text_light_focused.xml" fullword ascii
		 $a20= "res/drawable/common_google_signin_btn_text_light_focused.xmlmR=O" fullword ascii
		 $a21= "res/drawable/common_google_signin_btn_text_light_focused.xmlPK" fullword ascii
		 $a22= ";;res/drawable/common_google_signin_btn_text_light_normal.xml" fullword ascii
		 $a23= "res/drawable/common_google_signin_btn_text_light_normal.xmlPK" fullword ascii

		 $hex1= {246131303d20227265}
		 $hex2= {246131313d20223b3b}
		 $hex3= {246131323d20227265}
		 $hex4= {246131333d20227265}
		 $hex5= {246131343d20223b3b}
		 $hex6= {246131353d20227265}
		 $hex7= {246131363d20227265}
		 $hex8= {246131373d20223a3a}
		 $hex9= {246131383d20227265}
		 $hex10= {246131393d20227265}
		 $hex11= {2461313d20223b3b63}
		 $hex12= {246132303d20227265}
		 $hex13= {246132313d20227265}
		 $hex14= {246132323d20223b3b}
		 $hex15= {246132333d20227265}
		 $hex16= {2461323d20223b3b72}
		 $hex17= {2461333d2022726573}
		 $hex18= {2461343d2022726573}
		 $hex19= {2461353d20223a3a72}
		 $hex20= {2461363d2022726573}
		 $hex21= {2461373d2022726573}
		 $hex22= {2461383d2022726573}
		 $hex23= {2461393d2022726573}

	condition:
		15 of them
}
