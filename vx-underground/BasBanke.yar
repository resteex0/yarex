
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_BasBanke 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_BasBanke {
	meta: 
		 description= "vx_underground2_BasBanke Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-53-32" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "fb10f2f9b79ed2c21061cec17160fe20"

	strings:

	
 		 $a1= ";;res/drawable/common_google_signin_btn_icon_dark_focused.xml" fullword ascii
		 $a2= "res/drawable/common_google_signin_btn_icon_dark_focused.xmlmR" fullword ascii
		 $a3= "res/drawable/common_google_signin_btn_icon_dark_focused.xmlPK" fullword ascii
		 $a4= "::res/drawable/common_google_signin_btn_icon_dark_normal.xml" fullword ascii
		 $a5= "res/drawable/common_google_signin_btn_icon_dark_normal.xmlmQ" fullword ascii
		 $a6= "res/drawable/common_google_signin_btn_icon_dark_normal.xmlPK" fullword ascii
		 $a7= "res/drawable/common_google_signin_btn_icon_light_focused.xml" fullword ascii
		 $a8= "res/drawable/common_google_signin_btn_icon_light_focused.xmlmR=O" fullword ascii
		 $a9= "res/drawable/common_google_signin_btn_icon_light_focused.xmlPK" fullword ascii
		 $a10= ";;res/drawable/common_google_signin_btn_icon_light_normal.xml" fullword ascii
		 $a11= "res/drawable/common_google_signin_btn_icon_light_normal.xmlmQ" fullword ascii
		 $a12= "res/drawable/common_google_signin_btn_icon_light_normal.xmlPK" fullword ascii
		 $a13= ";;res/drawable/common_google_signin_btn_text_dark_focused.xml" fullword ascii
		 $a14= "res/drawable/common_google_signin_btn_text_dark_focused.xmlmR" fullword ascii
		 $a15= "res/drawable/common_google_signin_btn_text_dark_focused.xmlPK" fullword ascii
		 $a16= "::res/drawable/common_google_signin_btn_text_dark_normal.xml" fullword ascii
		 $a17= "res/drawable/common_google_signin_btn_text_dark_normal.xmlPK" fullword ascii
		 $a18= "res/drawable/common_google_signin_btn_text_light_focused.xml" fullword ascii
		 $a19= "res/drawable/common_google_signin_btn_text_light_focused.xmlmR=O" fullword ascii
		 $a20= "res/drawable/common_google_signin_btn_text_light_focused.xmlPK" fullword ascii
		 $a21= ";;res/drawable/common_google_signin_btn_text_light_normal.xml" fullword ascii
		 $a22= "res/drawable/common_google_signin_btn_text_light_normal.xmlPK" fullword ascii
		 $a23= "res/layout/notification_template_big_media_narrow_custom.xml" fullword ascii
		 $a24= "res/layout/notification_template_big_media_narrow_custom.xmlPK" fullword ascii

		 $hex1= {246131303d20223b3b}
		 $hex2= {246131313d20227265}
		 $hex3= {246131323d20227265}
		 $hex4= {246131333d20223b3b}
		 $hex5= {246131343d20227265}
		 $hex6= {246131353d20227265}
		 $hex7= {246131363d20223a3a}
		 $hex8= {246131373d20227265}
		 $hex9= {246131383d20227265}
		 $hex10= {246131393d20227265}
		 $hex11= {2461313d20223b3b72}
		 $hex12= {246132303d20227265}
		 $hex13= {246132313d20223b3b}
		 $hex14= {246132323d20227265}
		 $hex15= {246132333d20227265}
		 $hex16= {246132343d20227265}
		 $hex17= {2461323d2022726573}
		 $hex18= {2461333d2022726573}
		 $hex19= {2461343d20223a3a72}
		 $hex20= {2461353d2022726573}
		 $hex21= {2461363d2022726573}
		 $hex22= {2461373d2022726573}
		 $hex23= {2461383d2022726573}
		 $hex24= {2461393d2022726573}

	condition:
		16 of them
}
