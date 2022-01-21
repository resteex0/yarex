
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Zumanek 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Zumanek {
	meta: 
		 description= "vx_underground2_Zumanek Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-18-07" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "06b158b22abdfc010e3dad8f77378ef1"
		 hash2= "116ba343f4b9692ffb665de3b6e15787"
		 hash3= "66ec4dfddf8ca0e5d30a73bf2931d740"
		 hash4= "9efbb5cf8f05c8bf4eb07e20586e0f97"
		 hash5= "c940b613a8d78ce2f9a644c3c2f12853"

	strings:

	
 		 $s1= "bcdefghijklmnopqrstuvwxyz{|}~" fullword wide
		 $s2= "CL_MPPAUSE CL_MPPLAY CL_MPPREV" fullword wide
		 $s3= "CL_MPRECORD CL_MPSTEP CL_MPSTOP" fullword wide
		 $s4= "CL_MPRECORD CL_MPSTEP CL_MPSTOP DI_MPBACK" fullword wide
		 $s5= "DI_MPPAUSE DI_MPPLAY DI_MPPREV" fullword wide
		 $s6= "DI_MPRECORD DI_MPSTEP DI_MPSTOP EN_MPBACK" fullword wide
		 $s7= "EN_MPPAUSE EN_MPPLAY EN_MPPREV" fullword wide
		 $s8= "EN_MPRECORD EN_MPSTEP EN_MPSTOP" fullword wide
		 $s9= "EN_MPRECORD EN_MPSTEP EN_MPSTOP CHARTABLE" fullword wide
		 $s10= "IW_GFX_COMBOBOXDOWNARROWBUTTON" fullword wide
		 $s11= "IW_GFX_COOLCHECKBOX_FALSE" fullword wide
		 $s12= "IW_GFX_DBNAV_CANCELDISABLED" fullword wide
		 $s13= "IW_GFX_DBNAV_DELETEDISABLED" fullword wide
		 $s14= "IW_GFX_DBNAV_EDITDISABLED" fullword wide
		 $s15= "IW_GFX_DBNAV_FIRSTDISABLED" fullword wide
		 $s16= "IW_GFX_DBNAV_INSERTDISABLED" fullword wide
		 $s17= "IW_GFX_DBNAV_LASTDISABLED" fullword wide
		 $s18= "IW_GFX_DBNAV_NEXTDISABLED" fullword wide
		 $s19= "IW_GFX_DBNAV_POSTDISABLED" fullword wide
		 $s20= "IW_GFX_DBNAV_PRIORDISABLED" fullword wide
		 $s21= "IW_GFX_DBNAV_REFRESHDISABLED" fullword wide
		 $s22= "IW_GFX_SESSIONTIMEOUT IW_GFX_TP" fullword wide
		 $s23= "IW_JS_TABCONTROL IW_WAP_DB" fullword wide
		 $s24= "WIN10STYLE WIN7STYLE WIN8STYLE" fullword wide
		 $s25= "WINXCTRLS_MOMENTUMDOTS_BLACK_24" fullword wide
		 $s26= "WINXCTRLS_MOMENTUMDOTS_BLACK_32" fullword wide
		 $s27= "WINXCTRLS_MOMENTUMDOTS_BLACK_48" fullword wide
		 $s28= "WINXCTRLS_MOMENTUMDOTS_BLACK_64" fullword wide
		 $s29= "WINXCTRLS_MOMENTUMDOTS_WHITE_24" fullword wide
		 $s30= "WINXCTRLS_MOMENTUMDOTS_WHITE_32" fullword wide
		 $s31= "WINXCTRLS_MOMENTUMDOTS_WHITE_48" fullword wide
		 $s32= "WINXCTRLS_SEARCHINDICATORS_TEXT" fullword wide
		 $s33= "WINXCTRLS_SECTORRING_BLACK_24" fullword wide
		 $s34= "WINXCTRLS_SECTORRING_BLACK_32" fullword wide
		 $s35= "WINXCTRLS_SECTORRING_BLACK_48" fullword wide
		 $s36= "WINXCTRLS_SECTORRING_BLACK_64" fullword wide
		 $s37= "WINXCTRLS_SECTORRING_WHITE_24" fullword wide
		 $s38= "WINXCTRLS_SECTORRING_WHITE_32" fullword wide
		 $s39= "WINXCTRLS_SECTORRING_WHITE_48" fullword wide
		 $s40= "WINXCTRLS_SECTORRING_WHITE_64" fullword wide

		 $hex1= {247331303d20224957}
		 $hex2= {247331313d20224957}
		 $hex3= {247331323d20224957}
		 $hex4= {247331333d20224957}
		 $hex5= {247331343d20224957}
		 $hex6= {247331353d20224957}
		 $hex7= {247331363d20224957}
		 $hex8= {247331373d20224957}
		 $hex9= {247331383d20224957}
		 $hex10= {247331393d20224957}
		 $hex11= {2473313d2022626364}
		 $hex12= {247332303d20224957}
		 $hex13= {247332313d20224957}
		 $hex14= {247332323d20224957}
		 $hex15= {247332333d20224957}
		 $hex16= {247332343d20225749}
		 $hex17= {247332353d20225749}
		 $hex18= {247332363d20225749}
		 $hex19= {247332373d20225749}
		 $hex20= {247332383d20225749}
		 $hex21= {247332393d20225749}
		 $hex22= {2473323d2022434c5f}
		 $hex23= {247333303d20225749}
		 $hex24= {247333313d20225749}
		 $hex25= {247333323d20225749}
		 $hex26= {247333333d20225749}
		 $hex27= {247333343d20225749}
		 $hex28= {247333353d20225749}
		 $hex29= {247333363d20225749}
		 $hex30= {247333373d20225749}
		 $hex31= {247333383d20225749}
		 $hex32= {247333393d20225749}
		 $hex33= {2473333d2022434c5f}
		 $hex34= {247334303d20225749}
		 $hex35= {2473343d2022434c5f}
		 $hex36= {2473353d202244495f}
		 $hex37= {2473363d202244495f}
		 $hex38= {2473373d2022454e5f}
		 $hex39= {2473383d2022454e5f}
		 $hex40= {2473393d2022454e5f}

	condition:
		26 of them
}
