
/*
   YARA Rule Set
   Author: resteex
   Identifier: BandarChor_Ransomware 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_BandarChor_Ransomware {
	meta: 
		 description= "BandarChor_Ransomware Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_23-58-55" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "226b276b333804a0a5aac78d8e11ddf0"
		 hash2= "5f7e9108d4fa09a6cd9c89f39bb51229"
		 hash3= "5fab6fbdff1a72cd5eafdd27b5ee11a9"
		 hash4= "7c9ee8c189f40e2f9ebd2660a2d2f65d"
		 hash5= "81597a3dca5e7302766352fdcc2637a2"
		 hash6= "8ac04f77862e7778b0950e2beb397b79"
		 hash7= "9146ae0009e78aa23b05850a9027a9f8"

	strings:

	
 		 $s1= "052055055050055048052050054070" fullword wide
		 $s2= "055056052052054053054067054057054068" fullword wide
		 $s3= "28C4C820-401A-101B-A3C9-08002B2F49FB" fullword wide
		 $s4= "%2protocolStdFileEditingserver" fullword wide
		 $s5= "%2protocolStdFileEditingverb0" fullword wide
		 $s6= "78E1BDD1-9941-11cf-9756-00AA00C00908" fullword wide
		 $s7= "*AC:Fa_New1_PCBhHH.vbp" fullword wide
		 $s8= "*AC:Fa_New1_PCNJJi.vbp" fullword wide
		 $s9= "C4145310-469C-11d1-B182-00A0C922E820" fullword wide
		 $s10= "CLSID%1DefaultExtension" fullword wide
		 $s11= "commdlg_LBSelChangedNotify" fullword wide
		 $s12= "dD1B20A40-59D5-101B-A3C9-08002B2F49FB" fullword wide
		 $s13= "e72E67120-5959-11cf-91F6-C2863C385E30" fullword wide
		 $s14= "emgkgtgnnmnmninigthkgogggvmkhinjggnvm" fullword wide
		 $s15= "IW_GFX_COOLCHECKBOX_FALSE" fullword wide
		 $s16= "IW_GFX_DBNAV_CANCELDISABLED" fullword wide
		 $s17= "IW_GFX_DBNAV_DELETEDISABLED" fullword wide
		 $s18= "IW_GFX_DBNAV_EDITDISABLED" fullword wide
		 $s19= "IW_GFX_DBNAV_FIRSTDISABLED" fullword wide
		 $s20= "IW_GFX_DBNAV_INSERTDISABLED" fullword wide
		 $s21= "IW_GFX_DBNAV_LASTDISABLED" fullword wide
		 $s22= "IW_GFX_DBNAV_NEXTDISABLED" fullword wide
		 $s23= "IW_GFX_DBNAV_POSTDISABLED" fullword wide
		 $s24= "IW_GFX_DBNAV_PRIORDISABLED" fullword wide
		 $s25= "IW_GFX_DBNAV_REFRESHDISABLED" fullword wide
		 $s26= "IW_GFX_SESSIONTIMEOUT IW_GFX_TP" fullword wide
		 $s27= "IW_JS_TABCONTROL IW_WAP_DB" fullword wide
		 $s28= "mgkgtgnnmnmninigthkgogggvmkhinjggnvm" fullword wide
		 $s29= "r1F3D5522-3F42-11d1-B2FA-00A0C908FB55" fullword wide

		 $hex1= {247331303d2022434c}
		 $hex2= {247331313d2022636f}
		 $hex3= {247331323d20226444}
		 $hex4= {247331333d20226537}
		 $hex5= {247331343d2022656d}
		 $hex6= {247331353d20224957}
		 $hex7= {247331363d20224957}
		 $hex8= {247331373d20224957}
		 $hex9= {247331383d20224957}
		 $hex10= {247331393d20224957}
		 $hex11= {2473313d2022303532}
		 $hex12= {247332303d20224957}
		 $hex13= {247332313d20224957}
		 $hex14= {247332323d20224957}
		 $hex15= {247332333d20224957}
		 $hex16= {247332343d20224957}
		 $hex17= {247332353d20224957}
		 $hex18= {247332363d20224957}
		 $hex19= {247332373d20224957}
		 $hex20= {247332383d20226d67}
		 $hex21= {247332393d20227231}
		 $hex22= {2473323d2022303535}
		 $hex23= {2473333d2022323843}
		 $hex24= {2473343d2022253270}
		 $hex25= {2473353d2022253270}
		 $hex26= {2473363d2022373845}
		 $hex27= {2473373d20222a4143}
		 $hex28= {2473383d20222a4143}
		 $hex29= {2473393d2022433431}

	condition:
		19 of them
}
