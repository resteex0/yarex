
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_KeyPass 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_KeyPass {
	meta: 
		 description= "Win32_KeyPass Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_19-54-56" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "6999c944d1c98b2739d015448c99a291"

	strings:

	
 		 $s1= "%08lX%04X%04x%02X%02X%02X%02X%02X%02X%02X%02X" fullword wide
		 $s2= "%08lX-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X" fullword wide
		 $s3= "af:ddvctoolsvc7libsshipatlmfcsrcmfcviewcore.cpp" fullword wide
		 $s4= "af:ddvctoolsvc7libsshipatlmfcsrcmfcwinfrm.cpp" fullword wide
		 $s5= "AFX_WM_ON_BEFORE_SHOW_RIBBON_ITEM_MENU" fullword wide
		 $s6= "AFX_WM_ON_HIGHLIGHT_RIBBON_LIST_ITEM" fullword wide
		 $s7= "aMFCShellListCtrl_EnableShellContextMenu" fullword wide
		 $s8= "@f:ddvctoolsvc7libsshipatlmfcincludeafxwin2.inl" fullword wide
		 $s9= "f:ddvctoolsvc7libsshipatlmfcsrcmfcappcore.cpp" fullword wide
		 $s10= "f:ddvctoolsvc7libsshipatlmfcsrcmfcarray_s.cpp" fullword wide
		 $s11= "f:ddvctoolsvc7libsshipatlmfcsrcmfcauxdata.cpp" fullword wide
		 $s12= "f:ddvctoolsvc7libsshipatlmfcsrcmfcfilecore.cpp" fullword wide
		 $s13= "f:ddvctoolsvc7libsshipatlmfcsrcmfcoledrop2.cpp" fullword wide
		 $s14= "f:ddvctoolsvc7libsshipatlmfcsrcmfcoleipfrm.cpp" fullword wide
		 $s15= "f:ddvctoolsvc7libsshipatlmfcsrcmfcolestrm.cpp" fullword wide
		 $s16= "f:ddvctoolsvc7libsshipatlmfcsrcmfcwinctrl2.cpp" fullword wide
		 $s17= "IDB_OFFICE2007_MENU_BTN_VERT_SEPARATOR" fullword wide
		 $s18= "IDB_OFFICE2007_POPUPMENU_RESIZEBAR_ICON_HV" fullword wide
		 $s19= "IDB_OFFICE2007_POPUPMENU_RESIZEBAR_ICON_HVT" fullword wide
		 $s20= "IDB_OFFICE2007_POPUPMENU_RESIZEBAR_ICON_V" fullword wide
		 $s21= "IDB_OFFICE2007_RIBBON_BORDER_FLOATY" fullword wide
		 $s22= "IDB_OFFICE2007_RIBBON_BTN_DEFAULT_ICON" fullword wide
		 $s23= "IDB_OFFICE2007_RIBBON_BTN_DEFAULT_IMAGE" fullword wide
		 $s24= "IDB_OFFICE2007_RIBBON_BTN_DEFAULT_QAT" fullword wide
		 $s25= "IDB_OFFICE2007_RIBBON_BTN_DEFAULT_QAT_ICON" fullword wide
		 $s26= "IDB_OFFICE2007_RIBBON_BTN_GROUPMENU_F_C" fullword wide
		 $s27= "IDB_OFFICE2007_RIBBON_BTN_GROUPMENU_F_M" fullword wide
		 $s28= "IDB_OFFICE2007_RIBBON_BTN_GROUPMENU_L_C" fullword wide
		 $s29= "IDB_OFFICE2007_RIBBON_BTN_GROUPMENU_L_M" fullword wide
		 $s30= "IDB_OFFICE2007_RIBBON_BTN_GROUPMENU_M_C" fullword wide
		 $s31= "IDB_OFFICE2007_RIBBON_BTN_GROUPMENU_M_M" fullword wide
		 $s32= "IDB_OFFICE2007_RIBBON_BTN_LAUNCH_ICON" fullword wide
		 $s33= "IDB_OFFICE2007_RIBBON_BTN_PALETTE_B" fullword wide
		 $s34= "IDB_OFFICE2007_RIBBON_BTN_PALETTE_M" fullword wide
		 $s35= "IDB_OFFICE2007_RIBBON_BTN_PALETTE_T" fullword wide
		 $s36= "IDB_OFFICE2007_RIBBON_BTN_PANEL_MAIN" fullword wide
		 $s37= "IDB_OFFICE2007_RIBBON_BTN_STATUS_PANE" fullword wide
		 $s38= "IDB_OFFICE2007_RIBBON_CAPTION_QA_GLASS" fullword wide
		 $s39= "IDB_OFFICE2007_RIBBON_CATEGORY_BACK" fullword wide
		 $s40= "IDB_OFFICE2007_RIBBON_CATEGORY_TAB_SEP" fullword wide
		 $s41= "IDB_OFFICE2007_RIBBON_CONTEXT_PANEL_BACK_B" fullword wide
		 $s42= "IDB_OFFICE2007_RIBBON_CONTEXT_PANEL_BACK_T" fullword wide
		 $s43= "IDB_OFFICE2007_RIBBON_CONTEXT_SEPARATOR" fullword wide
		 $s44= "IDB_OFFICE2007_RIBBON_PANEL_MAIN_BORDER" fullword wide
		 $s45= "IDB_OFFICE2007_RIBBON_PANEL_SEPARATOR" fullword wide
		 $s46= "IDB_OFFICE2007_RIBBON_PROGRESS_BACK" fullword wide
		 $s47= "IDB_OFFICE2007_RIBBON_PROGRESS_INFINITY" fullword wide
		 $s48= "IDB_OFFICE2007_RIBBON_PROGRESS_NORMAL" fullword wide
		 $s49= "IDB_OFFICE2007_RIBBON_PROGRESS_NORMAL_EXT" fullword wide
		 $s50= "IDB_OFFICE2007_RIBBON_SLIDER_BTN_MINUS" fullword wide
		 $s51= "IDB_OFFICE2007_RIBBON_SLIDER_BTN_PLUS" fullword wide
		 $s52= "IDB_OFFICE2007_STATUSBAR_PANEBORDER" fullword wide
		 $s53= "MFCColorButton_EnableAutomaticButton" fullword wide
		 $s54= "NMFCShellTreeCtrl_EnableShellContextMenu" fullword wide
		 $s55= "SoftwareMicrosoftWindowsCurrentVersionPoliciesComdlg32" fullword wide
		 $s56= "SoftwareMicrosoftWindowsCurrentVersionPoliciesExplorer" fullword wide
		 $s57= "SoftwareMicrosoftWindowsCurrentVersionPoliciesNetwork" fullword wide
		 $s58= "]SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $a1= "af:ddvctoolsvc7libsshipatlmfcsrcmfcviewcore.cpp" fullword ascii
		 $a2= "af:ddvctoolsvc7libsshipatlmfcsrcmfcwinfrm.cpp" fullword ascii
		 $a3= "@f:ddvctoolsvc7libsshipatlmfcincludeafxwin2.inl" fullword ascii
		 $a4= "f:ddvctoolsvc7libsshipatlmfcsrcmfcappcore.cpp" fullword ascii
		 $a5= "f:ddvctoolsvc7libsshipatlmfcsrcmfcarray_s.cpp" fullword ascii
		 $a6= "f:ddvctoolsvc7libsshipatlmfcsrcmfcauxdata.cpp" fullword ascii
		 $a7= "f:ddvctoolsvc7libsshipatlmfcsrcmfcfilecore.cpp" fullword ascii
		 $a8= "f:ddvctoolsvc7libsshipatlmfcsrcmfcoledrop2.cpp" fullword ascii
		 $a9= "f:ddvctoolsvc7libsshipatlmfcsrcmfcoleipfrm.cpp" fullword ascii
		 $a10= "f:ddvctoolsvc7libsshipatlmfcsrcmfcolestrm.cpp" fullword ascii
		 $a11= "f:ddvctoolsvc7libsshipatlmfcsrcmfcwinctrl2.cpp" fullword ascii
		 $a12= "SoftwareMicrosoftWindowsCurrentVersionPoliciesComdlg32" fullword ascii
		 $a13= "SoftwareMicrosoftWindowsCurrentVersionPoliciesExplorer" fullword ascii
		 $a14= "SoftwareMicrosoftWindowsCurrentVersionPoliciesNetwork" fullword ascii

		 $hex1= {246131303d2022663a}
		 $hex2= {246131313d2022663a}
		 $hex3= {246131323d2022536f}
		 $hex4= {246131333d2022536f}
		 $hex5= {246131343d2022536f}
		 $hex6= {2461313d202261663a}
		 $hex7= {2461323d202261663a}
		 $hex8= {2461333d202240663a}
		 $hex9= {2461343d2022663a64}
		 $hex10= {2461353d2022663a64}
		 $hex11= {2461363d2022663a64}
		 $hex12= {2461373d2022663a64}
		 $hex13= {2461383d2022663a64}
		 $hex14= {2461393d2022663a64}
		 $hex15= {247331303d2022663a}
		 $hex16= {247331313d2022663a}
		 $hex17= {247331323d2022663a}
		 $hex18= {247331333d2022663a}
		 $hex19= {247331343d2022663a}
		 $hex20= {247331353d2022663a}
		 $hex21= {247331363d2022663a}
		 $hex22= {247331373d20224944}
		 $hex23= {247331383d20224944}
		 $hex24= {247331393d20224944}
		 $hex25= {2473313d2022253038}
		 $hex26= {247332303d20224944}
		 $hex27= {247332313d20224944}
		 $hex28= {247332323d20224944}
		 $hex29= {247332333d20224944}
		 $hex30= {247332343d20224944}
		 $hex31= {247332353d20224944}
		 $hex32= {247332363d20224944}
		 $hex33= {247332373d20224944}
		 $hex34= {247332383d20224944}
		 $hex35= {247332393d20224944}
		 $hex36= {2473323d2022253038}
		 $hex37= {247333303d20224944}
		 $hex38= {247333313d20224944}
		 $hex39= {247333323d20224944}
		 $hex40= {247333333d20224944}
		 $hex41= {247333343d20224944}
		 $hex42= {247333353d20224944}
		 $hex43= {247333363d20224944}
		 $hex44= {247333373d20224944}
		 $hex45= {247333383d20224944}
		 $hex46= {247333393d20224944}
		 $hex47= {2473333d202261663a}
		 $hex48= {247334303d20224944}
		 $hex49= {247334313d20224944}
		 $hex50= {247334323d20224944}
		 $hex51= {247334333d20224944}
		 $hex52= {247334343d20224944}
		 $hex53= {247334353d20224944}
		 $hex54= {247334363d20224944}
		 $hex55= {247334373d20224944}
		 $hex56= {247334383d20224944}
		 $hex57= {247334393d20224944}
		 $hex58= {2473343d202261663a}
		 $hex59= {247335303d20224944}
		 $hex60= {247335313d20224944}
		 $hex61= {247335323d20224944}
		 $hex62= {247335333d20224d46}
		 $hex63= {247335343d20224e4d}
		 $hex64= {247335353d2022536f}
		 $hex65= {247335363d2022536f}
		 $hex66= {247335373d2022536f}
		 $hex67= {247335383d20225d53}
		 $hex68= {2473353d2022414658}
		 $hex69= {2473363d2022414658}
		 $hex70= {2473373d2022614d46}
		 $hex71= {2473383d202240663a}
		 $hex72= {2473393d2022663a64}

	condition:
		9 of them
}
