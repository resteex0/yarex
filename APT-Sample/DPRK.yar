
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_DPRK 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_DPRK {
	meta: 
		 description= "APT_Sample_DPRK Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-22_14-14-42" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "143cb4f16dcfc16a02812718acd32c8f"
		 hash2= "234b42fb42080176c6ffd240145f2c0c"
		 hash3= "3e36d7056812d0c1852e7b8f446b7e0f"
		 hash4= "4613f51087f01715bf9132c704aea2c2"
		 hash5= "4731cbaee7aca37b596e38690160a749"
		 hash6= "6a261443299788af1467142d5f538b2c"
		 hash7= "be6de8b0c3d1894eca18cdf8b6a37aa6"
		 hash8= "e3d03829cbec1a8cca56c6ae730ba9a8"
		 hash9= "eb9db98914207815d763e2e5cfbe96b9"

	strings:

	
 		 $s1= "ABDCEFGHIJKLNMOPQRSTVUWXYZ" fullword wide
		 $s2= "com.security01.android.fastapplock" fullword wide
		 $s3= "com.studioapplock.free.android" fullword wide
		 $s4= "com.umsikgonghap.health.gonghap" fullword wide
		 $s5= "C:WindowsSys64intelservice.exe" fullword wide
		 $s6= "C:WindowsSys64updater.exe" fullword wide
		 $s7= "HARDWAREDESCRIPTIONSystemCentralProcessor0" fullword wide
		 $a1= "::Base.TextAppearance.AppCompat.Light.Widget.PopupMenu.Large" fullword ascii
		 $a2= "::Base.TextAppearance.AppCompat.Light.Widget.PopupMenu.Small" fullword ascii
		 $a3= "Base.TextAppearance.AppCompat.Widget.ActionBar.Title.Inverse" fullword ascii
		 $a4= "com.akexorcist.roundcornerprogressbar.RoundCornerProgressBar" fullword ascii
		 $a5= "com.github.pwittchen.reactivenetwork.library.ReactiveNetwork" fullword ascii
		 $a6= ";;https://creativecommons.org/publicdomain/zero/1.0/legalcode" fullword ascii
		 $a7= "==https://developer.android.com/google/play-services/index.html" fullword ascii
		 $a8= "https://github.com/akexorcist/Android-RoundCornerProgressBar" fullword ascii
		 $a9= "https://github.com/Flipboard/bottomsheet/blob/master/LICENSE" fullword ascii
		 $a10= ">>https://github.com/futuresimple/android-floating-action-button" fullword ascii
		 $a11= ";;https://github.com/LGDeveloper/QCircle-Design-Template/wiki" fullword ascii
		 $a12= "::https://github.com/nostra13/Android-Universal-Image-Loader" fullword ascii
		 $a13= "==password_is_not_required_after_unlocking_for_a_period_of_time" fullword ascii
		 $a14= "::res/color/abc_primary_text_disable_only_material_light.xml" fullword ascii
		 $a15= "res/color/abc_primary_text_disable_only_material_light.xmlmP" fullword ascii
		 $a16= "res/color/abc_primary_text_disable_only_material_light.xmlPK" fullword ascii
		 $a17= "::res/color-v23/abc_btn_colored_borderless_text_material.xml" fullword ascii
		 $a18= "res/color-v23/abc_btn_colored_borderless_text_material.xmlmP" fullword ascii
		 $a19= "res/color-v23/abc_btn_colored_borderless_text_material.xmlPK" fullword ascii
		 $a20= "::res/drawable/abc_spinner_textfield_background_material.xml" fullword ascii
		 $a21= "res/drawable/abc_spinner_textfield_background_material.xmlPK" fullword ascii
		 $a22= ";;res/drawable-hdpi-v4/abc_btn_rating_star_off_mtrl_alpha.png" fullword ascii
		 $a23= "res/drawable-hdpi-v4/abc_btn_rating_star_off_mtrl_alpha.pngPK" fullword ascii
		 $a24= "::res/drawable-hdpi-v4/abc_btn_rating_star_on_mtrl_alpha.png" fullword ascii
		 $a25= "res/drawable-hdpi-v4/abc_btn_rating_star_on_mtrl_alpha.pngPK" fullword ascii
		 $a26= "::res/drawable-hdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.png" fullword ascii
		 $a27= "res/drawable-hdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.pngPK" fullword ascii
		 $a28= "res/drawable-hdpi-v4/abc_cab_background_top_mtrl_alpha.9.png" fullword ascii
		 $a29= "res/drawable-hdpi-v4/abc_cab_background_top_mtrl_alpha.9.pngPK" fullword ascii
		 $a30= "res/drawable-hdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png" fullword ascii
		 $a31= "res/drawable-hdpi-v4/abc_ic_commit_search_api_mtrl_alpha.pngPK" fullword ascii
		 $a32= "res/drawable-hdpi-v4/abc_ic_menu_moreoverflow_mtrl_alpha.png" fullword ascii
		 $a33= "res/drawable-hdpi-v4/abc_ic_menu_moreoverflow_mtrl_alpha.pngPK" fullword ascii
		 $a34= ";;res/drawable-hdpi-v4/abc_ic_voice_search_api_mtrl_alpha.png" fullword ascii
		 $a35= "res/drawable-hdpi-v4/abc_ic_voice_search_api_mtrl_alpha.pngPK" fullword ascii
		 $a36= "res/drawable-hdpi-v4/abc_list_selector_disabled_holo_dark.9.png" fullword ascii
		 $a37= "res/drawable-hdpi-v4/abc_list_selector_disabled_holo_light.9.png" fullword ascii
		 $a38= ";;res/drawable-hdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.png" fullword ascii
		 $a39= "res/drawable-hdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.pngPK" fullword ascii
		 $a40= "res/drawable-hdpi-v4/abc_scrubber_control_off_mtrl_alpha.png" fullword ascii
		 $a41= "res/drawable-hdpi-v4/abc_scrubber_control_off_mtrl_alpha.pngPK" fullword ascii
		 $a42= "::res/drawable-hdpi-v4/abc_scrubber_primary_mtrl_alpha.9.png" fullword ascii
		 $a43= "res/drawable-hdpi-v4/abc_scrubber_primary_mtrl_alpha.9.pngPK" fullword ascii
		 $a44= "==res/drawable-hdpi-v4/abc_textfield_activated_mtrl_alpha.9.png" fullword ascii
		 $a45= "res/drawable-hdpi-v4/abc_textfield_activated_mtrl_alpha.9.png" fullword ascii
		 $a46= "res/drawable-hdpi-v4/abc_textfield_activated_mtrl_alpha.9.pngPK" fullword ascii
		 $a47= ";;res/drawable-hdpi-v4/abc_textfield_default_mtrl_alpha.9.png" fullword ascii
		 $a48= "res/drawable-hdpi-v4/abc_textfield_default_mtrl_alpha.9.pngPK" fullword ascii
		 $a49= ">>res/drawable-hdpi-v4/abc_text_select_handle_left_mtrl_dark.png" fullword ascii
		 $a50= "res/drawable-hdpi-v4/abc_text_select_handle_left_mtrl_dark.png" fullword ascii
		 $a51= "res/drawable-hdpi-v4/abc_text_select_handle_left_mtrl_dark.pngPK" fullword ascii
		 $a52= "res/drawable-hdpi-v4/abc_text_select_handle_left_mtrl_light.png" fullword ascii
		 $a53= "res/drawable-hdpi-v4/abc_text_select_handle_middle_mtrl_dark.png" fullword ascii
		 $a54= "res/drawable-hdpi-v4/abc_text_select_handle_right_mtrl_dark.png" fullword ascii
		 $a55= "res/drawable-hdpi-v4/abc_text_select_handle_right_mtrl_light.png" fullword ascii
		 $a56= "res/drawable-hdpi-v4/ic_action_navigation_close_inverted.png" fullword ascii
		 $a57= "res/drawable-hdpi-v4/ic_action_navigation_close_inverted.pngPK" fullword ascii
		 $a58= "::res/drawable-hdpi-v4/notify_panel_notification_icon_bg.png" fullword ascii
		 $a59= "res/drawable-hdpi-v4/notify_panel_notification_icon_bg.pngPK" fullword ascii
		 $a60= ">>res/drawable-ldrtl-hdpi-v17/abc_ic_menu_copy_mtrl_am_alpha.png" fullword ascii
		 $a61= "res/drawable-ldrtl-hdpi-v17/abc_ic_menu_copy_mtrl_am_alpha.png" fullword ascii
		 $a62= "res/drawable-ldrtl-hdpi-v17/abc_ic_menu_copy_mtrl_am_alpha.pngPK" fullword ascii
		 $a63= "::res/drawable-ldrtl-hdpi-v17/abc_ic_menu_cut_mtrl_alpha.png" fullword ascii
		 $a64= "res/drawable-ldrtl-hdpi-v17/abc_ic_menu_cut_mtrl_alpha.pngPK" fullword ascii
		 $a65= ";;res/drawable-ldrtl-hdpi-v17/abc_spinner_mtrl_am_alpha.9.png" fullword ascii
		 $a66= "res/drawable-ldrtl-hdpi-v17/abc_spinner_mtrl_am_alpha.9.pngPK" fullword ascii
		 $a67= ";;res/drawable-ldrtl-hdpi-v4/abc_ic_ab_back_mtrl_am_alpha.png" fullword ascii
		 $a68= "res/drawable-ldrtl-hdpi-v4/abc_ic_ab_back_mtrl_am_alpha.pngPK" fullword ascii
		 $a69= "==res/drawable-ldrtl-hdpi-v4/abc_ic_menu_copy_mtrl_am_alpha.png" fullword ascii
		 $a70= "res/drawable-ldrtl-hdpi-v4/abc_ic_menu_copy_mtrl_am_alpha.png" fullword ascii
		 $a71= "res/drawable-ldrtl-hdpi-v4/abc_ic_menu_copy_mtrl_am_alpha.pngPK" fullword ascii
		 $a72= "::res/drawable-ldrtl-hdpi-v4/abc_spinner_mtrl_am_alpha.9.png" fullword ascii
		 $a73= "res/drawable-ldrtl-hdpi-v4/abc_spinner_mtrl_am_alpha.9.pngPK" fullword ascii
		 $a74= ">>res/drawable-ldrtl-mdpi-v17/abc_ic_menu_copy_mtrl_am_alpha.png" fullword ascii
		 $a75= "res/drawable-ldrtl-mdpi-v17/abc_ic_menu_copy_mtrl_am_alpha.png" fullword ascii
		 $a76= "res/drawable-ldrtl-mdpi-v17/abc_ic_menu_copy_mtrl_am_alpha.pngPK" fullword ascii
		 $a77= "::res/drawable-ldrtl-mdpi-v17/abc_ic_menu_cut_mtrl_alpha.png" fullword ascii
		 $a78= "res/drawable-ldrtl-mdpi-v17/abc_ic_menu_cut_mtrl_alpha.pngPK" fullword ascii
		 $a79= ";;res/drawable-ldrtl-mdpi-v17/abc_spinner_mtrl_am_alpha.9.png" fullword ascii
		 $a80= "res/drawable-ldrtl-mdpi-v17/abc_spinner_mtrl_am_alpha.9.pngPK" fullword ascii
		 $a81= ";;res/drawable-ldrtl-mdpi-v4/abc_ic_ab_back_mtrl_am_alpha.png" fullword ascii
		 $a82= "res/drawable-ldrtl-mdpi-v4/abc_ic_ab_back_mtrl_am_alpha.pngPK" fullword ascii
		 $a83= "==res/drawable-ldrtl-mdpi-v4/abc_ic_menu_copy_mtrl_am_alpha.png" fullword ascii
		 $a84= "res/drawable-ldrtl-mdpi-v4/abc_ic_menu_copy_mtrl_am_alpha.png" fullword ascii
		 $a85= "res/drawable-ldrtl-mdpi-v4/abc_ic_menu_copy_mtrl_am_alpha.pngPK" fullword ascii
		 $a86= "::res/drawable-ldrtl-mdpi-v4/abc_spinner_mtrl_am_alpha.9.png" fullword ascii
		 $a87= "res/drawable-ldrtl-mdpi-v4/abc_spinner_mtrl_am_alpha.9.pngPK" fullword ascii
		 $a88= "res/drawable-ldrtl-xhdpi-v17/abc_ic_menu_copy_mtrl_am_alpha.png" fullword ascii
		 $a89= ";;res/drawable-ldrtl-xhdpi-v17/abc_ic_menu_cut_mtrl_alpha.png" fullword ascii
		 $a90= "res/drawable-ldrtl-xhdpi-v17/abc_ic_menu_cut_mtrl_alpha.pngPK" fullword ascii
		 $a91= "res/drawable-ldrtl-xhdpi-v17/abc_spinner_mtrl_am_alpha.9.png" fullword ascii
		 $a92= "res/drawable-ldrtl-xhdpi-v17/abc_spinner_mtrl_am_alpha.9.pngPK" fullword ascii
		 $a93= "res/drawable-ldrtl-xhdpi-v4/abc_ic_ab_back_mtrl_am_alpha.png" fullword ascii
		 $a94= "res/drawable-ldrtl-xhdpi-v4/abc_ic_ab_back_mtrl_am_alpha.pngPK" fullword ascii
		 $a95= ">>res/drawable-ldrtl-xhdpi-v4/abc_ic_menu_copy_mtrl_am_alpha.png" fullword ascii
		 $a96= "res/drawable-ldrtl-xhdpi-v4/abc_ic_menu_copy_mtrl_am_alpha.png" fullword ascii
		 $a97= "res/drawable-ldrtl-xhdpi-v4/abc_ic_menu_copy_mtrl_am_alpha.pngPK" fullword ascii
		 $a98= "::res/drawable-ldrtl-xhdpi-v4/abc_ic_menu_cut_mtrl_alpha.png" fullword ascii
		 $a99= "res/drawable-ldrtl-xhdpi-v4/abc_ic_menu_cut_mtrl_alpha.pngPK" fullword ascii
		 $a100= ";;res/drawable-ldrtl-xhdpi-v4/abc_spinner_mtrl_am_alpha.9.png" fullword ascii
		 $a101= "res/drawable-ldrtl-xhdpi-v4/abc_spinner_mtrl_am_alpha.9.pngPK" fullword ascii
		 $a102= "res/drawable-ldrtl-xxhdpi-v17/abc_ic_menu_copy_mtrl_am_alpha.png" fullword ascii
		 $a103= "res/drawable-ldrtl-xxhdpi-v17/abc_ic_menu_cut_mtrl_alpha.png" fullword ascii
		 $a104= "res/drawable-ldrtl-xxhdpi-v17/abc_ic_menu_cut_mtrl_alpha.pngPK" fullword ascii
		 $a105= "==res/drawable-ldrtl-xxhdpi-v17/abc_spinner_mtrl_am_alpha.9.png" fullword ascii
		 $a106= "res/drawable-ldrtl-xxhdpi-v17/abc_spinner_mtrl_am_alpha.9.png" fullword ascii
		 $a107= "res/drawable-ldrtl-xxhdpi-v17/abc_spinner_mtrl_am_alpha.9.pngPK" fullword ascii
		 $a108= "==res/drawable-ldrtl-xxhdpi-v4/abc_ic_ab_back_mtrl_am_alpha.png" fullword ascii
		 $a109= "res/drawable-ldrtl-xxhdpi-v4/abc_ic_ab_back_mtrl_am_alpha.png" fullword ascii
		 $a110= "res/drawable-ldrtl-xxhdpi-v4/abc_ic_ab_back_mtrl_am_alpha.pngPK" fullword ascii
		 $a111= "res/drawable-ldrtl-xxhdpi-v4/abc_ic_menu_copy_mtrl_am_alpha.png" fullword ascii
		 $a112= ";;res/drawable-ldrtl-xxhdpi-v4/abc_ic_menu_cut_mtrl_alpha.png" fullword ascii
		 $a113= "res/drawable-ldrtl-xxhdpi-v4/abc_ic_menu_cut_mtrl_alpha.pngPK" fullword ascii
		 $a114= "res/drawable-ldrtl-xxhdpi-v4/abc_spinner_mtrl_am_alpha.9.png" fullword ascii
		 $a115= "res/drawable-ldrtl-xxhdpi-v4/abc_spinner_mtrl_am_alpha.9.pngPK" fullword ascii
		 $a116= "==res/drawable-ldrtl-xxxhdpi-v17/abc_ic_menu_cut_mtrl_alpha.png" fullword ascii
		 $a117= "res/drawable-ldrtl-xxxhdpi-v17/abc_ic_menu_cut_mtrl_alpha.png" fullword ascii
		 $a118= "res/drawable-ldrtl-xxxhdpi-v17/abc_ic_menu_cut_mtrl_alpha.pngPK" fullword ascii
		 $a119= ">>res/drawable-ldrtl-xxxhdpi-v17/abc_spinner_mtrl_am_alpha.9.png" fullword ascii
		 $a120= "res/drawable-ldrtl-xxxhdpi-v17/abc_spinner_mtrl_am_alpha.9.png" fullword ascii
		 $a121= "res/drawable-ldrtl-xxxhdpi-v17/abc_spinner_mtrl_am_alpha.9.pngPK" fullword ascii
		 $a122= ">>res/drawable-ldrtl-xxxhdpi-v4/abc_ic_ab_back_mtrl_am_alpha.png" fullword ascii
		 $a123= "res/drawable-ldrtl-xxxhdpi-v4/abc_ic_ab_back_mtrl_am_alpha.png" fullword ascii
		 $a124= "res/drawable-ldrtl-xxxhdpi-v4/abc_ic_ab_back_mtrl_am_alpha.pngPK" fullword ascii
		 $a125= "res/drawable-ldrtl-xxxhdpi-v4/abc_ic_menu_copy_mtrl_am_alpha.png" fullword ascii
		 $a126= "res/drawable-ldrtl-xxxhdpi-v4/abc_ic_menu_cut_mtrl_alpha.png" fullword ascii
		 $a127= "res/drawable-ldrtl-xxxhdpi-v4/abc_ic_menu_cut_mtrl_alpha.pngPK" fullword ascii
		 $a128= "==res/drawable-ldrtl-xxxhdpi-v4/abc_spinner_mtrl_am_alpha.9.png" fullword ascii
		 $a129= "res/drawable-ldrtl-xxxhdpi-v4/abc_spinner_mtrl_am_alpha.9.png" fullword ascii
		 $a130= "res/drawable-ldrtl-xxxhdpi-v4/abc_spinner_mtrl_am_alpha.9.pngPK" fullword ascii
		 $a131= ";;res/drawable-mdpi-v4/abc_btn_rating_star_off_mtrl_alpha.png" fullword ascii
		 $a132= "res/drawable-mdpi-v4/abc_btn_rating_star_off_mtrl_alpha.pngPK" fullword ascii
		 $a133= "::res/drawable-mdpi-v4/abc_btn_rating_star_on_mtrl_alpha.png" fullword ascii
		 $a134= "res/drawable-mdpi-v4/abc_btn_rating_star_on_mtrl_alpha.pngPK" fullword ascii
		 $a135= "::res/drawable-mdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.png" fullword ascii
		 $a136= "res/drawable-mdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.pngPK" fullword ascii
		 $a137= "res/drawable-mdpi-v4/abc_cab_background_top_mtrl_alpha.9.png" fullword ascii
		 $a138= "res/drawable-mdpi-v4/abc_cab_background_top_mtrl_alpha.9.pngPK" fullword ascii
		 $a139= "res/drawable-mdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png" fullword ascii
		 $a140= "res/drawable-mdpi-v4/abc_ic_commit_search_api_mtrl_alpha.pngPK" fullword ascii
		 $a141= "res/drawable-mdpi-v4/abc_ic_menu_moreoverflow_mtrl_alpha.png" fullword ascii
		 $a142= "res/drawable-mdpi-v4/abc_ic_menu_moreoverflow_mtrl_alpha.pngPK" fullword ascii
		 $a143= ";;res/drawable-mdpi-v4/abc_ic_voice_search_api_mtrl_alpha.png" fullword ascii
		 $a144= "res/drawable-mdpi-v4/abc_ic_voice_search_api_mtrl_alpha.pngPK" fullword ascii
		 $a145= "res/drawable-mdpi-v4/abc_list_selector_disabled_holo_dark.9.png" fullword ascii
		 $a146= "res/drawable-mdpi-v4/abc_list_selector_disabled_holo_light.9.png" fullword ascii
		 $a147= ";;res/drawable-mdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.png" fullword ascii
		 $a148= "res/drawable-mdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.pngPK" fullword ascii
		 $a149= "res/drawable-mdpi-v4/abc_scrubber_control_off_mtrl_alpha.png" fullword ascii
		 $a150= "res/drawable-mdpi-v4/abc_scrubber_control_off_mtrl_alpha.pngPK" fullword ascii
		 $a151= "::res/drawable-mdpi-v4/abc_scrubber_primary_mtrl_alpha.9.png" fullword ascii
		 $a152= "res/drawable-mdpi-v4/abc_scrubber_primary_mtrl_alpha.9.pngPK" fullword ascii
		 $a153= "==res/drawable-mdpi-v4/abc_textfield_activated_mtrl_alpha.9.png" fullword ascii
		 $a154= "res/drawable-mdpi-v4/abc_textfield_activated_mtrl_alpha.9.png" fullword ascii
		 $a155= "res/drawable-mdpi-v4/abc_textfield_activated_mtrl_alpha.9.pngPK" fullword ascii
		 $a156= ";;res/drawable-mdpi-v4/abc_textfield_default_mtrl_alpha.9.png" fullword ascii
		 $a157= "res/drawable-mdpi-v4/abc_textfield_default_mtrl_alpha.9.pngPK" fullword ascii
		 $a158= ">>res/drawable-mdpi-v4/abc_text_select_handle_left_mtrl_dark.png" fullword ascii
		 $a159= "res/drawable-mdpi-v4/abc_text_select_handle_left_mtrl_dark.png" fullword ascii
		 $a160= "res/drawable-mdpi-v4/abc_text_select_handle_left_mtrl_dark.pngPK" fullword ascii
		 $a161= "res/drawable-mdpi-v4/abc_text_select_handle_left_mtrl_light.png" fullword ascii
		 $a162= "res/drawable-mdpi-v4/abc_text_select_handle_middle_mtrl_dark.png" fullword ascii
		 $a163= "res/drawable-mdpi-v4/abc_text_select_handle_right_mtrl_dark.png" fullword ascii
		 $a164= "res/drawable-mdpi-v4/abc_text_select_handle_right_mtrl_light.png" fullword ascii
		 $a165= "res/drawable-mdpi-v4/ic_action_navigation_close_inverted.png" fullword ascii
		 $a166= "res/drawable-mdpi-v4/ic_action_navigation_close_inverted.pngPK" fullword ascii
		 $a167= "::res/drawable-mdpi-v4/notify_panel_notification_icon_bg.png" fullword ascii
		 $a168= "res/drawable-mdpi-v4/notify_panel_notification_icon_bg.pngPK" fullword ascii
		 $a169= "res/drawable-v21/abc_action_bar_item_background_material.xml" fullword ascii
		 $a170= "res/drawable-v21/abc_action_bar_item_background_material.xml]" fullword ascii
		 $a171= "res/drawable-v21/abc_action_bar_item_background_material.xmlPK" fullword ascii
		 $a172= "==res/drawable-v21/design_bottom_navigation_item_background.xml" fullword ascii
		 $a173= "res/drawable-v21/design_bottom_navigation_item_background.xml]" fullword ascii
		 $a174= "res/drawable-v21/design_bottom_navigation_item_background.xmlPK" fullword ascii
		 $a175= "res/drawable-xhdpi-v4/abc_btn_rating_star_off_mtrl_alpha.png" fullword ascii
		 $a176= "res/drawable-xhdpi-v4/abc_btn_rating_star_off_mtrl_alpha.pngPK" fullword ascii
		 $a177= ";;res/drawable-xhdpi-v4/abc_btn_rating_star_on_mtrl_alpha.png" fullword ascii
		 $a178= "res/drawable-xhdpi-v4/abc_btn_rating_star_on_mtrl_alpha.pngPK" fullword ascii
		 $a179= ";;res/drawable-xhdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.png" fullword ascii
		 $a180= "res/drawable-xhdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.pngPK" fullword ascii
		 $a181= "==res/drawable-xhdpi-v4/abc_cab_background_top_mtrl_alpha.9.png" fullword ascii
		 $a182= "res/drawable-xhdpi-v4/abc_cab_background_top_mtrl_alpha.9.png" fullword ascii
		 $a183= "res/drawable-xhdpi-v4/abc_cab_background_top_mtrl_alpha.9.pngPK" fullword ascii
		 $a184= "==res/drawable-xhdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png" fullword ascii
		 $a185= "res/drawable-xhdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png" fullword ascii
		 $a186= "res/drawable-xhdpi-v4/abc_ic_commit_search_api_mtrl_alpha.pngPK" fullword ascii
		 $a187= "==res/drawable-xhdpi-v4/abc_ic_menu_moreoverflow_mtrl_alpha.png" fullword ascii
		 $a188= "res/drawable-xhdpi-v4/abc_ic_menu_moreoverflow_mtrl_alpha.png" fullword ascii
		 $a189= "res/drawable-xhdpi-v4/abc_ic_menu_moreoverflow_mtrl_alpha.pngPK" fullword ascii
		 $a190= "::res/drawable-xhdpi-v4/abc_ic_menu_selectall_mtrl_alpha.png" fullword ascii
		 $a191= "res/drawable-xhdpi-v4/abc_ic_menu_selectall_mtrl_alpha.pngPK" fullword ascii
		 $a192= "res/drawable-xhdpi-v4/abc_ic_voice_search_api_mtrl_alpha.png" fullword ascii
		 $a193= "res/drawable-xhdpi-v4/abc_ic_voice_search_api_mtrl_alpha.pngPK" fullword ascii
		 $a194= "res/drawable-xhdpi-v4/abc_list_selector_disabled_holo_dark.9.png" fullword ascii
		 $a195= "res/drawable-xhdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.png" fullword ascii
		 $a196= "res/drawable-xhdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.pngPK" fullword ascii
		 $a197= "::res/drawable-xhdpi-v4/abc_popup_background_mtrl_mult.9.png" fullword ascii
		 $a198= "res/drawable-xhdpi-v4/abc_popup_background_mtrl_mult.9.pngPK" fullword ascii
		 $a199= "==res/drawable-xhdpi-v4/abc_scrubber_control_off_mtrl_alpha.png" fullword ascii
		 $a200= "res/drawable-xhdpi-v4/abc_scrubber_control_off_mtrl_alpha.png" fullword ascii
		 $a201= "res/drawable-xhdpi-v4/abc_scrubber_control_off_mtrl_alpha.pngPK" fullword ascii
		 $a202= ";;res/drawable-xhdpi-v4/abc_scrubber_primary_mtrl_alpha.9.png" fullword ascii
		 $a203= "res/drawable-xhdpi-v4/abc_scrubber_primary_mtrl_alpha.9.pngPK" fullword ascii
		 $a204= ">>res/drawable-xhdpi-v4/abc_textfield_activated_mtrl_alpha.9.png" fullword ascii
		 $a205= "res/drawable-xhdpi-v4/abc_textfield_activated_mtrl_alpha.9.png" fullword ascii
		 $a206= "res/drawable-xhdpi-v4/abc_textfield_activated_mtrl_alpha.9.pngPK" fullword ascii
		 $a207= "res/drawable-xhdpi-v4/abc_textfield_default_mtrl_alpha.9.png" fullword ascii
		 $a208= "res/drawable-xhdpi-v4/abc_textfield_default_mtrl_alpha.9.pngPK" fullword ascii
		 $a209= "res/drawable-xhdpi-v4/abc_text_select_handle_left_mtrl_dark.png" fullword ascii
		 $a210= "res/drawable-xhdpi-v4/abc_text_select_handle_left_mtrl_light.png" fullword ascii
		 $a211= "res/drawable-xhdpi-v4/abc_text_select_handle_right_mtrl_dark.png" fullword ascii
		 $a212= "==res/drawable-xhdpi-v4/ic_action_navigation_close_inverted.png" fullword ascii
		 $a213= "res/drawable-xhdpi-v4/ic_action_navigation_close_inverted.png" fullword ascii
		 $a214= "res/drawable-xhdpi-v4/ic_action_navigation_close_inverted.pngPK" fullword ascii
		 $a215= "::res/drawable-xhdpi-v4/notification_bg_normal_pressed.9.png" fullword ascii
		 $a216= "res/drawable-xhdpi-v4/notification_bg_normal_pressed.9.pngPK" fullword ascii
		 $a217= ";;res/drawable-xhdpi-v4/notify_panel_notification_icon_bg.png" fullword ascii
		 $a218= "res/drawable-xhdpi-v4/notify_panel_notification_icon_bg.pngPK" fullword ascii
		 $a219= "==res/drawable-xxhdpi-v4/abc_btn_rating_star_off_mtrl_alpha.png" fullword ascii
		 $a220= "res/drawable-xxhdpi-v4/abc_btn_rating_star_off_mtrl_alpha.png" fullword ascii
		 $a221= "res/drawable-xxhdpi-v4/abc_btn_rating_star_off_mtrl_alpha.pngPK" fullword ascii
		 $a222= "res/drawable-xxhdpi-v4/abc_btn_rating_star_on_mtrl_alpha.png" fullword ascii
		 $a223= "res/drawable-xxhdpi-v4/abc_btn_rating_star_on_mtrl_alpha.pngPK" fullword ascii
		 $a224= "res/drawable-xxhdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.png" fullword ascii
		 $a225= "res/drawable-xxhdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.pngPK" fullword ascii
		 $a226= ">>res/drawable-xxhdpi-v4/abc_cab_background_top_mtrl_alpha.9.png" fullword ascii
		 $a227= "res/drawable-xxhdpi-v4/abc_cab_background_top_mtrl_alpha.9.png" fullword ascii
		 $a228= "res/drawable-xxhdpi-v4/abc_cab_background_top_mtrl_alpha.9.pngPK" fullword ascii
		 $a229= ">>res/drawable-xxhdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png" fullword ascii
		 $a230= "res/drawable-xxhdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png" fullword ascii
		 $a231= "res/drawable-xxhdpi-v4/abc_ic_commit_search_api_mtrl_alpha.pngPK" fullword ascii
		 $a232= "::res/drawable-xxhdpi-v4/abc_ic_go_search_api_mtrl_alpha.png" fullword ascii
		 $a233= "res/drawable-xxhdpi-v4/abc_ic_go_search_api_mtrl_alpha.pngPK" fullword ascii
		 $a234= ">>res/drawable-xxhdpi-v4/abc_ic_menu_moreoverflow_mtrl_alpha.png" fullword ascii
		 $a235= "res/drawable-xxhdpi-v4/abc_ic_menu_moreoverflow_mtrl_alpha.png" fullword ascii
		 $a236= "res/drawable-xxhdpi-v4/abc_ic_menu_moreoverflow_mtrl_alpha.pngPK" fullword ascii
		 $a237= "::res/drawable-xxhdpi-v4/abc_ic_menu_paste_mtrl_am_alpha.png" fullword ascii
		 $a238= "res/drawable-xxhdpi-v4/abc_ic_menu_paste_mtrl_am_alpha.pngPK" fullword ascii
		 $a239= ";;res/drawable-xxhdpi-v4/abc_ic_menu_selectall_mtrl_alpha.png" fullword ascii
		 $a240= "res/drawable-xxhdpi-v4/abc_ic_menu_selectall_mtrl_alpha.pngPK" fullword ascii
		 $a241= "==res/drawable-xxhdpi-v4/abc_ic_voice_search_api_mtrl_alpha.png" fullword ascii
		 $a242= "res/drawable-xxhdpi-v4/abc_ic_voice_search_api_mtrl_alpha.png" fullword ascii
		 $a243= "res/drawable-xxhdpi-v4/abc_ic_voice_search_api_mtrl_alpha.pngPK" fullword ascii
		 $a244= "==res/drawable-xxhdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.png" fullword ascii
		 $a245= "res/drawable-xxhdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.png" fullword ascii
		 $a246= "res/drawable-xxhdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.pngPK" fullword ascii
		 $a247= ";;res/drawable-xxhdpi-v4/abc_popup_background_mtrl_mult.9.png" fullword ascii
		 $a248= "res/drawable-xxhdpi-v4/abc_popup_background_mtrl_mult.9.pngPK" fullword ascii
		 $a249= ">>res/drawable-xxhdpi-v4/abc_scrubber_control_off_mtrl_alpha.png" fullword ascii
		 $a250= "res/drawable-xxhdpi-v4/abc_scrubber_control_off_mtrl_alpha.png" fullword ascii
		 $a251= "res/drawable-xxhdpi-v4/abc_scrubber_control_off_mtrl_alpha.pngPK" fullword ascii
		 $a252= "res/drawable-xxhdpi-v4/abc_scrubber_primary_mtrl_alpha.9.png" fullword ascii
		 $a253= "res/drawable-xxhdpi-v4/abc_scrubber_primary_mtrl_alpha.9.pngPK" fullword ascii
		 $a254= "::res/drawable-xxhdpi-v4/abc_scrubber_track_mtrl_alpha.9.png" fullword ascii
		 $a255= "res/drawable-xxhdpi-v4/abc_scrubber_track_mtrl_alpha.9.pngPK" fullword ascii
		 $a256= "res/drawable-xxhdpi-v4/abc_textfield_activated_mtrl_alpha.9.png" fullword ascii
		 $a257= "==res/drawable-xxhdpi-v4/abc_textfield_default_mtrl_alpha.9.png" fullword ascii
		 $a258= "res/drawable-xxhdpi-v4/abc_textfield_default_mtrl_alpha.9.png" fullword ascii
		 $a259= "res/drawable-xxhdpi-v4/abc_textfield_default_mtrl_alpha.9.pngPK" fullword ascii
		 $a260= "res/drawable-xxhdpi-v4/abc_text_select_handle_left_mtrl_dark.png" fullword ascii
		 $a261= "::res/drawable-xxhdpi-v4/ic_action_navigation_arrow_back.png" fullword ascii
		 $a262= "res/drawable-xxhdpi-v4/ic_action_navigation_arrow_back.pngPK" fullword ascii
		 $a263= ">>res/drawable-xxhdpi-v4/ic_action_navigation_close_inverted.png" fullword ascii
		 $a264= "res/drawable-xxhdpi-v4/ic_action_navigation_close_inverted.png" fullword ascii
		 $a265= "res/drawable-xxhdpi-v4/ic_action_navigation_close_inverted.pngPK" fullword ascii
		 $a266= "::res/drawable-xxhdpi-v4/ic_action_voice_search_inverted.png" fullword ascii
		 $a267= "res/drawable-xxhdpi-v4/ic_action_voice_search_inverted.pngPK" fullword ascii
		 $a268= "==res/drawable-xxhdpi-v4/messenger_button_send_round_shadow.png" fullword ascii
		 $a269= "res/drawable-xxhdpi-v4/messenger_button_send_round_shadow.png" fullword ascii
		 $a270= "res/drawable-xxhdpi-v4/messenger_button_send_round_shadow.pngPK" fullword ascii
		 $a271= "==res/drawable-xxxhdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.png" fullword ascii
		 $a272= "res/drawable-xxxhdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.png" fullword ascii
		 $a273= "res/drawable-xxxhdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.pngPK" fullword ascii
		 $a274= "::res/drawable-xxxhdpi-v4/abc_ic_menu_copy_mtrl_am_alpha.png" fullword ascii
		 $a275= "res/drawable-xxxhdpi-v4/abc_ic_menu_copy_mtrl_am_alpha.pngPK" fullword ascii
		 $a276= "res/drawable-xxxhdpi-v4/abc_ic_menu_moreoverflow_mtrl_alpha.png" fullword ascii
		 $a277= ";;res/drawable-xxxhdpi-v4/abc_ic_menu_paste_mtrl_am_alpha.png" fullword ascii
		 $a278= "res/drawable-xxxhdpi-v4/abc_ic_menu_paste_mtrl_am_alpha.pngPK" fullword ascii
		 $a279= "res/drawable-xxxhdpi-v4/abc_ic_menu_selectall_mtrl_alpha.png" fullword ascii
		 $a280= "res/drawable-xxxhdpi-v4/abc_ic_menu_selectall_mtrl_alpha.pngPK" fullword ascii
		 $a281= ">>res/drawable-xxxhdpi-v4/abc_ic_voice_search_api_mtrl_alpha.png" fullword ascii
		 $a282= "res/drawable-xxxhdpi-v4/abc_ic_voice_search_api_mtrl_alpha.png" fullword ascii
		 $a283= "res/drawable-xxxhdpi-v4/abc_ic_voice_search_api_mtrl_alpha.pngPK" fullword ascii
		 $a284= "::res/drawable-xxxhdpi-v4/abc_tab_indicator_mtrl_alpha.9.png" fullword ascii
		 $a285= "res/drawable-xxxhdpi-v4/abc_tab_indicator_mtrl_alpha.9.pngPK" fullword ascii
		 $a286= ";;res/drawable-xxxhdpi-v4/ic_action_navigation_arrow_back.png" fullword ascii
		 $a287= "res/drawable-xxxhdpi-v4/ic_action_navigation_arrow_back.pngPK" fullword ascii
		 $a288= "res/drawable-xxxhdpi-v4/ic_action_navigation_close_inverted.png" fullword ascii
		 $a289= ";;res/drawable-xxxhdpi-v4/ic_action_voice_search_inverted.png" fullword ascii
		 $a290= "res/drawable-xxxhdpi-v4/ic_action_voice_search_inverted.pngPK" fullword ascii
		 $a291= ";;res/layout/material_view_pager_pagertitlestrip_newstand.xml" fullword ascii
		 $a292= "res/layout/material_view_pager_pagertitlestrip_newstand.xmlPK" fullword ascii
		 $a293= ";;res/layout/material_view_pager_pagertitlestrip_standard.xml" fullword ascii
		 $a294= "res/layout/material_view_pager_pagertitlestrip_standard.xmlPK" fullword ascii
		 $a295= "res/layout/notification_template_big_media_narrow_custom.xml" fullword ascii
		 $a296= "res/layout/notification_template_big_media_narrow_custom.xmlPK" fullword ascii
		 $a297= "res/layout-v17/notification_template_big_media_narrow_custom.xml" fullword ascii
		 $a298= "se.emilsjolander.stickylistheaders.StickyListHeadersListView" fullword ascii
		 $a299= "::TextAppearance.AppCompat.Widget.ActionBar.Subtitle.Inverse" fullword ascii
		 $a300= ";;TextAppearance.AppCompat.Widget.ActionMode.Subtitle.Inverse" fullword ascii

		 $hex1= {3a3a426173652e5465}
		 $hex2= {3a3a54657874417070}
		 $hex3= {3a3a68747470733a2f}
		 $hex4= {3a3a7265732f636f6c}
		 $hex5= {3a3a7265732f647261}
		 $hex6= {3b3b54657874417070}
		 $hex7= {3b3b68747470733a2f}
		 $hex8= {3b3b7265732f647261}
		 $hex9= {3b3b7265732f6c6179}
		 $hex10= {3d3d68747470733a2f}
		 $hex11= {3d3d70617373776f72}
		 $hex12= {3d3d7265732f647261}
		 $hex13= {3e3e68747470733a2f}
		 $hex14= {3e3e7265732f647261}
		 $hex15= {414244434546474849}
		 $hex16= {426173652e54657874}
		 $hex17= {433a57696e646f7773}
		 $hex18= {484152445741524544}
		 $hex19= {636f6d2e616b65786f}
		 $hex20= {636f6d2e6769746875}
		 $hex21= {636f6d2e7365637572}
		 $hex22= {636f6d2e7374756469}
		 $hex23= {636f6d2e756d73696b}
		 $hex24= {68747470733a2f2f67}
		 $hex25= {7265732f636f6c6f72}
		 $hex26= {7265732f6472617761}
		 $hex27= {7265732f6c61796f75}
		 $hex28= {73652e656d696c736a}

	condition:
		111 of them
}
