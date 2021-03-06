
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Oscorp 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Oscorp {
	meta: 
		 description= "vx_underground2_Oscorp Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-13-09" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8daf9ba69c0dcf9224fd1e4006c9dad3"
		 hash2= "c219509f3c95287a6b9900138628e5e1"

	strings:

	
 		 $a1= "?([a-zA-Z0-9-!#$%&'*+.^_`{|}~]+)/([a-zA-Z0-9-!#$%&'*+.^_`{|}~]+)" fullword ascii
		 $a2= "::Base.TextAppearance.AppCompat.Light.Widget.PopupMenu.Large" fullword ascii
		 $a3= "::Base.TextAppearance.AppCompat.Light.Widget.PopupMenu.Small" fullword ascii
		 $a4= "?Base_TextAppearance_AppCompat_Widget_ActionBar_Subtitle_Inverse" fullword ascii
		 $a5= "Base.TextAppearance.AppCompat.Widget.ActionBar.Title.Inverse" fullword ascii
		 $a6= "Base_TextAppearance_AppCompat_Widget_ActionBar_Title_Inverse" fullword ascii
		 $a7= ">>Base.TextAppearance.AppCompat.Widget.Button.Borderless.Colored" fullword ascii
		 $a8= ">Base_TextAppearance_AppCompat_Widget_Button_Borderless_Colored" fullword ascii
		 $a9= "Landroid/content/DialogInterface$OnMultiChoiceClickListener;" fullword ascii
		 $a10= "?Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;" fullword ascii
		 $a11= "=Landroid/hardware/camera2/CameraCaptureSession$StateCallback;" fullword ascii
		 $a12= ";Landroid/support/v4/graphics/drawable/IconCompatParcelizer;" fullword ascii
		 $a13= ";Landroidx/appcompat/widget/ActivityChooserView$InnerLayout;" fullword ascii
		 $a14= "=Lorg/webrtc/audio/JavaAudioDeviceModule$SamplesReadyCallback;" fullword ascii
		 $a15= "?Lorg/webrtc/MediaCodecWrapperFactoryImpl$MediaCodecWrapperImpl;" fullword ascii
		 $a16= ";Lorg/webrtc/NetworkMonitorAutoDetect$SimpleNetworkCallback;" fullword ascii
		 $a17= "?Lorg/webrtc/NetworkMonitorAutoDetect$WifiDirectManagerDelegate;" fullword ascii
		 $a18= "Lorg/webrtc/voiceengine/WebRtcAudioRecord$AudioRecordThread;" fullword ascii
		 $a19= "META-INF/androidx.coordinatorlayout_coordinatorlayout.versionUT" fullword ascii
		 $a20= "META-INF/androidx.legacy_legacy-support-core-utils.versionUT" fullword ascii
		 $a21= "META-INF/androidx.lifecycle_lifecycle-livedata-core.versionUT" fullword ascii
		 $a22= "META-INF/androidx.slidingpanelayout_slidingpanelayout.versionUT" fullword ascii
		 $a23= ">>res/color/abc_background_cache_hint_selector_material_dark.xml" fullword ascii
		 $a24= "res/color/abc_background_cache_hint_selector_material_dark.xmlPK" fullword ascii
		 $a25= "res/color/abc_background_cache_hint_selector_material_dark.xmluP" fullword ascii
		 $a26= "::res/color/abc_primary_text_disable_only_material_light.xml" fullword ascii
		 $a27= "res/color/abc_primary_text_disable_only_material_light.xmlPK" fullword ascii
		 $a28= "res/color/abc_primary_text_disable_only_material_light.xmluP" fullword ascii
		 $a29= "::res/color-v21/abc_btn_colored_borderless_text_material.xml" fullword ascii
		 $a30= "res/color-v21/abc_btn_colored_borderless_text_material.xmlPK" fullword ascii
		 $a31= "res/color-v21/abc_btn_colored_borderless_text_material.xmluP" fullword ascii
		 $a32= "::res/color-v23/abc_btn_colored_borderless_text_material.xml" fullword ascii
		 $a33= "res/color-v23/abc_btn_colored_borderless_text_material.xmlPK" fullword ascii
		 $a34= "res/color-v23/abc_btn_colored_borderless_text_material.xmluP" fullword ascii
		 $a35= "::res/drawable/abc_spinner_textfield_background_material.xml" fullword ascii
		 $a36= "res/drawable/abc_spinner_textfield_background_material.xmlPK" fullword ascii
		 $a37= "::res/drawable-hdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.png" fullword ascii
		 $a38= "res/drawable-hdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.pngPK" fullword ascii
		 $a39= "res/drawable-hdpi-v4/abc_cab_background_top_mtrl_alpha.9.png" fullword ascii
		 $a40= "res/drawable-hdpi-v4/abc_cab_background_top_mtrl_alpha.9.png5" fullword ascii
		 $a41= "res/drawable-hdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png" fullword ascii
		 $a42= "res/drawable-hdpi-v4/abc_ic_commit_search_api_mtrl_alpha.pngPK" fullword ascii
		 $a43= "res/drawable-hdpi-v4/abc_list_selector_disabled_holo_dark.9.png5" fullword ascii
		 $a44= ";;res/drawable-hdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.png" fullword ascii
		 $a45= "res/drawable-hdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.png5" fullword ascii
		 $a46= "res/drawable-hdpi-v4/abc_scrubber_control_off_mtrl_alpha.png" fullword ascii
		 $a47= "res/drawable-hdpi-v4/abc_scrubber_control_off_mtrl_alpha.pngPK" fullword ascii
		 $a48= "::res/drawable-hdpi-v4/abc_scrubber_primary_mtrl_alpha.9.png" fullword ascii
		 $a49= "res/drawable-hdpi-v4/abc_scrubber_primary_mtrl_alpha.9.pngPK" fullword ascii
		 $a50= "==res/drawable-hdpi-v4/abc_textfield_activated_mtrl_alpha.9.png" fullword ascii
		 $a51= "res/drawable-hdpi-v4/abc_textfield_activated_mtrl_alpha.9.png5" fullword ascii
		 $a52= ";;res/drawable-hdpi-v4/abc_textfield_default_mtrl_alpha.9.png" fullword ascii
		 $a53= "res/drawable-hdpi-v4/abc_textfield_default_mtrl_alpha.9.png5" fullword ascii
		 $a54= ">>res/drawable-hdpi-v4/abc_text_select_handle_left_mtrl_dark.png" fullword ascii
		 $a55= "res/drawable-hdpi-v4/abc_text_select_handle_left_mtrl_dark.png5" fullword ascii
		 $a56= "res/drawable-hdpi-v4/abc_text_select_handle_left_mtrl_light.png5" fullword ascii
		 $a57= "res/drawable-hdpi-v4/abc_text_select_handle_middle_mtrl_dark.png" fullword ascii
		 $a58= "res/drawable-hdpi-v4/abc_text_select_handle_right_mtrl_dark.png5" fullword ascii
		 $a59= "::res/drawable-hdpi-v4/notify_panel_notification_icon_bg.png" fullword ascii
		 $a60= ">>res/drawable-ldrtl-hdpi-v17/abc_ic_menu_copy_mtrl_am_alpha.png" fullword ascii
		 $a61= "res/drawable-ldrtl-hdpi-v17/abc_ic_menu_copy_mtrl_am_alpha.png5" fullword ascii
		 $a62= "::res/drawable-ldrtl-hdpi-v17/abc_ic_menu_cut_mtrl_alpha.png" fullword ascii
		 $a63= ";;res/drawable-ldrtl-hdpi-v17/abc_spinner_mtrl_am_alpha.9.png" fullword ascii
		 $a64= "res/drawable-ldrtl-hdpi-v17/abc_spinner_mtrl_am_alpha.9.png5" fullword ascii
		 $a65= ">>res/drawable-ldrtl-mdpi-v17/abc_ic_menu_copy_mtrl_am_alpha.png" fullword ascii
		 $a66= "res/drawable-ldrtl-mdpi-v17/abc_ic_menu_copy_mtrl_am_alpha.png5" fullword ascii
		 $a67= "::res/drawable-ldrtl-mdpi-v17/abc_ic_menu_cut_mtrl_alpha.png" fullword ascii
		 $a68= ";;res/drawable-ldrtl-mdpi-v17/abc_spinner_mtrl_am_alpha.9.png" fullword ascii
		 $a69= "res/drawable-ldrtl-mdpi-v17/abc_spinner_mtrl_am_alpha.9.png5" fullword ascii
		 $a70= "res/drawable-ldrtl-xhdpi-v17/abc_ic_menu_copy_mtrl_am_alpha.png5" fullword ascii
		 $a71= ";;res/drawable-ldrtl-xhdpi-v17/abc_ic_menu_cut_mtrl_alpha.png" fullword ascii
		 $a72= "res/drawable-ldrtl-xhdpi-v17/abc_ic_menu_cut_mtrl_alpha.png5" fullword ascii
		 $a73= "res/drawable-ldrtl-xhdpi-v17/abc_spinner_mtrl_am_alpha.9.png" fullword ascii
		 $a74= "res/drawable-ldrtl-xhdpi-v17/abc_spinner_mtrl_am_alpha.9.pngPK" fullword ascii
		 $a75= "res/drawable-ldrtl-xxhdpi-v17/abc_ic_menu_cut_mtrl_alpha.png" fullword ascii
		 $a76= "res/drawable-ldrtl-xxhdpi-v17/abc_ic_menu_cut_mtrl_alpha.png5" fullword ascii
		 $a77= "==res/drawable-ldrtl-xxhdpi-v17/abc_spinner_mtrl_am_alpha.9.png" fullword ascii
		 $a78= "res/drawable-ldrtl-xxhdpi-v17/abc_spinner_mtrl_am_alpha.9.png" fullword ascii
		 $a79= "res/drawable-ldrtl-xxhdpi-v17/abc_spinner_mtrl_am_alpha.9.pngPK" fullword ascii
		 $a80= "==res/drawable-ldrtl-xxxhdpi-v17/abc_ic_menu_cut_mtrl_alpha.png" fullword ascii
		 $a81= "res/drawable-ldrtl-xxxhdpi-v17/abc_ic_menu_cut_mtrl_alpha.png" fullword ascii
		 $a82= "res/drawable-ldrtl-xxxhdpi-v17/abc_ic_menu_cut_mtrl_alpha.pngPK" fullword ascii
		 $a83= ">>res/drawable-ldrtl-xxxhdpi-v17/abc_spinner_mtrl_am_alpha.9.png" fullword ascii
		 $a84= "res/drawable-ldrtl-xxxhdpi-v17/abc_spinner_mtrl_am_alpha.9.png5" fullword ascii
		 $a85= "::res/drawable-mdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.png" fullword ascii
		 $a86= "res/drawable-mdpi-v4/abc_cab_background_top_mtrl_alpha.9.png" fullword ascii
		 $a87= "res/drawable-mdpi-v4/abc_cab_background_top_mtrl_alpha.9.png5" fullword ascii
		 $a88= "res/drawable-mdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png" fullword ascii
		 $a89= "res/drawable-mdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png5" fullword ascii
		 $a90= "res/drawable-mdpi-v4/abc_list_selector_disabled_holo_dark.9.png" fullword ascii
		 $a91= ";;res/drawable-mdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.png" fullword ascii
		 $a92= "res/drawable-mdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.png5" fullword ascii
		 $a93= "res/drawable-mdpi-v4/abc_scrubber_control_off_mtrl_alpha.png" fullword ascii
		 $a94= "res/drawable-mdpi-v4/abc_scrubber_control_off_mtrl_alpha.png5" fullword ascii
		 $a95= "::res/drawable-mdpi-v4/abc_scrubber_primary_mtrl_alpha.9.png" fullword ascii
		 $a96= "==res/drawable-mdpi-v4/abc_textfield_activated_mtrl_alpha.9.png" fullword ascii
		 $a97= "res/drawable-mdpi-v4/abc_textfield_activated_mtrl_alpha.9.png5" fullword ascii
		 $a98= ";;res/drawable-mdpi-v4/abc_textfield_default_mtrl_alpha.9.png" fullword ascii
		 $a99= "res/drawable-mdpi-v4/abc_textfield_default_mtrl_alpha.9.png5" fullword ascii
		 $a100= ">>res/drawable-mdpi-v4/abc_text_select_handle_left_mtrl_dark.png" fullword ascii
		 $a101= "res/drawable-mdpi-v4/abc_text_select_handle_left_mtrl_dark.png5" fullword ascii
		 $a102= "res/drawable-mdpi-v4/abc_text_select_handle_left_mtrl_light.png" fullword ascii
		 $a103= "res/drawable-mdpi-v4/abc_text_select_handle_right_mtrl_dark.png5" fullword ascii
		 $a104= "::res/drawable-mdpi-v4/notify_panel_notification_icon_bg.png" fullword ascii
		 $a105= "res/drawable-v21/abc_action_bar_item_background_material.xml" fullword ascii
		 $a106= "res/drawable-v21/abc_action_bar_item_background_material.xmlPK" fullword ascii
		 $a107= "res/drawable-v21/abc_action_bar_item_background_material.xmlu" fullword ascii
		 $a108= "res/drawable-watch-v20/abc_dialog_material_background.xmluNA" fullword ascii
		 $a109= ";;res/drawable-xhdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.png" fullword ascii
		 $a110= "res/drawable-xhdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.png5" fullword ascii
		 $a111= "==res/drawable-xhdpi-v4/abc_cab_background_top_mtrl_alpha.9.png" fullword ascii
		 $a112= "res/drawable-xhdpi-v4/abc_cab_background_top_mtrl_alpha.9.png5" fullword ascii
		 $a113= "==res/drawable-xhdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png" fullword ascii
		 $a114= "res/drawable-xhdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png" fullword ascii
		 $a115= "res/drawable-xhdpi-v4/abc_ic_commit_search_api_mtrl_alpha.pngPK" fullword ascii
		 $a116= "::res/drawable-xhdpi-v4/abc_ic_menu_selectall_mtrl_alpha.png" fullword ascii
		 $a117= "res/drawable-xhdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.png" fullword ascii
		 $a118= "res/drawable-xhdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.png5" fullword ascii
		 $a119= "::res/drawable-xhdpi-v4/abc_popup_background_mtrl_mult.9.png" fullword ascii
		 $a120= "==res/drawable-xhdpi-v4/abc_scrubber_control_off_mtrl_alpha.png" fullword ascii
		 $a121= "res/drawable-xhdpi-v4/abc_scrubber_control_off_mtrl_alpha.png5" fullword ascii
		 $a122= ";;res/drawable-xhdpi-v4/abc_scrubber_primary_mtrl_alpha.9.png" fullword ascii
		 $a123= "res/drawable-xhdpi-v4/abc_scrubber_primary_mtrl_alpha.9.pngPK" fullword ascii
		 $a124= ">>res/drawable-xhdpi-v4/abc_textfield_activated_mtrl_alpha.9.png" fullword ascii
		 $a125= "res/drawable-xhdpi-v4/abc_textfield_activated_mtrl_alpha.9.png5" fullword ascii
		 $a126= "res/drawable-xhdpi-v4/abc_textfield_default_mtrl_alpha.9.png" fullword ascii
		 $a127= "res/drawable-xhdpi-v4/abc_textfield_default_mtrl_alpha.9.png5" fullword ascii
		 $a128= "res/drawable-xhdpi-v4/abc_text_select_handle_left_mtrl_dark.png5" fullword ascii
		 $a129= "::res/drawable-xhdpi-v4/notification_bg_normal_pressed.9.png" fullword ascii
		 $a130= ";;res/drawable-xhdpi-v4/notify_panel_notification_icon_bg.png" fullword ascii
		 $a131= "res/drawable-xhdpi-v4/notify_panel_notification_icon_bg.pngPK" fullword ascii
		 $a132= "res/drawable-xxhdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.png" fullword ascii
		 $a133= "res/drawable-xxhdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.png5" fullword ascii
		 $a134= ">>res/drawable-xxhdpi-v4/abc_cab_background_top_mtrl_alpha.9.png" fullword ascii
		 $a135= "res/drawable-xxhdpi-v4/abc_cab_background_top_mtrl_alpha.9.png5" fullword ascii
		 $a136= ">>res/drawable-xxhdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png" fullword ascii
		 $a137= "res/drawable-xxhdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png5" fullword ascii
		 $a138= "::res/drawable-xxhdpi-v4/abc_ic_menu_paste_mtrl_am_alpha.png" fullword ascii
		 $a139= ";;res/drawable-xxhdpi-v4/abc_ic_menu_selectall_mtrl_alpha.png" fullword ascii
		 $a140= "res/drawable-xxhdpi-v4/abc_ic_menu_selectall_mtrl_alpha.png5" fullword ascii
		 $a141= "==res/drawable-xxhdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.png" fullword ascii
		 $a142= "res/drawable-xxhdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.png5" fullword ascii
		 $a143= ";;res/drawable-xxhdpi-v4/abc_popup_background_mtrl_mult.9.png" fullword ascii
		 $a144= "res/drawable-xxhdpi-v4/abc_popup_background_mtrl_mult.9.pngPK" fullword ascii
		 $a145= ">>res/drawable-xxhdpi-v4/abc_scrubber_control_off_mtrl_alpha.png" fullword ascii
		 $a146= "res/drawable-xxhdpi-v4/abc_scrubber_control_off_mtrl_alpha.png5" fullword ascii
		 $a147= "res/drawable-xxhdpi-v4/abc_scrubber_primary_mtrl_alpha.9.png" fullword ascii
		 $a148= "res/drawable-xxhdpi-v4/abc_scrubber_primary_mtrl_alpha.9.png5" fullword ascii
		 $a149= "::res/drawable-xxhdpi-v4/abc_scrubber_track_mtrl_alpha.9.png" fullword ascii
		 $a150= "res/drawable-xxhdpi-v4/abc_textfield_activated_mtrl_alpha.9.png5" fullword ascii
		 $a151= "==res/drawable-xxhdpi-v4/abc_textfield_default_mtrl_alpha.9.png" fullword ascii
		 $a152= "res/drawable-xxhdpi-v4/abc_textfield_default_mtrl_alpha.9.png5" fullword ascii
		 $a153= "==res/drawable-xxxhdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.png" fullword ascii
		 $a154= "res/drawable-xxxhdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.png" fullword ascii
		 $a155= "res/drawable-xxxhdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.pngPK" fullword ascii
		 $a156= "::res/drawable-xxxhdpi-v4/abc_ic_menu_copy_mtrl_am_alpha.png" fullword ascii
		 $a157= "res/drawable-xxxhdpi-v4/abc_ic_menu_copy_mtrl_am_alpha.pngPK" fullword ascii
		 $a158= ";;res/drawable-xxxhdpi-v4/abc_ic_menu_paste_mtrl_am_alpha.png" fullword ascii
		 $a159= "res/drawable-xxxhdpi-v4/abc_ic_menu_paste_mtrl_am_alpha.png5" fullword ascii
		 $a160= "res/drawable-xxxhdpi-v4/abc_ic_menu_selectall_mtrl_alpha.png" fullword ascii
		 $a161= "res/drawable-xxxhdpi-v4/abc_ic_menu_selectall_mtrl_alpha.png5" fullword ascii
		 $a162= "::res/drawable-xxxhdpi-v4/abc_tab_indicator_mtrl_alpha.9.png" fullword ascii
		 $a163= "==res/layout-watch-v20/abc_alert_dialog_button_bar_material.xml" fullword ascii
		 $a164= "res/layout-watch-v20/abc_alert_dialog_button_bar_material.xml" fullword ascii
		 $a165= "res/layout-watch-v20/abc_alert_dialog_button_bar_material.xmlPK" fullword ascii
		 $a166= "::TextAppearance.AppCompat.Widget.ActionBar.Subtitle.Inverse" fullword ascii
		 $a167= ";;TextAppearance.AppCompat.Widget.ActionMode.Subtitle.Inverse" fullword ascii
		 $a168= ";TextAppearance_AppCompat_Widget_ActionMode_Subtitle_Inverse" fullword ascii

		 $hex1= {24613130303d20223e}
		 $hex2= {24613130313d202272}
		 $hex3= {24613130323d202272}
		 $hex4= {24613130333d202272}
		 $hex5= {24613130343d20223a}
		 $hex6= {24613130353d202272}
		 $hex7= {24613130363d202272}
		 $hex8= {24613130373d202272}
		 $hex9= {24613130383d202272}
		 $hex10= {24613130393d20223b}
		 $hex11= {246131303d20223f4c}
		 $hex12= {24613131303d202272}
		 $hex13= {24613131313d20223d}
		 $hex14= {24613131323d202272}
		 $hex15= {24613131333d20223d}
		 $hex16= {24613131343d202272}
		 $hex17= {24613131353d202272}
		 $hex18= {24613131363d20223a}
		 $hex19= {24613131373d202272}
		 $hex20= {24613131383d202272}
		 $hex21= {24613131393d20223a}
		 $hex22= {246131313d20223d4c}
		 $hex23= {24613132303d20223d}
		 $hex24= {24613132313d202272}
		 $hex25= {24613132323d20223b}
		 $hex26= {24613132333d202272}
		 $hex27= {24613132343d20223e}
		 $hex28= {24613132353d202272}
		 $hex29= {24613132363d202272}
		 $hex30= {24613132373d202272}
		 $hex31= {24613132383d202272}
		 $hex32= {24613132393d20223a}
		 $hex33= {246131323d20223b4c}
		 $hex34= {24613133303d20223b}
		 $hex35= {24613133313d202272}
		 $hex36= {24613133323d202272}
		 $hex37= {24613133333d202272}
		 $hex38= {24613133343d20223e}
		 $hex39= {24613133353d202272}
		 $hex40= {24613133363d20223e}
		 $hex41= {24613133373d202272}
		 $hex42= {24613133383d20223a}
		 $hex43= {24613133393d20223b}
		 $hex44= {246131333d20223b4c}
		 $hex45= {24613134303d202272}
		 $hex46= {24613134313d20223d}
		 $hex47= {24613134323d202272}
		 $hex48= {24613134333d20223b}
		 $hex49= {24613134343d202272}
		 $hex50= {24613134353d20223e}
		 $hex51= {24613134363d202272}
		 $hex52= {24613134373d202272}
		 $hex53= {24613134383d202272}
		 $hex54= {24613134393d20223a}
		 $hex55= {246131343d20223d4c}
		 $hex56= {24613135303d202272}
		 $hex57= {24613135313d20223d}
		 $hex58= {24613135323d202272}
		 $hex59= {24613135333d20223d}
		 $hex60= {24613135343d202272}
		 $hex61= {24613135353d202272}
		 $hex62= {24613135363d20223a}
		 $hex63= {24613135373d202272}
		 $hex64= {24613135383d20223b}
		 $hex65= {24613135393d202272}
		 $hex66= {246131353d20223f4c}
		 $hex67= {24613136303d202272}
		 $hex68= {24613136313d202272}
		 $hex69= {24613136323d20223a}
		 $hex70= {24613136333d20223d}
		 $hex71= {24613136343d202272}
		 $hex72= {24613136353d202272}
		 $hex73= {24613136363d20223a}
		 $hex74= {24613136373d20223b}
		 $hex75= {24613136383d20223b}
		 $hex76= {246131363d20223b4c}
		 $hex77= {246131373d20223f4c}
		 $hex78= {246131383d20224c6f}
		 $hex79= {246131393d20224d45}
		 $hex80= {2461313d20223f285b}
		 $hex81= {246132303d20224d45}
		 $hex82= {246132313d20224d45}
		 $hex83= {246132323d20224d45}
		 $hex84= {246132333d20223e3e}
		 $hex85= {246132343d20227265}
		 $hex86= {246132353d20227265}
		 $hex87= {246132363d20223a3a}
		 $hex88= {246132373d20227265}
		 $hex89= {246132383d20227265}
		 $hex90= {246132393d20223a3a}
		 $hex91= {2461323d20223a3a42}
		 $hex92= {246133303d20227265}
		 $hex93= {246133313d20227265}
		 $hex94= {246133323d20223a3a}
		 $hex95= {246133333d20227265}
		 $hex96= {246133343d20227265}
		 $hex97= {246133353d20223a3a}
		 $hex98= {246133363d20227265}
		 $hex99= {246133373d20223a3a}
		 $hex100= {246133383d20227265}
		 $hex101= {246133393d20227265}
		 $hex102= {2461333d20223a3a42}
		 $hex103= {246134303d20227265}
		 $hex104= {246134313d20227265}
		 $hex105= {246134323d20227265}
		 $hex106= {246134333d20227265}
		 $hex107= {246134343d20223b3b}
		 $hex108= {246134353d20227265}
		 $hex109= {246134363d20227265}
		 $hex110= {246134373d20227265}
		 $hex111= {246134383d20223a3a}
		 $hex112= {246134393d20227265}
		 $hex113= {2461343d20223f4261}
		 $hex114= {246135303d20223d3d}
		 $hex115= {246135313d20227265}
		 $hex116= {246135323d20223b3b}
		 $hex117= {246135333d20227265}
		 $hex118= {246135343d20223e3e}
		 $hex119= {246135353d20227265}
		 $hex120= {246135363d20227265}
		 $hex121= {246135373d20227265}
		 $hex122= {246135383d20227265}
		 $hex123= {246135393d20223a3a}
		 $hex124= {2461353d2022426173}
		 $hex125= {246136303d20223e3e}
		 $hex126= {246136313d20227265}
		 $hex127= {246136323d20223a3a}
		 $hex128= {246136333d20223b3b}
		 $hex129= {246136343d20227265}
		 $hex130= {246136353d20223e3e}
		 $hex131= {246136363d20227265}
		 $hex132= {246136373d20223a3a}
		 $hex133= {246136383d20223b3b}
		 $hex134= {246136393d20227265}
		 $hex135= {2461363d2022426173}
		 $hex136= {246137303d20227265}
		 $hex137= {246137313d20223b3b}
		 $hex138= {246137323d20227265}
		 $hex139= {246137333d20227265}
		 $hex140= {246137343d20227265}
		 $hex141= {246137353d20227265}
		 $hex142= {246137363d20227265}
		 $hex143= {246137373d20223d3d}
		 $hex144= {246137383d20227265}
		 $hex145= {246137393d20227265}
		 $hex146= {2461373d20223e3e42}
		 $hex147= {246138303d20223d3d}
		 $hex148= {246138313d20227265}
		 $hex149= {246138323d20227265}
		 $hex150= {246138333d20223e3e}
		 $hex151= {246138343d20227265}
		 $hex152= {246138353d20223a3a}
		 $hex153= {246138363d20227265}
		 $hex154= {246138373d20227265}
		 $hex155= {246138383d20227265}
		 $hex156= {246138393d20227265}
		 $hex157= {2461383d20223e4261}
		 $hex158= {246139303d20227265}
		 $hex159= {246139313d20223b3b}
		 $hex160= {246139323d20227265}
		 $hex161= {246139333d20227265}
		 $hex162= {246139343d20227265}
		 $hex163= {246139353d20223a3a}
		 $hex164= {246139363d20223d3d}
		 $hex165= {246139373d20227265}
		 $hex166= {246139383d20223b3b}
		 $hex167= {246139393d20227265}
		 $hex168= {2461393d20224c616e}

	condition:
		112 of them
}
