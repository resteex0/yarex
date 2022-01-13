
/*
   YARA Rule Set
   Author: resteex
   Identifier: AceDeceiver 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_AceDeceiver {
	meta: 
		 description= "AceDeceiver Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-12_19-28-26" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1107c445289b2ac3912a9b4419c48f58"
		 hash2= "1dc2584cd2c167907ae547bd4b040710"
		 hash3= "2fbdfd6a94af3ad388450ccd4fbe4fe4"
		 hash4= "310acf02b0b5e748a2de353448904445"
		 hash5= "3652db89ace912e15628b45b80cf389a"
		 hash6= "3c1406453dbec9284caa1a10b4a83fd7"
		 hash7= "41e820885d1cc951a848fd586be3e894"
		 hash8= "5d9b59db4b8cc84bd2e14f9e1768fb87"
		 hash9= "5e74324567ab4ebe47044337beec6f99"
		 hash10= "6614bd786cd5e7d0c7fd419cf7cd79ac"
		 hash11= "6a6d7ee4d87d824340e8e08c34ed7891"
		 hash12= "7fde49574366e059d0454bdefceb1434"
		 hash13= "96724f179c3afd44ddcc60bed4a4089d"
		 hash14= "99910c48e7fc3bae3393013c8c797f43"
		 hash15= "a3b156f679a915c0c7a255151d73965b"
		 hash16= "a63124c34c6d5b4b33113af4288e248c"
		 hash17= "c1c335b98209ffa9336db47bfc0eea36"
		 hash18= "c6523b9cbce3dacd966ee7fac64e851a"
		 hash19= "c79492a303547697453438d321af4c50"
		 hash20= "d3186cb98e898c5364fa23b710ff1da4"
		 hash21= "d6f664197eadfd8e080ccc0bbeee6e1e"
		 hash22= "e2f05253fd536c7e01f6e0a4ce2b2b34"
		 hash23= "e777707b967cd2c4a312064397a5ef5c"
		 hash24= "ebfcecf97992fe3e707786462abb4fce"

	strings:

	
 		 $s1= "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}" fullword wide
		 $s2= "0%d-%02d-%02d_%02d%02d%02d" fullword wide
		 $s3= "405096f6-8d6a-4957-a44c-fd4657a4fbf5" fullword wide
		 $s4= "- abort() has been called" fullword wide
		 $s5= "AniBgImgNext blading over." fullword wide
		 $s6= "app_icon_default_36x36.png" fullword wide
		 $s7= "applicable_iPhone_20x20.png" fullword wide
		 $s8= "ApplicationAlreadyInstalled" fullword wide
		 $s9= "- Attempt to initialize the CRT more than once." fullword wide
		 $s10= "- Attempt to use MSIL code from this assembly during native code initialization" fullword wide
		 $s11= "backup_icon_iBackup_56x56.png" fullword wide
		 $s12= "backup_icon_iRecover_56x56.png" fullword wide
		 $s13= "backup_icon_recover_56x56.png" fullword wide
		 $s14= "'Battery_loading_animation.png" fullword wide
		 $s15= "btn_select_default_W50.png" fullword wide
		 $s16= "CallHistory.storedata-shm" fullword wide
		 $s17= "CallHistory.storedata-wal" fullword wide
		 $s18= "cApplicationVerificationFailed" fullword wide
		 $s19= "clear_complete_300x216.png" fullword wide
		 $s20= "/clr) function from a native constructor or from DllMain." fullword wide
		 $s21= "com.apple.bookmarks.Folder" fullword wide
		 $s22= "'connected_img_809x596.png" fullword wide
		 $s23= "'connected_img_998x596.png" fullword wide
		 $s24= "'connected_trust_760x482.png" fullword wide
		 $s25= "contact_icon_border_100x100.png" fullword wide
		 $s26= "contact_icon_border_40x40.png" fullword wide
		 $s27= "Controls_select_16x16.png" fullword wide
		 $s28= "Controls_select_white_16x16.png" fullword wide
		 $s29= "Could not find ziped file" fullword wide
		 $s30= "Create Standby Event failed!" fullword wide
		 $s31= "Device_inf_battery_37x16.png" fullword wide
		 $s32= "Device_inf_disk_44x16.png" fullword wide
		 $s33= "'Device_inf_grid_440x343.png" fullword wide
		 $s34= "Device_inf_lightning_16x16.png" fullword wide
		 $s35= "Device_info_icon_edit_20x20.png" fullword wide
		 $s36= "Device_inf_tools_mask_56x56.png" fullword wide
		 $s37= "device_iPhone4s_black.jpg" fullword wide
		 $s38= "device_iPhone4s_white.jpg" fullword wide
		 $s39= "device_iPhone5c_white.jpg" fullword wide
		 $s40= "device_iPhone5c_yellow.jpg" fullword wide
		 $s41= "device_iPhone5s_silver.jpg" fullword wide
		 $s42= "device_iPhone6Plus_gold.jpg" fullword wide
		 $s43= "device_iPhone6Plus_gray.jpg" fullword wide
		 $s44= "device_iPhone6Plus_silver.jpg" fullword wide
		 $s45= "'device_iPhone6_silver.jpg" fullword wide
		 $s46= "'device_iPhone6sPlus_gold.jpg" fullword wide
		 $s47= "'device_iPhone6sPlus_gray.jpg" fullword wide
		 $s48= "device_iPhone6sPlus_silver.jpg" fullword wide
		 $s49= "device_iPhone6s_roseGold.jpg" fullword wide
		 $s50= "device_iPhone6s_silver.jpg" fullword wide
		 $s51= "device_iPod_touch4_black.jpg" fullword wide
		 $s52= "'device_iPod_touch4_white.jpg" fullword wide
		 $s53= "device_iPod_touch5_blue.jpg" fullword wide
		 $s54= "device_iPod_touch5_gray.jpg" fullword wide
		 $s55= "device_iPod_touch5_pink.jpg" fullword wide
		 $s56= "device_iPod_touch5_silver.jpg" fullword wide
		 $s57= "device_iPod_touch5_yellow.jpg" fullword wide
		 $s58= "Download_nav_xunlei_120x36.png" fullword wide
		 $s59= "Error parsing element name" fullword wide
		 $s60= "Error while parsing attributes" fullword wide
		 $s61= "Error while parsing attribute string" fullword wide
		 $s62= "Expand_arrow_666_12x12.png" fullword wide
		 $s63= "Expected start-tag closing" fullword wide
		 $s64= "file='messagebox_icon_48x48.png' source='0,0,48,48'" fullword wide
		 $s65= "file='messagebox_icon_48x48.png' source='0,144,48,192'" fullword wide
		 $s66= "file='messagebox_icon_48x48.png' source='0,48,48,96'" fullword wide
		 $s67= "file='messagebox_icon_48x48.png' source='0,96,48,144'" fullword wide
		 $s68= "filespatchtools7z-327z.exe" fullword wide
		 $s69= "filespatchtools7z-647z.exe" fullword wide
		 $s70= "file='%s' source='0,%d,40,%d'" fullword wide
		 $s71= "file='%s' source='%d,0,%d,%d'" fullword wide
		 $s72= "file='tabel_header_Arrow.png' source='0,0,30,30'" fullword wide
		 $s73= "file='tabel_header_Arrow.png' source='0,30,30,60'" fullword wide
		 $s74= "file='wnd_compress_p3.png' source='0,0,120,%d' dest='0, 0,120,%d'" fullword wide
		 $s75= "flash_device_switch_13x13.png" fullword wide
		 $s76= "flash_ipsw_beta_41x18.png" fullword wide
		 $s77= "- floating point support not loaded" fullword wide
		 $s78= "gapp_icon_border_26x26.png" fullword wide
		 $s79= "gapp_icon_border_36x36.png" fullword wide
		 $s80= "garrow_mobileMoving_160x76.png" fullword wide
		 $s81= "gbackup_icon_backup_56x56.png" fullword wide
		 $s82= "gconnected_text_460x46.png" fullword wide
		 $s83= "gconnected_text_700x46.png" fullword wide
		 $s84= "gControls_select_half_16x16.png" fullword wide
		 $s85= "gdevice_iPhone5c_blue.jpg" fullword wide
		 $s86= "Gdevice_iPhone5c_green.jpg" fullword wide
		 $s87= "gdevice_iPhone5c_pink.jpg" fullword wide
		 $s88= "gdevice_iPhone6sPlus_roseGold.jpg" fullword wide
		 $s89= "Gdevice_iPod_touch5_red.jpg" fullword wide
		 $s90= "Gflash_device_disk_32x15.png" fullword wide
		 $s91= "GHead_btnPlayerBG_min_20x20.png" fullword wide
		 $s92= "GHead_btnsys_menu_20x20.png" fullword wide
		 $s93= "gHead_download__28x28.png" fullword wide
		 $s94= "GHead_download_icon_30x30.png" fullword wide
		 $s95= "gHead_label_icon_video_36x36.png" fullword wide
		 $s96= "Gi4Tools_LOGO_140x180.png" fullword wide
		 $s97= "Gicon_default_100x100.png" fullword wide
		 $s98= "gicon_deviceMove_56x56.png" fullword wide
		 $s99= "Gicon_pro_emotion_56x56.png" fullword wide
		 $s100= "gicon_repairApp_56x56.png" fullword wide
		 $s101= "gImport_img_icon_80x80.png" fullword wide
		 $s102= "gMusic_play_icon_16x16.png" fullword wide
		 $s103= "Gphoto_default_132x132.png" fullword wide
		 $s104= "gphoto_defaultGallery_132x132.png" fullword wide
		 $s105= "Gphoto_select_146x146.png" fullword wide
		 $s106= "Gphoto_select_146x202.png" fullword wide
		 $s107= "gright_menu_arrow_1_16x16.png" fullword wide
		 $s108= "gright_menu_arrow_3_16x16.png" fullword wide
		 $s109= "grotation_loading_flash_260x260.png" fullword wide
		 $s110= "Gtextbox_bottom_arrow.png" fullword wide
		 $s111= "GTitleBar_icon_download_24x24.png" fullword wide
		 $s112= "gtools_icon_backup_20x20.png" fullword wide
		 $s113= "Gtools_icon_browse_20x20.png" fullword wide
		 $s114= "Gtools_icon_favorite_20x20.png" fullword wide
		 $s115= "Gtools_icon_folder_20x20.png" fullword wide
		 $s116= "Gtools_icon_newDownload_20x20.png" fullword wide
		 $s117= "gtools_icon_newPlayList_20x20.png" fullword wide
		 $s118= "gtools_icon_newRings_20x20.png" fullword wide
		 $s119= "gtools_icon_repair_20x20.png" fullword wide
		 $s120= "Gtools_icon_restore_20x20.png" fullword wide
		 $s121= "Gtools_icon_stop_20x20.png" fullword wide
		 $s122= "Gtools_icon_toPlayList_20x20.png" fullword wide
		 $s123= "Gtools_icon_unfavorite_20x20.png" fullword wide
		 $s124= "Gtools_icon_update_20x20.png" fullword wide
		 $s125= "gtray_menu_bg_188x272.png" fullword wide
		 $s126= "gvedio_convert_icon_del_20x20.png.png" fullword wide
		 $s127= "'Head_btnsys_close_29x20.png" fullword wide
		 $s128= "Head_btnsys_color_20x20.png" fullword wide
		 $s129= "Head_btnsys_feedback_20x20.png" fullword wide
		 $s130= "Head_btnsys_max_20x20.png" fullword wide
		 $s131= "Head_btnsys_min_20x20.png" fullword wide
		 $s132= "Head_download__113x28.png" fullword wide
		 $s133= "'Head_downloading_icon_30x30.png" fullword wide
		 $s134= "Head_label_icon_app_36x36.png" fullword wide
		 $s135= "Head_label_icon_device_36x36.png" fullword wide
		 $s136= "Head_label_icon_ebooks_36x36.png" fullword wide
		 $s137= "'Head_label_icon_flash_36x36.png" fullword wide
		 $s138= "Head_label_icon_music_36x36.png" fullword wide
		 $s139= "Head_label_icon_tools_36x36.png" fullword wide
		 $s140= "Head_label_icon_wallpaper_36x36.png" fullword wide
		 $s141= "HMulSelListContainerElementUI" fullword wide
		 $s142= "http://app3.i4.cn/log/info/uploadActiveInfo.go?type=5" fullword wide
		 $s143= "http://app3.i4.cn/log/info/uploadLogFile.go" fullword wide
		 $s144= "http://url.i4.cn/6FjqAjaa" fullword wide
		 $s145= "http://url.i4.cn/yumEbiaa" fullword wide
		 $s146= "http://www.i4.cn/newsContent-1854.html" fullword wide
		 $s147= "I4DownLoadManager::TaskPause:" fullword wide
		 $s148= "icon_dataManage_20x20.png" fullword wide
		 $s149= "icon_disabled_mask_56x56.png" fullword wide
		 $s150= "icon_exclamation_16x16.png" fullword wide
		 $s151= "'icon_fileManage_20x20.png" fullword wide
		 $s152= "icon_installResidues_26x26.png" fullword wide
		 $s153= "icon_iTunes_backup_112x112.png" fullword wide
		 $s154= "icon_iTunes_bacRec_56x56.png" fullword wide
		 $s155= "icon_iTunes_recovery_112x112.png" fullword wide
		 $s156= "icon_otherTools_60x60.png" fullword wide
		 $s157= "icon_outgoingCalls_16x16.png" fullword wide
		 $s158= "icon_pro_bacRec_56x56.png" fullword wide
		 $s159= "'icon_recording_20x20.png" fullword wide
		 $s160= "icon_video_convert_56x56.png" fullword wide
		 $s161= "'list_gallery_default_136x136.png" fullword wide
		 $s162= "list_head_arrow_20x20.png" fullword wide
		 $s163= "'logding_animation_212x212.png" fullword wide
		 $s164= "logding_animation2_212x212.png" fullword wide
		 $s165= "messagebox_icon_48x48.png" fullword wide
		 $s166= "messagebox_icon_80x80.png" fullword wide
		 $s167= "MicrosoftInternet ExplorerQuick Launch" fullword wide
		 $s168= "MismatchedApplicationIdentifierEntitlement" fullword wide
		 $s169= "mobileLibraryCachescom.apple.mobile.installation.plist" fullword wide
		 $s170= "MulSelListContainerElement" fullword wide
		 $s171= "Music_pause_icon_16x16.png" fullword wide
		 $s172= "- not enough space for arguments" fullword wide
		 $s173= "- not enough space for environment" fullword wide
		 $s174= "- not enough space for locale information" fullword wide
		 $s175= "- not enough space for lowio initialization" fullword wide
		 $s176= "- not enough space for _onexit/atexit table" fullword wide
		 $s177= "- not enough space for stdio initialization" fullword wide
		 $s178= "- not enough space for thread data" fullword wide
		 $s179= "OMicrosoft Visual C++ Runtime Library" fullword wide
		 $s180= "photo_gallery_shortcut.png" fullword wide
		 $s181= "photo_topBorder_132x6.png" fullword wide
		 $s182= "'photozip_animation_212x212.png" fullword wide
		 $s183= "player_animation_20x20.gif" fullword wide
		 $s184= "privatevarmobileLibrarySMSsms.db" fullword wide
		 $s185= "privatevarmobileLibrarySMSsms.db-shm" fullword wide
		 $s186= "privatevarmobileLibrarySMSsms.db-wal" fullword wide
		 $s187= "- pure virtual function call" fullword wide
		 $s188= "ringmake_play_100x100.png" fullword wide
		 $s189= "ringMaker_aTime_pointer_8x151.png" fullword wide
		 $s190= "ringMaker_bTime_pointer_8x151.png" fullword wide
		 $s191= "ringMaker_play_btn_100x100.png" fullword wide
		 $s192= "'ringMaker_play_pointer_11x149.png" fullword wide
		 $s193= "ringMaker_timeChange_btn_15x15.png" fullword wide
		 $s194= "ringmake_textbox_arrow.png" fullword wide
		 $s195= "rocky-racooninstall.conf" fullword wide
		 $s196= "rotation_loading_260x260.png" fullword wide
		 $s197= "rotation_PhotoZipbg_300x300.png" fullword wide
		 $s198= "%scacheCrashReporti4Tools_%04d%02d%02d-%02d%02d%02d.dmp" fullword wide
		 $s199= "'skin_new_year2016Background.png" fullword wide
		 $s200= "slotQueryTaskProgress:I4T_ERROR " fullword wide
		 $s201= "slotQueryTaskProgress:task delete on complete" fullword wide
		 $s202= "SOFTWAREApple Computer, Inc.iPodRegisteredApps4" fullword wide
		 $s203= "SoftwareClassesiTunes.ipa" fullword wide
		 $s204= "SoftwareClasses%sDefaultIcon" fullword wide
		 $s205= "SoftwareClasses%sshell" fullword wide
		 $s206= "SoftwareClasses%sshelli4Tools" fullword wide
		 $s207= "SoftwareClasses%sshelli4Toolscommand" fullword wide
		 $s208= "SOFTWAREMicrosoftInternet Explorer" fullword wide
		 $s209= "SoftwareMicrosoftWindowsCurrentVersionApp PathsiTunes.exe" fullword wide
		 $s210= "SoftwareMicrosoftWindowsCurrentVersionExplorerFileExts.ipa" fullword wide
		 $s211= "SOFTWAREMicrosoftWindowsCurrentVersionUninstall" fullword wide
		 $s212= "%svarmobileLibraryCachescom.apple.mobile.installation.plist" fullword wide
		 $s213= "SystemConfiguration.plist" fullword wide
		 $s214= "tabel_list_icon40px_mask.png" fullword wide
		 $s215= "This indicates a bug in your application." fullword wide
		 $s216= "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (" fullword wide
		 $s217= "tools_icon_activation_20x20.png" fullword wide
		 $s218= "'tools_icon_add_20x20.png" fullword wide
		 $s219= "tools_icon_addLunar_20x20.png" fullword wide
		 $s220= "'tools_icon_allSelect_20x20.png" fullword wide
		 $s221= "'tools_icon_break_20x20.png" fullword wide
		 $s222= "tools_icon_clear_20x20.png" fullword wide
		 $s223= "tools_icon_contactDeduplication_20x20.png" fullword wide
		 $s224= "tools_icon_download_20x20.png" fullword wide
		 $s225= "tools_icon_edit_20x20.png" fullword wide
		 $s226= "'tools_icon_export_20x20.png" fullword wide
		 $s227= "tools_icon_flash_20x20.png" fullword wide
		 $s228= "tools_icon_folder_16x16.png" fullword wide
		 $s229= "tools_icon_goBack_20x20.png" fullword wide
		 $s230= "'tools_icon_import_20x20.png" fullword wide
		 $s231= "tools_icon_install_20x20.png" fullword wide
		 $s232= "tools_icon_newFolder_20x20.png" fullword wide
		 $s233= "'tools_icon_pause_20x20.png" fullword wide
		 $s234= "'tools_icon_play_20x20.png" fullword wide
		 $s235= "tools_icon_playList_20x20.png" fullword wide
		 $s236= "tools_icon_refresh_20x20.png" fullword wide
		 $s237= "tools_icon_save_20x20.png" fullword wide
		 $s238= "tools_icon_screenshot_20x20.png" fullword wide
		 $s239= "tools_icon_search_20x20.png" fullword wide
		 $s240= "tools_icon_searchSHSH_20x20.png" fullword wide
		 $s241= "'tools_icon_uninstall_20x20.png" fullword wide
		 $s242= "tree_icon_circle_12x12.png" fullword wide
		 $s243= "tree_icon_disconnect_12x12.png" fullword wide
		 $s244= "- unable to initialize heap" fullword wide
		 $s245= "- unable to open console device" fullword wide
		 $s246= "- unexpected multithread lock error" fullword wide
		 $s247= "varmobileLibrarySMSsms.db" fullword wide
		 $s248= "WeiboSDK3rdApp isAppInstalled appKey " fullword wide
		 $s249= "[WeiboSDK registerApp:] " fullword wide
		 $s250= "WeiboSDK registerApp error : appKey" fullword wide
		 $s251= "WeiboSDK send %@ error : " fullword wide
		 $s252= "WeiboSDK send %@ error : object.app " fullword wide
		 $s253= "WorkerQueueThread Create Failed!" fullword wide
		 $a1= "@12@0:4^{_xmlAttr=^vi*^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlAttr}^{_xmlAttr}^{_xmlDoc}^{_xmlNs}i^v}" fullword ascii
		 $a2= "@12@0:4^{_xmlNode=^vi*^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlDoc}^{_xmlNs}*^{_" fullword ascii
		 $a3= "@24@0:8^{_xmlAttr=^vi*^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlAttr}^{_xmlAttr}^{_xmlDoc}^{_xmlNs}i^v}" fullword ascii
		 $a4= "@24@0:8^{_xmlNode=^vi*^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlDoc}^{_xmlNs}*^{_" fullword ascii
		 $a5= "adClickCallback.xhtml?%@&toolversion=%@&adid=%@&appid=%@&cid=%@&adtype=%@&isAuth=%@&isjail=%@&pkaget" fullword ascii
		 $a6= "appinfo.xhtml?appid=%@&isAuth=%@&isjail=%@&rt=1&%@&pkagetype=%@&sort=%@&specialid=%@&type=%@&remdord" fullword ascii
		 $a7= "?File2Dev@FileMgr@@QAEHAAV?$basic_string@GU?$char_traits@G@std@@V?$allocator@G@2@@std@@AAV?$basic_st" fullword ascii
		 $a8= "?File2PC@FileMgr@@QAEHAAV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AAV?$basic_str" fullword ascii
		 $a9= "%@fileCheckErrorCb.xhtml?%@&sip=%@&url=%@&scode=%@&ccode=%@&toolversion=%@&id=%@&ctype=%@&sbyte=%@&c" fullword ascii
		 $a10= "getAppList.xhtml?%@&isAuth=%@&sort=%@&remd=%@&specialid=0&type=%@&pageno=%ld&isjail=%@&toolversion=%" fullword ascii
		 $a11= "getAppList.xhtml?keyword=%@&%@&isAuth=%@&remd=9&pageno=%ld&isjail=%@&isinput=%d&toolversion=%@&hid=%" fullword ascii
		 $a12= "%@getModelPrice.xhtml?serialnumber=%s&%@&modelnum=%@&buydate=%@&capacity=%@&toolversion=%@&lastdate=" fullword ascii
		 $a13= "%@getModelPrice.xhtml?serialnumber=%s&%@&modelnum=%@&buydate=%@&capacity=%@&toolversion=%@&warranty=" fullword ascii
		 $a14= "%@getversioninfo.xhtml?%@&isAuth=%@&toolversion=%@&lastShowTime=%@&cid=%@&isjail=%@&authortype=%@&up" fullword ascii
		 $a15= "%@getversioninfo.xhtml?%@&lastShowTime=%@&cid=%@&authortype=%@&update=%@&serialnumber=%s&reachabilit" fullword ascii
		 $a16= "%@getversioninfo.xhtml?%@&toolversion=%@&lastShowTime=%@&cid=%@&authortype=%@&update=%@&serialnumber" fullword ascii
		 $a17= "http://c.isdspeed.qq.com/code.cgi?domain=mobile.opensdk.com&cgi=opensdk&type=0&code=0&time=100&data=" fullword ascii
		 $a18= "http://ios3.update.i4.cn/getRenovateAppListMbl.xhtml?checktype=%@&%@&isAuth=%@&cid=%@&isjail=%@&tool" fullword ascii
		 $a19= "https://buy.itunes.apple.com/WebObjects/MZFastFinance.woa/wa/songDownloadDone?songId=%@guid=%@&downl" fullword ascii
		 $a20= "https://open.weixin.qq.com/connect/smsauthorize?appid=%@&redirect_uri=%@&response_type=code&scope=%@" fullword ascii
		 $a21= "https://p22-buy.itunes.apple.com/WebObjects/MZFastFinance.woa/wa/songDownloadDone?Pod=22&songId=%s&g" fullword ascii
		 $a22= "/i4Connect/Share/DownloadManager/CKDownloadManager/ThirdPart/HTTPServer/HTTP/Responses/HTTPAsyncFile" fullword ascii
		 $a23= "/i4Connect/Share/DownloadManager/CKDownloadManager/ThirdPart/HTTPServer/HTTP/Responses/HTTPFileRespo" fullword ascii
		 $a24= "idfa=%@&idfv=%@&openudid=%@&osversion=%@&udid=%@&macaddress=%@&model=%@&certificateid=%@&bundleid=%@" fullword ascii
		 $a25= "mqqapi://card/show_pslcard?src_type=internal&version=1&uin=%@&key=%@&card_type=group&source=external" fullword ascii
		 $a26= "%@?platform=2&act_type=5&login_status=0&need_user_auth=0&via=2&uin=1000&app_id=%@&result=%d&openid=%" fullword ascii
		 $a27= "%@?platform=2&type=%d&to_type=%d&act_type=%d&via=2&uin=1000&to_uin=0&call_source=%d&app_id=%@&result" fullword ascii
		 $a28= "requestForBilateralFollowersListOfUser:withAccessToken:andOtherProperties:queue:withCompletionHandle" fullword ascii
		 $a29= "requestForBilateralFriendsListOfUser:withAccessToken:andOtherProperties:queue:withCompletionHandler:" fullword ascii
		 $a30= "requestForCommonFriendsListBetweenUser:andUser:withAccessToken:andOtherProperties:queue:withCompleti" fullword ascii
		 $a31= "requestForFriendshipDetailBetweenTargetUser:andSourceUser:withAccessToken:andOtherProperties:queue:w" fullword ascii
		 $a32= "requestForInviteBilateralFriend:withAccessToken:inviteText:inviteUrl:inviteLogoUrl:queue:withComplet" fullword ascii
		 $a33= "requestForShareAStatus:contatinsAPicture:orPictureUrl:withAccessToken:andOtherProperties:queue:withC" fullword ascii
		 $a34= "setupCallback.xhtml?%@&adid=%@&appid=%@&adtype=%@&isAuth=%@&isjail=%@&pkagetype=%ld&remdorder=%@&rem" fullword ascii
		 $a35= "setupCallback.xhtml?%@&appid=%@&remd=%@&pkagetype=%@&remdorder=%@&sort=%@&specialid=%@&type=%@&searc" fullword ascii
		 $a36= "setupCallback.xhtml?%@&appid=%@&remd=%@&remdorder=%@&pkagetype=%ld&sort=%@&specialid=%@&type=%@&appd" fullword ascii
		 $a37= "setupCallback.xhtml?%@&toolversion=%@&adid=%@&appid=%@&cid=%@&adtype=%@&isAuth=%@&isjail=%@&pkagetyp" fullword ascii
		 $a38= "setupCallback.xhtml?%@&toolversion=%@&appid=%@&isAuth=%@&remd=%@&cid=%@&isjail=%@&remdorder=%@&pkage" fullword ascii
		 $a39= "specialClickCallBack.xhtml?%@&toolversion=%@&sid=%@&sort=%@&cid=%@&isAuth=%@&isjail=%@&toolversion=%" fullword ascii
		 $a40= "v16@0:4^{_xmlNode=^vi*^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlDoc}^{_xmlNs}*^{_" fullword ascii
		 $a41= "v16@0:4^{_xmlNs=^{_xmlNs}i**^v^{_xmlDoc}}8^{_xmlNode=^vi*^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode" fullword ascii
		 $a42= "v20@0:4^{_xmlNode=^vi*^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlDoc}^{_xmlNs}*^{_" fullword ascii
		 $a43= "v32@0:8^{_xmlNode=^vi*^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlDoc}^{_xmlNs}*^{_" fullword ascii
		 $a44= "v32@0:8^{_xmlNs=^{_xmlNs}i**^v^{_xmlDoc}}16^{_xmlNode=^vi*^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNod" fullword ascii
		 $a45= "v40@0:8^{_xmlNode=^vi*^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlDoc}^{_xmlNs}*^{_" fullword ascii
		 $a46= "xmlAttr}^{_xmlNs}^vSS}16^{_xmlNode=^vi*^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xml" fullword ascii
		 $a47= "xmlAttr}^{_xmlNs}^vSS}8^{_xmlNode=^vi*^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlD" fullword ascii
		 $a48= "^{_xmlDoc=^vi*^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlDoc}ii^{_xmlDtd}^{_xmlDtd" fullword ascii
		 $a49= "^{_xmlNode=^vi*^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlNode}^{_xmlDoc}^{_xmlNs}*^{_xmlAttr" fullword ascii

		 $hex1= {246131303d20226765}
		 $hex2= {246131313d20226765}
		 $hex3= {246131323d20222540}
		 $hex4= {246131333d20222540}
		 $hex5= {246131343d20222540}
		 $hex6= {246131353d20222540}
		 $hex7= {246131363d20222540}
		 $hex8= {246131373d20226874}
		 $hex9= {246131383d20226874}
		 $hex10= {246131393d20226874}
		 $hex11= {2461313d2022403132}
		 $hex12= {246132303d20226874}
		 $hex13= {246132313d20226874}
		 $hex14= {246132323d20222f69}
		 $hex15= {246132333d20222f69}
		 $hex16= {246132343d20226964}
		 $hex17= {246132353d20226d71}
		 $hex18= {246132363d20222540}
		 $hex19= {246132373d20222540}
		 $hex20= {246132383d20227265}
		 $hex21= {246132393d20227265}
		 $hex22= {2461323d2022403132}
		 $hex23= {246133303d20227265}
		 $hex24= {246133313d20227265}
		 $hex25= {246133323d20227265}
		 $hex26= {246133333d20227265}
		 $hex27= {246133343d20227365}
		 $hex28= {246133353d20227365}
		 $hex29= {246133363d20227365}
		 $hex30= {246133373d20227365}
		 $hex31= {246133383d20227365}
		 $hex32= {246133393d20227370}
		 $hex33= {2461333d2022403234}
		 $hex34= {246134303d20227631}
		 $hex35= {246134313d20227631}
		 $hex36= {246134323d20227632}
		 $hex37= {246134333d20227633}
		 $hex38= {246134343d20227633}
		 $hex39= {246134353d20227634}
		 $hex40= {246134363d2022786d}
		 $hex41= {246134373d2022786d}
		 $hex42= {246134383d20225e7b}
		 $hex43= {246134393d20225e7b}
		 $hex44= {2461343d2022403234}
		 $hex45= {2461353d2022616443}
		 $hex46= {2461363d2022617070}
		 $hex47= {2461373d20223f4669}
		 $hex48= {2461383d20223f4669}
		 $hex49= {2461393d2022254066}
		 $hex50= {24733130303d202267}
		 $hex51= {24733130313d202267}
		 $hex52= {24733130323d202267}
		 $hex53= {24733130333d202247}
		 $hex54= {24733130343d202267}
		 $hex55= {24733130353d202247}
		 $hex56= {24733130363d202247}
		 $hex57= {24733130373d202267}
		 $hex58= {24733130383d202267}
		 $hex59= {24733130393d202267}
		 $hex60= {247331303d20222d20}
		 $hex61= {24733131303d202247}
		 $hex62= {24733131313d202247}
		 $hex63= {24733131323d202267}
		 $hex64= {24733131333d202247}
		 $hex65= {24733131343d202247}
		 $hex66= {24733131353d202247}
		 $hex67= {24733131363d202247}
		 $hex68= {24733131373d202267}
		 $hex69= {24733131383d202267}
		 $hex70= {24733131393d202267}
		 $hex71= {247331313d20226261}
		 $hex72= {24733132303d202247}
		 $hex73= {24733132313d202247}
		 $hex74= {24733132323d202247}
		 $hex75= {24733132333d202247}
		 $hex76= {24733132343d202247}
		 $hex77= {24733132353d202267}
		 $hex78= {24733132363d202267}
		 $hex79= {24733132373d202227}
		 $hex80= {24733132383d202248}
		 $hex81= {24733132393d202248}
		 $hex82= {247331323d20226261}
		 $hex83= {24733133303d202248}
		 $hex84= {24733133313d202248}
		 $hex85= {24733133323d202248}
		 $hex86= {24733133333d202227}
		 $hex87= {24733133343d202248}
		 $hex88= {24733133353d202248}
		 $hex89= {24733133363d202248}
		 $hex90= {24733133373d202227}
		 $hex91= {24733133383d202248}
		 $hex92= {24733133393d202248}
		 $hex93= {247331333d20226261}
		 $hex94= {24733134303d202248}
		 $hex95= {24733134313d202248}
		 $hex96= {24733134323d202268}
		 $hex97= {24733134333d202268}
		 $hex98= {24733134343d202268}
		 $hex99= {24733134353d202268}
		 $hex100= {24733134363d202268}
		 $hex101= {24733134373d202249}
		 $hex102= {24733134383d202269}
		 $hex103= {24733134393d202269}
		 $hex104= {247331343d20222742}
		 $hex105= {24733135303d202269}
		 $hex106= {24733135313d202227}
		 $hex107= {24733135323d202269}
		 $hex108= {24733135333d202269}
		 $hex109= {24733135343d202269}
		 $hex110= {24733135353d202269}
		 $hex111= {24733135363d202269}
		 $hex112= {24733135373d202269}
		 $hex113= {24733135383d202269}
		 $hex114= {24733135393d202227}
		 $hex115= {247331353d20226274}
		 $hex116= {24733136303d202269}
		 $hex117= {24733136313d202227}
		 $hex118= {24733136323d20226c}
		 $hex119= {24733136333d202227}
		 $hex120= {24733136343d20226c}
		 $hex121= {24733136353d20226d}
		 $hex122= {24733136363d20226d}
		 $hex123= {24733136373d20224d}
		 $hex124= {24733136383d20224d}
		 $hex125= {24733136393d20226d}
		 $hex126= {247331363d20224361}
		 $hex127= {24733137303d20224d}
		 $hex128= {24733137313d20224d}
		 $hex129= {24733137323d20222d}
		 $hex130= {24733137333d20222d}
		 $hex131= {24733137343d20222d}
		 $hex132= {24733137353d20222d}
		 $hex133= {24733137363d20222d}
		 $hex134= {24733137373d20222d}
		 $hex135= {24733137383d20222d}
		 $hex136= {24733137393d20224f}
		 $hex137= {247331373d20224361}
		 $hex138= {24733138303d202270}
		 $hex139= {24733138313d202270}
		 $hex140= {24733138323d202227}
		 $hex141= {24733138333d202270}
		 $hex142= {24733138343d202270}
		 $hex143= {24733138353d202270}
		 $hex144= {24733138363d202270}
		 $hex145= {24733138373d20222d}
		 $hex146= {24733138383d202272}
		 $hex147= {24733138393d202272}
		 $hex148= {247331383d20226341}
		 $hex149= {24733139303d202272}
		 $hex150= {24733139313d202272}
		 $hex151= {24733139323d202227}
		 $hex152= {24733139333d202272}
		 $hex153= {24733139343d202272}
		 $hex154= {24733139353d202272}
		 $hex155= {24733139363d202272}
		 $hex156= {24733139373d202272}
		 $hex157= {24733139383d202225}
		 $hex158= {24733139393d202227}
		 $hex159= {247331393d2022636c}
		 $hex160= {2473313d20227b2530}
		 $hex161= {24733230303d202273}
		 $hex162= {24733230313d202273}
		 $hex163= {24733230323d202253}
		 $hex164= {24733230333d202253}
		 $hex165= {24733230343d202253}
		 $hex166= {24733230353d202253}
		 $hex167= {24733230363d202253}
		 $hex168= {24733230373d202253}
		 $hex169= {24733230383d202253}
		 $hex170= {24733230393d202253}
		 $hex171= {247332303d20222f63}
		 $hex172= {24733231303d202253}
		 $hex173= {24733231313d202253}
		 $hex174= {24733231323d202225}
		 $hex175= {24733231333d202253}
		 $hex176= {24733231343d202274}
		 $hex177= {24733231353d202254}
		 $hex178= {24733231363d202254}
		 $hex179= {24733231373d202274}
		 $hex180= {24733231383d202227}
		 $hex181= {24733231393d202274}
		 $hex182= {247332313d2022636f}
		 $hex183= {24733232303d202227}
		 $hex184= {24733232313d202227}
		 $hex185= {24733232323d202274}
		 $hex186= {24733232333d202274}
		 $hex187= {24733232343d202274}
		 $hex188= {24733232353d202274}
		 $hex189= {24733232363d202227}
		 $hex190= {24733232373d202274}
		 $hex191= {24733232383d202274}
		 $hex192= {24733232393d202274}
		 $hex193= {247332323d20222763}
		 $hex194= {24733233303d202227}
		 $hex195= {24733233313d202274}
		 $hex196= {24733233323d202274}
		 $hex197= {24733233333d202227}
		 $hex198= {24733233343d202227}
		 $hex199= {24733233353d202274}
		 $hex200= {24733233363d202274}
		 $hex201= {24733233373d202274}
		 $hex202= {24733233383d202274}
		 $hex203= {24733233393d202274}
		 $hex204= {247332333d20222763}
		 $hex205= {24733234303d202274}
		 $hex206= {24733234313d202227}
		 $hex207= {24733234323d202274}
		 $hex208= {24733234333d202274}
		 $hex209= {24733234343d20222d}
		 $hex210= {24733234353d20222d}
		 $hex211= {24733234363d20222d}
		 $hex212= {24733234373d202276}
		 $hex213= {24733234383d202257}
		 $hex214= {24733234393d20225b}
		 $hex215= {247332343d20222763}
		 $hex216= {24733235303d202257}
		 $hex217= {24733235313d202257}
		 $hex218= {24733235323d202257}
		 $hex219= {24733235333d202257}
		 $hex220= {247332353d2022636f}
		 $hex221= {247332363d2022636f}
		 $hex222= {247332373d2022436f}
		 $hex223= {247332383d2022436f}
		 $hex224= {247332393d2022436f}
		 $hex225= {2473323d2022302564}
		 $hex226= {247333303d20224372}
		 $hex227= {247333313d20224465}
		 $hex228= {247333323d20224465}
		 $hex229= {247333333d20222744}
		 $hex230= {247333343d20224465}
		 $hex231= {247333353d20224465}
		 $hex232= {247333363d20224465}
		 $hex233= {247333373d20226465}
		 $hex234= {247333383d20226465}
		 $hex235= {247333393d20226465}
		 $hex236= {2473333d2022343035}
		 $hex237= {247334303d20226465}
		 $hex238= {247334313d20226465}
		 $hex239= {247334323d20226465}
		 $hex240= {247334333d20226465}
		 $hex241= {247334343d20226465}
		 $hex242= {247334353d20222764}
		 $hex243= {247334363d20222764}
		 $hex244= {247334373d20222764}
		 $hex245= {247334383d20226465}
		 $hex246= {247334393d20226465}
		 $hex247= {2473343d20222d2061}
		 $hex248= {247335303d20226465}
		 $hex249= {247335313d20226465}
		 $hex250= {247335323d20222764}
		 $hex251= {247335333d20226465}
		 $hex252= {247335343d20226465}
		 $hex253= {247335353d20226465}
		 $hex254= {247335363d20226465}
		 $hex255= {247335373d20226465}
		 $hex256= {247335383d2022446f}
		 $hex257= {247335393d20224572}
		 $hex258= {2473353d2022416e69}
		 $hex259= {247336303d20224572}
		 $hex260= {247336313d20224572}
		 $hex261= {247336323d20224578}
		 $hex262= {247336333d20224578}
		 $hex263= {247336343d20226669}
		 $hex264= {247336353d20226669}
		 $hex265= {247336363d20226669}
		 $hex266= {247336373d20226669}
		 $hex267= {247336383d20226669}
		 $hex268= {247336393d20226669}
		 $hex269= {2473363d2022617070}
		 $hex270= {247337303d20226669}
		 $hex271= {247337313d20226669}
		 $hex272= {247337323d20226669}
		 $hex273= {247337333d20226669}
		 $hex274= {247337343d20226669}
		 $hex275= {247337353d2022666c}
		 $hex276= {247337363d2022666c}
		 $hex277= {247337373d20222d20}
		 $hex278= {247337383d20226761}
		 $hex279= {247337393d20226761}
		 $hex280= {2473373d2022617070}
		 $hex281= {247338303d20226761}
		 $hex282= {247338313d20226762}
		 $hex283= {247338323d20226763}
		 $hex284= {247338333d20226763}
		 $hex285= {247338343d20226743}
		 $hex286= {247338353d20226764}
		 $hex287= {247338363d20224764}
		 $hex288= {247338373d20226764}
		 $hex289= {247338383d20226764}
		 $hex290= {247338393d20224764}
		 $hex291= {2473383d2022417070}
		 $hex292= {247339303d20224766}
		 $hex293= {247339313d20224748}
		 $hex294= {247339323d20224748}
		 $hex295= {247339333d20226748}
		 $hex296= {247339343d20224748}
		 $hex297= {247339353d20226748}
		 $hex298= {247339363d20224769}
		 $hex299= {247339373d20224769}
		 $hex300= {247339383d20226769}
		 $hex301= {247339393d20224769}
		 $hex302= {2473393d20222d2041}

	condition:
		37 of them
}
