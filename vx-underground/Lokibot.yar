
/*
   YARA Rule Set
   Author: resteex
   Identifier: Lokibot 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Lokibot {
	meta: 
		 description= "Lokibot Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-13-12" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "04bdaec3bf8ef272bd6de2acf3cb828c"
		 hash2= "21e6f4fefdf70039a9160ca04a388389"
		 hash3= "3f327df4753c877cc8c91a952df75fb9"
		 hash4= "4e7c50fb3577f51f87e113c2fc40d5e7"
		 hash5= "6cc1182298faedff4123a01cd71f17f5"
		 hash6= "79cbe5c736dca5564640e51892f32c1b"
		 hash7= "8cf5cb10708d0fea42106a1d31ba4248"
		 hash8= "8f35517bd68bbe4d0d2362445172763a"
		 hash9= "95f5f9111344c4c472b9d6656337abe3"
		 hash10= "97ee10e7b9b299b04c83d12eaf6dc5f5"
		 hash11= "9b8e1997fa6a66bc23a203c92c175f77"
		 hash12= "a0339a15a2f219b54b3c1a6b4afbc6be"
		 hash13= "cf940aab721563c8e310b535f0e8a2f8"
		 hash14= "f3d18776fefa9b0cffa6914cdf306cc9"

	strings:

	
 		 $s1= "Add_Manager_show.BackgroundImage" fullword wide
		 $s2= "Add_user_show.BackgroundImage" fullword wide
		 $s3= "Bt_add_manager.BackgroundImage" fullword wide
		 $s4= "Bt_Continue_As_Guest.BackgroundImage" fullword wide
		 $s5= "Bt_Continue_As_Manager.BackgroundImage" fullword wide
		 $s6= "Bt_Continue_As_Player.BackgroundImage" fullword wide
		 $s7= "Bt_continue.BackgroundImage" fullword wide
		 $s8= "Bt_Continue_change_details" fullword wide
		 $s9= "Bt_Continue_change_details.BackgroundImage" fullword wide
		 $s10= "Bt_credits.BackgroundImage" fullword wide
		 $s11= "Bt_feedback.BackgroundImage" fullword wide
		 $s12= "Bt_get_tip.BackgroundImage" fullword wide
		 $s13= "Bt_Givefeedback.BackgroundImage" fullword wide
		 $s14= "Bt_Guest_login.BackgroundImage" fullword wide
		 $s15= "Bt_guistwait_back.BackgroundImage" fullword wide
		 $s16= "bt_guistwait_exit.BackgroundImage" fullword wide
		 $s17= "BT_login_reports.BackgroundImage" fullword wide
		 $s18= "Bt_MainForm_exit.BackgroundImage" fullword wide
		 $s19= "Bt_manager_add.BackgroundImage" fullword wide
		 $s20= "Bt_manager_back.BackgroundImage" fullword wide
		 $s21= "Bt_manager_exit.BackgroundImage" fullword wide
		 $s22= "Bt_manager_login.BackgroundImage" fullword wide
		 $s23= "Bt_manager_tips.BackgroundImage" fullword wide
		 $s24= "BT_New_game.BackgroundImage" fullword wide
		 $s25= "Bt_personal_scores.BackgroundImage" fullword wide
		 $s26= "Bt_play_game.BackgroundImage" fullword wide
		 $s27= "Bt_remove.BackgroundImage" fullword wide
		 $s28= "Bt_Reports_Back.BackgroundImage" fullword wide
		 $s29= "Bt_Reports_Exit.BackgroundImage" fullword wide
		 $s30= "Bt_Reversi_back.BackgroundImage" fullword wide
		 $s31= "Bt_reversi_exit.BackgroundImage" fullword wide
		 $s32= "Bt_reversi_instuctions.BackgroundImage" fullword wide
		 $s33= "Bt_score_report.BackgroundImage" fullword wide
		 $s34= "Bt_top_players.BackgroundImage" fullword wide
		 $s35= "Bt_user_add.BackgroundImage" fullword wide
		 $s36= "Bt_User_login.BackgroundImage" fullword wide
		 $s37= "Bt_User_managment_back.BackgroundImage" fullword wide
		 $s38= "Bt_User_Managment_exit.BackgroundImage" fullword wide
		 $s39= "Bt_usersOptions_exit.BackgroundImage" fullword wide
		 $s40= "{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}N" fullword wide
		 $s41= "GameBox.Properties.Resources" fullword wide
		 $s42= "Microsoft.Container.DataSpaces" fullword wide
		 $s43= "Microsoft.Container.EncryptionTransform" fullword wide
		 $s44= "OpenCC_GUI.Languages.Language_" fullword wide
		 $s45= "panel_board.BackgroundImage" fullword wide
		 $s46= "pictureBox1.BackgroundImage" fullword wide
		 $s47= "pictureBox2.BackgroundImage" fullword wide
		 $s48= "Portalquiz.Properties.Resources" fullword wide
		 $s49= "Remove_Manager_show.BackgroundImage" fullword wide
		 $s50= "Remove_user_show.BackgroundImage" fullword wide
		 $s51= "StrongEncryptionDataSpace" fullword wide
		 $s52= "StrongEncryptionTransform" fullword wide
		 $s53= "Wobetesido suvesebuxomelot" fullword wide

		 $hex1= {247331303d20224274}
		 $hex2= {247331313d20224274}
		 $hex3= {247331323d20224274}
		 $hex4= {247331333d20224274}
		 $hex5= {247331343d20224274}
		 $hex6= {247331353d20224274}
		 $hex7= {247331363d20226274}
		 $hex8= {247331373d20224254}
		 $hex9= {247331383d20224274}
		 $hex10= {247331393d20224274}
		 $hex11= {2473313d2022416464}
		 $hex12= {247332303d20224274}
		 $hex13= {247332313d20224274}
		 $hex14= {247332323d20224274}
		 $hex15= {247332333d20224274}
		 $hex16= {247332343d20224254}
		 $hex17= {247332353d20224274}
		 $hex18= {247332363d20224274}
		 $hex19= {247332373d20224274}
		 $hex20= {247332383d20224274}
		 $hex21= {247332393d20224274}
		 $hex22= {2473323d2022416464}
		 $hex23= {247333303d20224274}
		 $hex24= {247333313d20224274}
		 $hex25= {247333323d20224274}
		 $hex26= {247333333d20224274}
		 $hex27= {247333343d20224274}
		 $hex28= {247333353d20224274}
		 $hex29= {247333363d20224274}
		 $hex30= {247333373d20224274}
		 $hex31= {247333383d20224274}
		 $hex32= {247333393d20224274}
		 $hex33= {2473333d202242745f}
		 $hex34= {247334303d20227b46}
		 $hex35= {247334313d20224761}
		 $hex36= {247334323d20224d69}
		 $hex37= {247334333d20224d69}
		 $hex38= {247334343d20224f70}
		 $hex39= {247334353d20227061}
		 $hex40= {247334363d20227069}
		 $hex41= {247334373d20227069}
		 $hex42= {247334383d2022506f}
		 $hex43= {247334393d20225265}
		 $hex44= {2473343d202242745f}
		 $hex45= {247335303d20225265}
		 $hex46= {247335313d20225374}
		 $hex47= {247335323d20225374}
		 $hex48= {247335333d2022576f}
		 $hex49= {2473353d202242745f}
		 $hex50= {2473363d202242745f}
		 $hex51= {2473373d202242745f}
		 $hex52= {2473383d202242745f}
		 $hex53= {2473393d202242745f}

	condition:
		35 of them
}
