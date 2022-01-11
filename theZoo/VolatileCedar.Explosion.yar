
/*
   YARA Rule Set
   Author: resteex
   Identifier: VolatileCedar_Explosion 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_VolatileCedar_Explosion {
	meta: 
		 description= "VolatileCedar_Explosion Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-30-59" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "034e4c62965f8d5dd5d5a2ce34a53ba9"
		 hash2= "08c988d6cebdd55f3b123f2d9d5507a6"
		 hash3= "184320a057e455555e3be22e67663722"
		 hash4= "1d4b0fc476b7d20f1ef590bcaa78dc5d"
		 hash5= "1dcac3178a1b85d5179ce75eace04d10"
		 hash6= "22872f40f5aad3354bbf641fe90f2fd6"
		 hash7= "29eca6286a01c0b684f7d5f0bfe0c0e6"
		 hash8= "2b9106e8df3aa98c3654a4e0733d83e7"
		 hash9= "306d243745ba53d09353b3b722d471b8"
		 hash10= "3f35c97e9e87472030b84ae1bc932ffc"
		 hash11= "44b5a3af895f31e22f6bc4eb66bd3eb7"
		 hash12= "4f8b989bc424a39649805b5b93318295"
		 hash13= "5b505d0286378efcca4df38ed4a26c90"
		 hash14= "5ca3ac2949022e5c77335f7e228db1d8"
		 hash15= "5d437eb2a22ec8f37139788f2087d45d"
		 hash16= "61b11b9e6baae4f764722a808119ed0c"
		 hash17= "66e2adf710261e925db588b5fac98ad8"
		 hash18= "6f11a67803e1299a22c77c8e24072b82"
		 hash19= "7031426fb851e93965a72902842b7c2c"
		 hash20= "740c47c663f5205365ae9fb08adfb127"
		 hash21= "7cd87c4976f1b34a0b060a23faddbd19"
		 hash22= "7dbc46559efafe8ec8446b836129598c"
		 hash23= "826b772c81f41505f96fc18e666b1acd"
		 hash24= "981234d969a4c5e6edea50df009efedd"
		 hash25= "9a5a99def615966ea05e3067057d6b37"
		 hash26= "ab3d0c748ced69557f78b7071879e50a"
		 hash27= "c19e91a91a2fa55e869c42a70da9a506"
		 hash28= "c7ac6193245b76cc8cebc2835ee13532"
		 hash29= "c898aed0ab4173cc3ac7d4849d06e7fa"
		 hash30= "c9a4317f1002fefcc7a250c3d76d4b01"
		 hash31= "d2074d6273f41c34e8ba370aa9af46ad"
		 hash32= "e6f874b7629b11a2f5ed3cc2c123f8b6"
		 hash33= "ea53e618432ca0c823fafc06dc60b726"
		 hash34= "eb7042ad32f41c0e577b5b504c7558ea"
		 hash35= "edaca6fb1896a120237b2ce13f6bc3e6"

	strings:

	
 		 $s1= "1998-2012 VMware, Inc." fullword wide
		 $s2= "6.00.2900.2180 (xpsp_sp2_rtm.040803-2158)" fullword wide
		 $s3= "6.1.7600.16385 (win7_rtm.090713-1255)" fullword wide
		 $s4= "8.00.6001.18702" fullword wide
		 $s5= "9.2.0 build-799703" fullword wide
		 $s6= "All Rights Reserved" fullword wide
		 $s7= "Copyright (C) 2009" fullword wide
		 $s8= "Copyright (C) 2011" fullword wide
		 $s9= "Copyright (C) 2013" fullword wide
		 $s10= "Copyright Microsoft (C) 2009" fullword wide
		 $s11= "DefaultPassword" fullword wide
		 $s12= "EL$_RasDefaultCredentials#0" fullword wide
		 $s13= "error.renamefile" fullword wide
		 $s14= "FileDescription" fullword wide
		 $s15= "HTML Help Executable" fullword wide
		 $s16= "Internet Explorer" fullword wide
		 $s17= "Internet Explorer" fullword wide
		 $s18= "Internet Extensions for Win32" fullword wide
		 $s19= "LegalTrademarks" fullword wide
		 $s20= "Microsoft Corporation" fullword wide
		 $s21= "Microsoft Corporation. All rights reserved." fullword wide
		 $s22= "Operating System" fullword wide
		 $s23= "OriginalFilename" fullword wide
		 $s24= "Program Manager" fullword wide
		 $s25= "SELECT * FROM Win32_Process" fullword wide
		 $s26= "tools Dynamic Link Library" fullword wide
		 $s27= "tools Dynamic Link Library" fullword wide
		 $s28= "VMware Activation Helper" fullword wide
		 $s29= "VS_VERSION_INFO" fullword wide
		 $s30= "Windows Help DLL" fullword wide
		 $s31= "Windows Help Service" fullword wide
		 $s32= "Windows@ Internet Explorer" fullword wide
		 $s33= "Windows@ Internet Explorer" fullword wide
		 $s34= "Windows Winhlp32 Stub" fullword wide
		 $a1= "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" fullword ascii
		 $a2= "{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{" fullword ascii
		 $a3= "0@100@111@119@115@72@101@108@112@101@114@:DLD-SNCDLD-ST:87@105@110@100@111@119@115@32@72@101@108@112" fullword ascii
		 $a4= "%02X%02X%02X%02X%02X%02X%c" fullword ascii
		 $a5= "05@110@100@101@120@46@112@104@112@:DLD-D" fullword ascii
		 $a6= "09@47@105@110@100@101@120@46@112@104@112@:DLD-D" fullword ascii
		 $a7= "1111111111DLD-TN:69@120@112@108@111@115@105@118@101@:DLD-TN" fullword ascii
		 $a8= "1@114@:DLD-SN_DLD-ST:86@77@119@97@114@101@65@99@116@105@118@97@116@105@111@110@72@101@108@112@101@11" fullword ascii
		 $a9= "1@119@115@73@110@101@116@:DLD-SN;DLD-ST:87@105@110@100@111@119@115@32@73@110@101@116@:DLD-ST" fullword ascii
		 $a10= "112@114@100@97@116@97@46@115@121@115@" fullword ascii
		 $a11= "115@100@97@116@97@46@115@121@115@" fullword ascii
		 $a12= "119@110@104@101@108@112@46@100@108@108@" fullword ascii
		 $a13= "18@105@99@101@:DLD-CcDLD-C0:119@105@110@100@111@119@115@45@104@101@108@112@101@114@45@115@101@114@11" fullword ascii
		 $a14= "2@101@114@:DLD-RN_DLD-SN:86@77@119@97@114@101@65@99@116@105@118@97@116@105@111@110@72@101@108@112@10" fullword ascii
		 $a15= "2@111@47@109@105@99@114@111@47@100@97@116@97@47@105@110@100@101@120@46@112@104@112@:DLD-D" fullword ascii
		 $a16= "&&&'''+227DLLLLMMOMMQMQQO" fullword ascii
		 $a17= "31373C3H3P3V3]3c3j3p3x3~3" fullword ascii
		 $a18= "5$5)51575>5D5K5Q5Y5_5f5k5p5u5z5" fullword ascii
		 $a19= "52@52@51@47@105@110@100@101@120@46@112@104@112@:DLD-D" fullword ascii
		 $a20= "5!5'5.545;5A5I5O5V5[5`5e5j5p5t5y5~5" fullword ascii
		 $a21= "56@48@47@105@110@100@101@120@46@112@104@112@:DLD-D" fullword ascii
		 $a22= "77@105@99@114@111@115@111@102@116@" fullword ascii
		 $a23= "7#7*7/74797>7D7H7M7R7X7`7" fullword ascii
		 $a24= "%%&&''++-777NNNONOSOSSTTTTY" fullword ascii
		 $a25= "%&&'&'++77L7LLNONOOOQQQQQR" fullword ascii
		 $a26= "8@112@101@114@:DLD-SN%DLD-ST:72@101@108@112@101@114@:DLD-ST" fullword ascii
		 $a27= "82BD0E67-9FEA-4748-8672-D5EFE5B779B0" fullword ascii
		 $a28= "92@112@100@97@116@97@46@115@121@115@" fullword ascii
		 $a29= "92@67@111@110@102@105@103@46@77@115@105@" fullword ascii
		 $a30= "9375CFF0413111d3B88A00104B2A6676" fullword ascii
		 $a31= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" fullword ascii
		 $a32= ".?AV?$basic_filebuf@DU?$char_traits@D@std@@@std@@" fullword ascii
		 $a33= ".?AV?$basic_ios@DU?$char_traits@D@std@@@std@@" fullword ascii
		 $a34= ".?AV?$basic_ostream@DU?$char_traits@D@std@@@std@@" fullword ascii
		 $a35= ".?AV?$basic_streambuf@DU?$char_traits@D@std@@@std@@" fullword ascii
		 $a36= ".?AV?$money_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@std@@@std@@" fullword ascii
		 $a37= ".?AV?$money_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@std@@@std@@" fullword ascii
		 $a38= ".?AV?$money_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@@std@@@std@@" fullword ascii
		 $a39= ".?AV?$moneypunct@D$00@std@@" fullword ascii
		 $a40= ".?AV?$moneypunct@D$0A@@std@@" fullword ascii
		 $a41= ".?AV?$moneypunct@G$00@std@@" fullword ascii
		 $a42= ".?AV?$moneypunct@G$0A@@std@@" fullword ascii
		 $a43= ".?AV?$moneypunct@_W$00@std@@" fullword ascii
		 $a44= ".?AV?$moneypunct@_W$0A@@std@@" fullword ascii
		 $a45= ".?AV?$money_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@std@@@std@@" fullword ascii
		 $a46= ".?AV?$money_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@std@@@std@@" fullword ascii
		 $a47= ".?AV?$money_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@@std@@@std@@" fullword ascii
		 $a48= ".?AV?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@std@@@std@@" fullword ascii
		 $a49= ".?AV?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@std@@@std@@" fullword ascii
		 $a50= ".?AV?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@@std@@@std@@" fullword ascii
		 $a51= ".?AV?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@std@@@std@@" fullword ascii
		 $a52= ".?AV?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@std@@@std@@" fullword ascii
		 $a53= ".?AV?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@@std@@@std@@" fullword ascii
		 $a54= ".?AV?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@std@@@std@@" fullword ascii
		 $a55= ".?AV?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@std@@@std@@" fullword ascii
		 $a56= ".?AV?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@@std@@@std@@" fullword ascii
		 $a57= ".?AV?$time_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@std@@@std@@" fullword ascii
		 $a58= ".?AV?$time_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@std@@@std@@" fullword ascii
		 $a59= ".?AV?$time_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@@std@@@std@@" fullword ascii
		 $a60= ".?AVfailure@ios_base@std@@" fullword ascii
		 $a61= "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbc" fullword ascii
		 $a62= "cbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbc" fullword ascii
		 $a63= "@:DLD-C[DLD-C0:119@105@110@100@111@119@115@45@104@101@108@112@45@115@101@114@118@105@99@101@:DLD-C0" fullword ascii
		 $a64= "@:DLD-C[DLD-C0:119@105@110@100@111@119@115@45@104@101@108@112@45@115@101@114@118@105@99@101@:DLD-C0." fullword ascii
		 $a65= "DLD-D:104@116@116@112@58@47@47@101@120@112@108@111@114@101@114@101@100@111@116@110@116@46@105@110@10" fullword ascii
		 $a66= "DLD-D:104@116@116@112@58@47@47@115@97@118@101@119@101@98@46@119@105@110@107@46@119@115@47@118@50@47@" fullword ascii
		 $a67= "DLD-D:104@116@116@112@58@47@47@115@97@118@101@119@101@98@46@119@105@110@107@46@119@115@47@56@48@47@1" fullword ascii
		 $a68= "DLD-D:104@116@116@112@58@47@47@99@97@114@105@109@97@50@48@49@50@46@115@105@116@101@57@48@46@99@111@1" fullword ascii
		 $a69= "DLD-E:.info+.com:DLD-EaDLD-C:119@105@110@100@111@119@115@45@104@101@108@112@101@114@45@115@101@114@1" fullword ascii
		 $a70= "DLD-E:.info:DLD-E,DLD-C:105@101@115@101@114@118@101@114@:DLD-C.DLD-C0:105@101@115@101@114@118@101@11" fullword ascii
		 $a71= "DLD-E:.info:DLD-EYDLD-C:119@105@110@100@111@119@115@45@104@101@108@112@45@115@101@114@118@105@99@101" fullword ascii
		 $a72= "DLD-NTI:300:DLD-NTI8DLD-IP:49@56@52@46@49@48@55@46@57@55@46@49@56@56@:DLD-IP" fullword ascii
		 $a73= "DLD-NTI:300:DLD-NTI)DLD-IP:49@50@55@46@48@46@48@46@49@:DLD-IP" fullword ascii
		 $a74= "DLD-NTI:300:DLD-NTI/DLD-IP:54@57@46@54@52@46@57@48@46@57@52@:DLD-IP" fullword ascii
		 $a75= "DLD-NTI:500:DLD-NTI/DLD-IP:54@57@46@54@52@46@57@48@46@57@52@:DLD-IP" fullword ascii
		 $a76= "DLD-PRT:49@52@52@51@:DLD-PRT" fullword ascii
		 $a77= "DLD-PRT:49@52@52@52@51@:DLD-PRT" fullword ascii
		 $a78= "DLD-PRT:52@52@51@:DLD-PRT" fullword ascii
		 $a79= "DLD-RL:0:DLD-RLCDLD-RN:87@105@110@100@111@119@115@32@72@101@108@112@101@114@:DLD-RN%DLD-SN:72@101@10" fullword ascii
		 $a80= "DLD-RL:0:DLD-RLCDLD-RN:87@105@110@100@111@119@115@32@72@101@108@112@101@114@:DLD-RN@DLD-SN:87@105@11" fullword ascii
		 $a81= "DLD-RL:0:DLD-RL;DLD-RN:87@105@110@100@111@119@115@32@73@110@101@116@:DLD-RN8DLD-SN:87@105@110@100@11" fullword ascii
		 $a82= "DLD-RL:2:DLD-RLeDLD-RN:86@77@119@97@114@101@32@65@99@116@105@118@97@116@105@111@110@32@72@101@108@11" fullword ascii
		 $a83= "DLD-RN:105@110@101@116@:DLD-RN;DLD-IP:50@49@51@46@50@48@52@46@49@50@50@46@49@51@48@:DLD-IP" fullword ascii
		 $a84= "DLD-S:redotntexplore:DLD-S1DLD-P:47@101@120@47@105@101@46@112@104@112@:DLD-P" fullword ascii
		 $a85= "DLD-S:redotntexplore:DLD-S;DLD-P:47@56@48@47@105@110@100@101@120@46@112@104@112@:DLD-P" fullword ascii
		 $a86= "DLD-S:redotntexplore:DLD-SEDLD-P:47@118@50@47@56@48@47@105@110@100@101@120@46@112@104@112@:DLD-P" fullword ascii
		 $a87= "DLD-S:redotntexplore:DLD-SHDLD-P:47@118@50@47@52@52@51@47@105@110@100@101@120@46@112@104@112@:DLD-P" fullword ascii
		 $a88= "DLD-S:redotntexplore:DLD-SYDLD-P:47@109@105@99@114@111@47@100@97@116@97@47@105@110@100@101@120@46@11" fullword ascii
		 $a89= "DLD-VR:v2:DLD-VR=DLD-TN:69@120@112@108@111@115@105@118@101@45@52@52@51@:DLD-TN" fullword ascii
		 $a90= "DLD-VR:v2:DLD-VR:DLD-TN:69@120@112@108@111@115@105@118@101@45@56@48@:DLD-TN" fullword ascii
		 $a91= "DLD-VR:v3:DLD-VR=DLD-TN:69@120@112@108@111@115@105@118@101@45@52@52@51@:DLD-TN" fullword ascii
		 $a92= "d:vb_c++c++Profiler-PSmartSenderwnhelpwnhelpReleasewnhelp.pdb" fullword ascii
		 $a93= "ExpandEnvironmentStringsA" fullword ascii
		 $a94= "GAIsProcessorFeaturePresent" fullword ascii
		 $a95= "GdipCreateBitmapFromHBITMAP" fullword ascii
		 $a96= "GdipCreateBitmapFromScan0" fullword ascii
		 $a97= "GdipGetImageGraphicsContext" fullword ascii
		 $a98= "GetFileInformationByHandle" fullword ascii
		 $a99= "GetUserObjectInformationA" fullword ascii
		 $a100= "==gKg5XI+BmK=0UajJ3bz9mZ0BCSlxGc" fullword ascii
		 $a101= "==gKg5XI+BmK=0WYrR3bvJmL5FGav9mLj9Wb" fullword ascii
		 $a102= "==gKg5XI+BmK3d3ducHahR3ctlXawJjLz9WblVmLj9Wb" fullword ascii
		 $a103= "==gKg5XI+BmK3d3duIWaudmLj9Wb" fullword ascii
		 $a104= "==gKg5XI+BmK3hWZsBXZypnLzl3c" fullword ascii
		 $a105= "==gKg5XI+BmK8EiKj9mbuV2Y092aqEiP" fullword ascii
		 $a106= "==gKg5XI+BmK8EiKzV2Y1JXZk92aqEiP" fullword ascii
		 $a107= "==gKg5XI+BmK8oCYxEFQXNSR0IXMgpiP" fullword ascii
		 $a108= "==gKg5XI+BmK90TUyMDN1YTWI5kQkUjN" fullword ascii
		 $a109= "==gKg5XI+BmK==APhoSRuRGVhN3aqEiP" fullword ascii
		 $a110= "==gKg5XI+BmK==APhoySJxETqEiP" fullword ascii
		 $a111= "==gKg5XI+BmK==AXcZHazRWY0FmLkFGd" fullword ascii
		 $a112= "==gKg5XI+BmK==AXsJ2d1NnLkxGb" fullword ascii
		 $a113= "==gKg5XI+BmK==AXsJ2d6BnLkxGb" fullword ascii
		 $a114= "==gKg5XI+BmK=c3d35SbpNmcvN3bmRnLj9Wb" fullword ascii
		 $a115= "==gKg5XI+BmK=c3d35yZv92ZsVmLj9Wb" fullword ascii
		 $a116= "==gKg5XI+BmKcdHalxGclJnL01Gc" fullword ascii
		 $a117= "==gKg5XI+BmKcdHalxGclJnLzl3c" fullword ascii
		 $a118= "==gKg5XI+BmK=cHalxGclJnLzl3c" fullword ascii
		 $a119= "==gKg5XI+BmK=cVauR2b3NHIIVGbwByUlJndpNWZ" fullword ascii
		 $a120= "==gKg5XI+BmKcx1dp52clNmLkxGb" fullword ascii
		 $a121= "==gKg5XI+BmK=cXaulmblRnLlhXZ" fullword ascii
		 $a122= "==gKg5XI+BmKcxldoRWY0FmLzl3c" fullword ascii
		 $a123= "==gKg5XI+BmKcZ3c5NHdl1mLkxGb" fullword ascii
		 $a124= "==gKg5XI+BmK==gKDVHdQF2c0VmRpxWZzpCP" fullword ascii
		 $a125= "==gKg5XI+BmK==gKEVXbwBVYzNnK" fullword ascii
		 $a126= "==gKg5XI+BmK==gKEVXbwhUazRnK" fullword ascii
		 $a127= "==gKg5XI+BmK==gKF5WdtdVauR2b3NnK" fullword ascii
		 $a128= "==gKg5XI+BmK==gKF5WdttUZ5NnK" fullword ascii
		 $a129= "==gKg5XI+BmK==gKHVGdEJXa2V2cG9GbkVmc" fullword ascii
		 $a130= "==gKg5XI+BmK==gKHVGdSV2ZWFGb1VmK" fullword ascii
		 $a131= "==gKg5XI+BmK==gKqMEbvNXZGlGblpiK" fullword ascii
		 $a132= "==gKg5XI+BmK==gOcx1dp52clNmLkxGb" fullword ascii
		 $a133= "==gKg5XI+BmK==gOcZ3c5NHdl1mLkxGb" fullword ascii
		 $a134= "==gKg5XI+BmKhBXauUGe0VmcuFGbpBnLuVGd" fullword ascii
		 $a135= "==gKg5XI+BmK=IXYk5SbpNmcvN3bmRnLj9Wb" fullword ascii
		 $a136= "==gKg5XI+BmKkxGb2h2bzRnLlhXZ" fullword ascii
		 $a137= "==gKg5XI+BmK=Mndzd3allnLlhXZ" fullword ascii
		 $a138= "==gKg5XI+BmK=oCRlxWZ0VmRpxWZzpCP" fullword ascii
		 $a139= "==gKg5XI+BmK=oiRpxWZTVmbkpCP" fullword ascii
		 $a140= "==gKg5XI+BmK=oSRuVXbS92b0tUZ5NnK" fullword ascii
		 $a141= "==gKg5XI+BmK=oSRuVXbXlmbk92dzpCP" fullword ascii
		 $a142= "==gKg5XI+BmK=oyQslGci9WYyRGTvdmK" fullword ascii
		 $a143= "==gKg5XI+BmK=oyQvBXeQF2c0VmRpxWZzpCP" fullword ascii
		 $a144= "==gKg5XI+BmK=Q2b05WZ0dnLlhXZ" fullword ascii
		 $a145= "==gKg5XI+BmK==QbpNmcvN3bmRnLj9Wb" fullword ascii
		 $a146= "==gKg5XI+BmKqcUZ0RkcpZXZzpCP" fullword ascii
		 $a147= "==gKg5XI+BmKqsUasxGUy92YlN3c" fullword ascii
		 $a148= "==gKg5XI+BmKqwUazRHUy92YlN3c" fullword ascii
		 $a149= "==gKg5XI+BmK==wc5N3dp5mLlhXZ" fullword ascii
		 $a150= "==gKg5XI+BmK==wd2hWZsBnLlhXZ" fullword ascii
		 $a151= "==gKg5XI+BmK==wdp5GbvdmLlhXZ" fullword ascii
		 $a152= "==gKg5XI+BmK=wTIqIVRSVlTqEiP" fullword ascii
		 $a153= "==gKg5XI+BmK=wTIqIXZyVnbqEiP" fullword ascii
		 $a154= "==gKg5XI+BmK==wZv92ZsVmLj9Wb" fullword ascii
		 $a155= "==gKg5XI+BmKXlmbk92dzhUZsB3UlJndpNWZ" fullword ascii
		 $a156= "HKEY_CURRENT_USERSOFTWAREMicrosoftWindowsCurrentVersionRun" fullword ascii
		 $a157= "http://maktoob.yahoo.com/" fullword ascii
		 $a158= "http://www.bing.com/default.aspx" fullword ascii
		 $a159= "http://www.microsoft.com/en-us/default.aspx" fullword ascii
		 $a160= "InitializeCriticalSection" fullword ascii
		 $a161= "InitializeCriticalSectionAndSpinCount" fullword ascii
		 $a162= "JanFebMarAprMayJunJulAugSepOctNovDec" fullword ascii
		 $a163= ":Jan:January:Feb:February:Mar:March:Apr:April:May:May:Jun:June:Jul:July:Aug:August:Sep:September:Oct" fullword ascii
		 $a164= "jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj" fullword ascii
		 $a165= "jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj" fullword ascii
		 $a166= "jjkjjkjjkjjkjjkjjkjjkjjkjjkjjkjjkjjk" fullword ascii
		 $a167= "kjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjl" fullword ascii
		 $a168= "{lllmnlllplllplllnlllnllllnlllplllnlllnlllnlllnnlllnllllllll" fullword ascii
		 $a169= "/micro/index.php?micro=11" fullword ascii
		 $a170= "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM5UUYVYYYYYYY]Y]Y:" fullword ascii
		 $a171= "moooooooooooooooooooomlloppmppmppmppppppppppppppppmppppmnml" fullword ascii
		 $a172= "MsgWaitForMultipleObjects" fullword ascii
		 $a173= ":October:Nov:November:Dec:December" fullword ascii
		 $a174= "RegisterServiceCtrlHandlerA" fullword ascii
		 $a175= "SetUnhandledExceptionFilter" fullword ascii
		 $a176= "%s-%i.%i.%i.%i.%i.%i.dat" fullword ascii
		 $a177= "%s-%i.%i.%i.%i.%i.%i.sys" fullword ascii
		 $a178= "SOFTWAREMicrosoftWindowsCurrentVersion" fullword ascii
		 $a179= "SOFTWAREMicrosoftWindowsCurrentVersionRun" fullword ascii
		 $a180= "StartServiceCtrlDispatcherA" fullword ascii
		 $a181= ":Sun:Sunday:Mon:Monday:Tue:Tuesday:Wed:Wednesday:Thu:Thursday:Fri:Friday:Sat:Saturday" fullword ascii
		 $a182= "uttttttttttttttttttttttttttttt" fullword ascii
		 $a183= "vttttttttttttttttttttttttttttt" fullword ascii
		 $a184= "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii
		 $a185= "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwv|~" fullword ascii
		 $a186= "xttttttttttttttttttttttttttttv" fullword ascii
		 $a187= "xttttutttttttttttutttttttttttx" fullword ascii
		 $a188= "xxwwZZYYYXXXXXXXXYXXXYXXXXXXXYXXYYXXYXXXXXTbeeeeehhhO" fullword ascii

		 $hex1= {24613130303d20223d}
		 $hex2= {24613130313d20223d}
		 $hex3= {24613130323d20223d}
		 $hex4= {24613130333d20223d}
		 $hex5= {24613130343d20223d}
		 $hex6= {24613130353d20223d}
		 $hex7= {24613130363d20223d}
		 $hex8= {24613130373d20223d}
		 $hex9= {24613130383d20223d}
		 $hex10= {24613130393d20223d}
		 $hex11= {246131303d20223131}
		 $hex12= {24613131303d20223d}
		 $hex13= {24613131313d20223d}
		 $hex14= {24613131323d20223d}
		 $hex15= {24613131333d20223d}
		 $hex16= {24613131343d20223d}
		 $hex17= {24613131353d20223d}
		 $hex18= {24613131363d20223d}
		 $hex19= {24613131373d20223d}
		 $hex20= {24613131383d20223d}
		 $hex21= {24613131393d20223d}
		 $hex22= {246131313d20223131}
		 $hex23= {24613132303d20223d}
		 $hex24= {24613132313d20223d}
		 $hex25= {24613132323d20223d}
		 $hex26= {24613132333d20223d}
		 $hex27= {24613132343d20223d}
		 $hex28= {24613132353d20223d}
		 $hex29= {24613132363d20223d}
		 $hex30= {24613132373d20223d}
		 $hex31= {24613132383d20223d}
		 $hex32= {24613132393d20223d}
		 $hex33= {246131323d20223131}
		 $hex34= {24613133303d20223d}
		 $hex35= {24613133313d20223d}
		 $hex36= {24613133323d20223d}
		 $hex37= {24613133333d20223d}
		 $hex38= {24613133343d20223d}
		 $hex39= {24613133353d20223d}
		 $hex40= {24613133363d20223d}
		 $hex41= {24613133373d20223d}
		 $hex42= {24613133383d20223d}
		 $hex43= {24613133393d20223d}
		 $hex44= {246131333d20223138}
		 $hex45= {24613134303d20223d}
		 $hex46= {24613134313d20223d}
		 $hex47= {24613134323d20223d}
		 $hex48= {24613134333d20223d}
		 $hex49= {24613134343d20223d}
		 $hex50= {24613134353d20223d}
		 $hex51= {24613134363d20223d}
		 $hex52= {24613134373d20223d}
		 $hex53= {24613134383d20223d}
		 $hex54= {24613134393d20223d}
		 $hex55= {246131343d20223240}
		 $hex56= {24613135303d20223d}
		 $hex57= {24613135313d20223d}
		 $hex58= {24613135323d20223d}
		 $hex59= {24613135333d20223d}
		 $hex60= {24613135343d20223d}
		 $hex61= {24613135353d20223d}
		 $hex62= {24613135363d202248}
		 $hex63= {24613135373d202268}
		 $hex64= {24613135383d202268}
		 $hex65= {24613135393d202268}
		 $hex66= {246131353d20223240}
		 $hex67= {24613136303d202249}
		 $hex68= {24613136313d202249}
		 $hex69= {24613136323d20224a}
		 $hex70= {24613136333d20223a}
		 $hex71= {24613136343d20226a}
		 $hex72= {24613136353d20226a}
		 $hex73= {24613136363d20226a}
		 $hex74= {24613136373d20226b}
		 $hex75= {24613136383d20227b}
		 $hex76= {24613136393d20222f}
		 $hex77= {246131363d20222626}
		 $hex78= {24613137303d20224d}
		 $hex79= {24613137313d20226d}
		 $hex80= {24613137323d20224d}
		 $hex81= {24613137333d20223a}
		 $hex82= {24613137343d202252}
		 $hex83= {24613137353d202253}
		 $hex84= {24613137363d202225}
		 $hex85= {24613137373d202225}
		 $hex86= {24613137383d202253}
		 $hex87= {24613137393d202253}
		 $hex88= {246131373d20223331}
		 $hex89= {24613138303d202253}
		 $hex90= {24613138313d20223a}
		 $hex91= {24613138323d202275}
		 $hex92= {24613138333d202276}
		 $hex93= {24613138343d202276}
		 $hex94= {24613138353d202277}
		 $hex95= {24613138363d202278}
		 $hex96= {24613138373d202278}
		 $hex97= {24613138383d202278}
		 $hex98= {246131383d20223524}
		 $hex99= {246131393d20223532}
		 $hex100= {2461313d2022404040}
		 $hex101= {246132303d20223521}
		 $hex102= {246132313d20223536}
		 $hex103= {246132323d20223737}
		 $hex104= {246132333d20223723}
		 $hex105= {246132343d20222525}
		 $hex106= {246132353d20222526}
		 $hex107= {246132363d20223840}
		 $hex108= {246132373d20223832}
		 $hex109= {246132383d20223932}
		 $hex110= {246132393d20223932}
		 $hex111= {2461323d20227b7b7b}
		 $hex112= {246133303d20223933}
		 $hex113= {246133313d20224142}
		 $hex114= {246133323d20222e3f}
		 $hex115= {246133333d20222e3f}
		 $hex116= {246133343d20222e3f}
		 $hex117= {246133353d20222e3f}
		 $hex118= {246133363d20222e3f}
		 $hex119= {246133373d20222e3f}
		 $hex120= {246133383d20222e3f}
		 $hex121= {246133393d20222e3f}
		 $hex122= {2461333d2022304031}
		 $hex123= {246134303d20222e3f}
		 $hex124= {246134313d20222e3f}
		 $hex125= {246134323d20222e3f}
		 $hex126= {246134333d20222e3f}
		 $hex127= {246134343d20222e3f}
		 $hex128= {246134353d20222e3f}
		 $hex129= {246134363d20222e3f}
		 $hex130= {246134373d20222e3f}
		 $hex131= {246134383d20222e3f}
		 $hex132= {246134393d20222e3f}
		 $hex133= {2461343d2022253032}
		 $hex134= {246135303d20222e3f}
		 $hex135= {246135313d20222e3f}
		 $hex136= {246135323d20222e3f}
		 $hex137= {246135333d20222e3f}
		 $hex138= {246135343d20222e3f}
		 $hex139= {246135353d20222e3f}
		 $hex140= {246135363d20222e3f}
		 $hex141= {246135373d20222e3f}
		 $hex142= {246135383d20222e3f}
		 $hex143= {246135393d20222e3f}
		 $hex144= {2461353d2022303540}
		 $hex145= {246136303d20222e3f}
		 $hex146= {246136313d20226262}
		 $hex147= {246136323d20226362}
		 $hex148= {246136333d2022403a}
		 $hex149= {246136343d2022403a}
		 $hex150= {246136353d2022444c}
		 $hex151= {246136363d2022444c}
		 $hex152= {246136373d2022444c}
		 $hex153= {246136383d2022444c}
		 $hex154= {246136393d2022444c}
		 $hex155= {2461363d2022303940}
		 $hex156= {246137303d2022444c}
		 $hex157= {246137313d2022444c}
		 $hex158= {246137323d2022444c}
		 $hex159= {246137333d2022444c}
		 $hex160= {246137343d2022444c}
		 $hex161= {246137353d2022444c}
		 $hex162= {246137363d2022444c}
		 $hex163= {246137373d2022444c}
		 $hex164= {246137383d2022444c}
		 $hex165= {246137393d2022444c}
		 $hex166= {2461373d2022313131}
		 $hex167= {246138303d2022444c}
		 $hex168= {246138313d2022444c}
		 $hex169= {246138323d2022444c}
		 $hex170= {246138333d2022444c}
		 $hex171= {246138343d2022444c}
		 $hex172= {246138353d2022444c}
		 $hex173= {246138363d2022444c}
		 $hex174= {246138373d2022444c}
		 $hex175= {246138383d2022444c}
		 $hex176= {246138393d2022444c}
		 $hex177= {2461383d2022314031}
		 $hex178= {246139303d2022444c}
		 $hex179= {246139313d2022444c}
		 $hex180= {246139323d2022643a}
		 $hex181= {246139333d20224578}
		 $hex182= {246139343d20224741}
		 $hex183= {246139353d20224764}
		 $hex184= {246139363d20224764}
		 $hex185= {246139373d20224764}
		 $hex186= {246139383d20224765}
		 $hex187= {246139393d20224765}
		 $hex188= {2461393d2022314031}
		 $hex189= {247331303d2022436f}
		 $hex190= {247331313d20224465}
		 $hex191= {247331323d2022454c}
		 $hex192= {247331333d20226572}
		 $hex193= {247331343d20224669}
		 $hex194= {247331353d20224854}
		 $hex195= {247331363d2022496e}
		 $hex196= {247331373d2022496e}
		 $hex197= {247331383d2022496e}
		 $hex198= {247331393d20224c65}
		 $hex199= {2473313d2022313939}
		 $hex200= {247332303d20224d69}
		 $hex201= {247332313d20224d69}
		 $hex202= {247332323d20224f70}
		 $hex203= {247332333d20224f72}
		 $hex204= {247332343d20225072}
		 $hex205= {247332353d20225345}
		 $hex206= {247332363d2022746f}
		 $hex207= {247332373d2022746f}
		 $hex208= {247332383d2022564d}
		 $hex209= {247332393d20225653}
		 $hex210= {2473323d2022362e30}
		 $hex211= {247333303d20225769}
		 $hex212= {247333313d20225769}
		 $hex213= {247333323d20225769}
		 $hex214= {247333333d20225769}
		 $hex215= {247333343d20225769}
		 $hex216= {2473333d2022362e31}
		 $hex217= {2473343d2022382e30}
		 $hex218= {2473353d2022392e32}
		 $hex219= {2473363d2022416c6c}
		 $hex220= {2473373d2022436f70}
		 $hex221= {2473383d2022436f70}
		 $hex222= {2473393d2022436f70}

	condition:
		27 of them
}
