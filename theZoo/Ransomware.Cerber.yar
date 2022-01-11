
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Cerber 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Cerber {
	meta: 
		 description= "Ransomware_Cerber Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-27-25" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8b6bc16fd137c09a08b02bbe1bb7d670"

	strings:

	
 		 $s1= "$i$i$Y$Y$i$i$Y$Y$)$)$" fullword wide
		 $s2= "11111kicu4p3050f55f298b5211cf2bb82200aa00bdce0bf" fullword wide
		 $s3= "E8E(E,EPE@EHELE" fullword wide
		 $s4= "ElaborateBytes AG" fullword wide
		 $s5= "VS_VERSION_INFO" fullword wide
		 $a1= "''''''''''''''''''''''''''''''''''''''''" fullword ascii
		 $a2= "''''''''''''''''''''''''''''''''''''''''''''''" fullword ascii
		 $a3= "===@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=@@@==" fullword ascii
		 $a4= "=>=======================================================================>" fullword ascii
		 $a5= "||||{{{{{{{{{{{{{{{{{{{{{{{{{{{{{|" fullword ascii
		 $a6= "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" fullword ascii
		 $a7= "$$SSIQRRZRRZSZS[R[R[R[R[R[R[R[R[R[R[R[R[R[R[R[R[R[R[R[RRZSZZSRQQQQ]]]Z[[[[[[[[^[[[[[[[[[[[[[[[[[[[[[" fullword ascii
		 $a8= "$+JJSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSJS+$" fullword ascii
		 $a9= "2222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222" fullword ascii
		 $a10= "33333333333333333333333333" fullword ascii
		 $a11= "333333333333333333333333333" fullword ascii
		 $a12= "660022222+222+222+222+22222.000" fullword ascii
		 $a13= "6666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666" fullword ascii
		 $a14= "7777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777" fullword ascii
		 $a15= "777777777777777777777778A??" fullword ascii
		 $a16= "77777777777777777777777AAw" fullword ascii
		 $a17= "8888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888" fullword ascii
		 $a18= "bbQNMMMLLLLLLLLLLLLLLLLLLLLNQQQ" fullword ascii
		 $a19= "bb_UPNUUNUUNUUNUUNUUNUUPUUTTT" fullword ascii
		 $a20= "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" fullword ascii
		 $a21= "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" fullword ascii
		 $a22= "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" fullword ascii
		 $a23= "CCCCCCCCGCGCCGCCGCCGCCGCCGCCGCCGCCGCCGCCGCCGCCGCCGCCGCCGCCGCCGCCGCCGCCGCCCCCCCCCCC" fullword ascii
		 $a24= "==@?@D@D@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@C@@=?===C__v" fullword ascii
		 $a25= "DDFDFDFHHHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDFHHHHFFDDHII|_v" fullword ascii
		 $a26= "ECCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" fullword ascii
		 $a27= "&&&&(-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE-&(&&&WWWVVV\\\\\\\\\\VVWWWVVVi" fullword ascii
		 $a28= "ExpandEnvironmentStringsW" fullword ascii
		 $a29= "ff_exyyyxxxxxxxyyyyyyyyyxe_ff" fullword ascii
		 $a30= "FillConsoleOutputAttribute" fullword ascii
		 $a31= "FillConsoleOutputCharacterW" fullword ascii
		 $a32= "GetConsoleScreenBufferInfo" fullword ascii
		 $a33= "GetMenuCheckMarkDimensions" fullword ascii
		 $a34= "GetSecurityDescriptorOwner" fullword ascii
		 $a35= "GetUserObjectInformationW" fullword ascii
		 $a36= "~hiLVVVVVVVVVVVVVVVLVVVVVVVLVVVVVVVLVVVVVVVLVVVVVVVLVVVVVVVLVVVVVVVLVVVVVVVLVVVVVVVVVVVLLih~" fullword ascii
		 $a37= "hMLFFVVFVHVDFVFFFVFFFVFFFVFFFVFFFVFFFVFFFVFFFVFFFVFFFVFFFVFFFVFFFVFFFVFFFVFFFVFFFVHVDFFFLLLh" fullword ascii
		 $a38= "ieeWWWURRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR" fullword ascii
		 $a39= "ifUUUTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT" fullword ascii
		 $a40= "iiiiimimimimimimimimimimimimimimimimiiiiiiiioooooggggggggggggggggggggggggggggggggggggggooooo" fullword ascii
		 $a41= "InitializeCriticalSection" fullword ascii
		 $a42= "jhgXLUVVUVVUVUVUVUVUVUVUVUVUVUVUVUVUVUVUVUVUVUVUVUVUVUVUVUVUVUVUVUVUVUVUVUVUVUVUVVUVLUXihj" fullword ascii
		 $a43= "jiiXUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUXiij" fullword ascii
		 $a44= "jjjjijijijijijijijijijijiii" fullword ascii
		 $a45= "jjjjjjjjjiiiiiiiiiiiiiiiiii" fullword ascii
		 $a46= "|llololoolololllllollllollllollllollllollllollllllll|llll" fullword ascii
		 $a47= "{neeeWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW" fullword ascii
		 $a48= "nheUUUUTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT" fullword ascii
		 $a49= "~nnk^k^mmk^kmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm" fullword ascii
		 $a50= "}oggigiUUgUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUgUUUgXiggj}" fullword ascii
		 $a51= "oookokokokkomokkomokkomokkomokkomokkomokkomokkomkomooooooooo" fullword ascii
		 $a52= "{pnnnnllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll" fullword ascii
		 $a53= "~ppkkkkYYYkYkkkkYYYYkkkkkkYYYYkkkkkkkkkkkkkYYkkkkkkkkkkYkYYYYYYYYkkkkkYYYkkYYYYYYYYYYmmmr" fullword ascii
		 $a54= "ppkkklYYkYkYYYYkkkkkkkkkYYkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkklkkkkkkkkkYYkYYYYYYYYYkkkkklr" fullword ascii
		 $a55= "ppklklkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkklkllllr" fullword ascii
		 $a56= "prllllllklkklkllkllkkkkllllklklklklklklllllllklkllkllkllkllkllkkkklllllllllkllllrr" fullword ascii
		 $a57= "qnleeeWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW" fullword ascii
		 $a58= "qnnllllddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" fullword ascii
		 $a59= "}qogogggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggogigooo}" fullword ascii
		 $a60= "qolooloolooloolooloolooloolooloolooloolooloolooloolooloolooloolooloolooloololloolo" fullword ascii
		 $a61= "}qpplpolppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppplplppq" fullword ascii
		 $a62= "qqrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr" fullword ascii
		 $a63= "qrnddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" fullword ascii
		 $a64= "qrrrlrlllrlrllllllllrllllllllllllllllllllllllllllllllllllllllllrllllllllllrlrl" fullword ascii
		 $a65= "qrrrnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn" fullword ascii
		 $a66= "qrrrrrnkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk" fullword ascii
		 $a67= "qrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr" fullword ascii
		 $a68= "rrnddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" fullword ascii
		 $a69= "rrrkdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" fullword ascii
		 $a70= "rrrrkkdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" fullword ascii
		 $a71= "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr" fullword ascii
		 $a72= "}}rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr}}" fullword ascii
		 $a73= "SaferComputeTokenFromLevel" fullword ascii
		 $a74= "ScrollConsoleScreenBufferW" fullword ascii
		 $a75= "SetUnhandledExceptionFilter" fullword ascii
		 $a76= "SetUserObjectInformationW" fullword ascii
		 $a77= "thLLLVFVFVFVFVFLVFVVFVFLVFVVFVFLVFVVFVFLVFVVFVFLVFVVFVFLVFVVFVFLVFVVFVFLVFVVFVFLVFVFVVVVVLhw" fullword ascii
		 $a78= "tVVDCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" fullword ascii
		 $a79= "uA87777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777" fullword ascii
		 $a80= "vI@@DDDDDDDDDDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHDHIDHDDDDDD@DIv_v|IHH" fullword ascii
		 $a81= "wAA7777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777" fullword ascii
		 $a82= "WritePrivateProfileSectionA" fullword ascii
		 $a83= "XXJCAA@@@@@@@@@@@@@@@@@@@@CCJJJ" fullword ascii
		 $a84= "zfVUTTCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" fullword ascii
		 $a85= "}zyy}zh}o}yyy}o}yyy}o}yyy}o}yyy}o}yy}zhhhhh" fullword ascii
		 $a86= "[[[[[[[[[[[[[[[[[[[[[^ZZZZZZZZ]~a`^^mmmmm^^mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm[m^^^^^^^" fullword ascii

		 $hex1= {246131303d20223333}
		 $hex2= {246131313d20223333}
		 $hex3= {246131323d20223636}
		 $hex4= {246131333d20223636}
		 $hex5= {246131343d20223737}
		 $hex6= {246131353d20223737}
		 $hex7= {246131363d20223737}
		 $hex8= {246131373d20223838}
		 $hex9= {246131383d20226262}
		 $hex10= {246131393d20226262}
		 $hex11= {2461313d2022272727}
		 $hex12= {246132303d20224343}
		 $hex13= {246132313d20224343}
		 $hex14= {246132323d20224343}
		 $hex15= {246132333d20224343}
		 $hex16= {246132343d20223d3d}
		 $hex17= {246132353d20224444}
		 $hex18= {246132363d20224543}
		 $hex19= {246132373d20222626}
		 $hex20= {246132383d20224578}
		 $hex21= {246132393d20226666}
		 $hex22= {2461323d2022272727}
		 $hex23= {246133303d20224669}
		 $hex24= {246133313d20224669}
		 $hex25= {246133323d20224765}
		 $hex26= {246133333d20224765}
		 $hex27= {246133343d20224765}
		 $hex28= {246133353d20224765}
		 $hex29= {246133363d20227e68}
		 $hex30= {246133373d2022684d}
		 $hex31= {246133383d20226965}
		 $hex32= {246133393d20226966}
		 $hex33= {2461333d20223d3d3d}
		 $hex34= {246134303d20226969}
		 $hex35= {246134313d2022496e}
		 $hex36= {246134323d20226a68}
		 $hex37= {246134333d20226a69}
		 $hex38= {246134343d20226a6a}
		 $hex39= {246134353d20226a6a}
		 $hex40= {246134363d20227c6c}
		 $hex41= {246134373d20227b6e}
		 $hex42= {246134383d20226e68}
		 $hex43= {246134393d20227e6e}
		 $hex44= {2461343d20223d3e3d}
		 $hex45= {246135303d20227d6f}
		 $hex46= {246135313d20226f6f}
		 $hex47= {246135323d20227b70}
		 $hex48= {246135333d20227e70}
		 $hex49= {246135343d20227070}
		 $hex50= {246135353d20227070}
		 $hex51= {246135363d20227072}
		 $hex52= {246135373d2022716e}
		 $hex53= {246135383d2022716e}
		 $hex54= {246135393d20227d71}
		 $hex55= {2461353d20227c7c7c}
		 $hex56= {246136303d2022716f}
		 $hex57= {246136313d20227d71}
		 $hex58= {246136323d20227171}
		 $hex59= {246136333d20227172}
		 $hex60= {246136343d20227172}
		 $hex61= {246136353d20227172}
		 $hex62= {246136363d20227172}
		 $hex63= {246136373d20227172}
		 $hex64= {246136383d20227272}
		 $hex65= {246136393d20227272}
		 $hex66= {2461363d2022242424}
		 $hex67= {246137303d20227272}
		 $hex68= {246137313d20227272}
		 $hex69= {246137323d20227d7d}
		 $hex70= {246137333d20225361}
		 $hex71= {246137343d20225363}
		 $hex72= {246137353d20225365}
		 $hex73= {246137363d20225365}
		 $hex74= {246137373d20227468}
		 $hex75= {246137383d20227456}
		 $hex76= {246137393d20227541}
		 $hex77= {2461373d2022242453}
		 $hex78= {246138303d20227649}
		 $hex79= {246138313d20227741}
		 $hex80= {246138323d20225772}
		 $hex81= {246138333d20225858}
		 $hex82= {246138343d20227a66}
		 $hex83= {246138353d20227d7a}
		 $hex84= {246138363d20225b5b}
		 $hex85= {2461383d2022242b4a}
		 $hex86= {2461393d2022323232}
		 $hex87= {2473313d2022246924}
		 $hex88= {2473323d2022313131}
		 $hex89= {2473333d2022453845}
		 $hex90= {2473343d2022456c61}
		 $hex91= {2473353d202256535f}

	condition:
		11 of them
}
