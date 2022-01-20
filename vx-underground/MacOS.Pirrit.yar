
/*
   YARA Rule Set
   Author: resteex
   Identifier: MacOS_Pirrit 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_MacOS_Pirrit {
	meta: 
		 description= "MacOS_Pirrit Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_11-18-36" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "bd5f8ce198b71c6748603c8479652a7c"
		 hash2= "d478bed781fdb3b68293f8c042ae8ec8"

	strings:

	
 		 $a1= "@executable_path/../Frameworks/QtGui.framework/Versions/4/QtGui" fullword ascii
		 $a2= "/Library/Frameworks/QtCore.framework/Headers/qatomic_x86_64.h" fullword ascii
		 $a3= "/Library/Frameworks/QtCore.framework/Headers/qscopedpointer.h" fullword ascii
		 $a4= "/Library/Frameworks/QtCore.framework/Versions/4/Headers/qdir.h" fullword ascii
		 $a5= "/Library/Frameworks/QtCore.framework/Versions/4/Headers/qlist.h" fullword ascii
		 $a6= "/Library/Frameworks/QtNetwork.framework/Headers/qtcpsocket.h" fullword ascii
		 $a7= "/Users/redsky/projects/pirrit/macos/ProxyServer/AdsProxy/GZip.o" fullword ascii
		 $a8= "__Z20qt_qFindChild_helperPK7QObjectRK7QStringRK11QMetaObject" fullword ascii
		 $a9= "__ZN13QtServiceBase15setServiceFlagsE6QFlagsINS_11ServiceFlagEE" fullword ascii
		 $a10= "__ZN16QtServiceStarter11qt_metacallEN11QMetaObject4CallEiPPv" fullword ascii
		 $a11= "__ZN18QtUnixServerSocket11qt_metacallEN11QMetaObject4CallEiPPv" fullword ascii
		 $a12= "__ZN19QtServiceSysPrivate11qt_metacallEN11QMetaObject4CallEiPPv" fullword ascii
		 $a13= "__ZN3Upd18qt_static_metacallEP7QObjectN11QMetaObject4CallEiPPv" fullword ascii
		 $a14= "__ZN4QMapIP10QTcpSocketN8WebProxy18ChunkedRequestDataEEixERKS1_" fullword ascii
		 $a15= "__ZN5QListI5QPairI12QHostAddressiEE9node_copyEPNS3_4NodeES5_S5_" fullword ascii
		 $a16= "__ZN8WebProxy32finishedDownloadInjectionContentEP13QNetworkReply" fullword ascii
		 $a17= "__ZNK13QNetworkReply9attributeEN15QNetworkRequest9AttributeE" fullword ascii
		 $a18= "__ZNK5QListI5QPairI12QHostAddressiEE14const_iteratorneERKS4_" fullword ascii
		 $a19= "__ZNSt9basic_iosIcSt11char_traitsIcEE5clearESt12_Ios_Iostate" fullword ascii

		 $hex1= {246131303d20225f5f}
		 $hex2= {246131313d20225f5f}
		 $hex3= {246131323d20225f5f}
		 $hex4= {246131333d20225f5f}
		 $hex5= {246131343d20225f5f}
		 $hex6= {246131353d20225f5f}
		 $hex7= {246131363d20225f5f}
		 $hex8= {246131373d20225f5f}
		 $hex9= {246131383d20225f5f}
		 $hex10= {246131393d20225f5f}
		 $hex11= {2461313d2022406578}
		 $hex12= {2461323d20222f4c69}
		 $hex13= {2461333d20222f4c69}
		 $hex14= {2461343d20222f4c69}
		 $hex15= {2461353d20222f4c69}
		 $hex16= {2461363d20222f4c69}
		 $hex17= {2461373d20222f5573}
		 $hex18= {2461383d20225f5f5a}
		 $hex19= {2461393d20225f5f5a}

	condition:
		9 of them
}
