
/*
   YARA Rule Set
   Author: resteex
   Identifier: Android_PegasusB 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Android_PegasusB {
	meta: 
		 description= "Android_PegasusB Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-24-42" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8d4b77fa3546149f25bd17357d41fbf0"

	strings:

	
 		 $s1= "seC.dujmehn.qdtheyt" fullword wide
		 $a1= "bY^GY^GY^GY^GY^GY^GY^GY^GY^GY^GY^GY^GY^GY^GY^G9/" fullword ascii
		 $a2= "org/eclipse/paho/client/mqttv3/internal/nls/messages_cs.propertiesmTMO" fullword ascii
		 $a3= "org/eclipse/paho/client/mqttv3/internal/nls/messages_cs.propertiesPK" fullword ascii
		 $a4= "org/eclipse/paho/client/mqttv3/internal/nls/messages_de.propertiesmT]o" fullword ascii
		 $a5= "org/eclipse/paho/client/mqttv3/internal/nls/messages_de.propertiesPK" fullword ascii
		 $a6= "org/eclipse/paho/client/mqttv3/internal/nls/messages_es.propertiesPK" fullword ascii
		 $a7= "org/eclipse/paho/client/mqttv3/internal/nls/messages_es.properties]S" fullword ascii
		 $a8= "org/eclipse/paho/client/mqttv3/internal/nls/messages_fr.propertiesPK" fullword ascii
		 $a9= "org/eclipse/paho/client/mqttv3/internal/nls/messages_fr.propertiesuSMO" fullword ascii
		 $a10= "org/eclipse/paho/client/mqttv3/internal/nls/messages_hu.propertiesPK" fullword ascii
		 $a11= "org/eclipse/paho/client/mqttv3/internal/nls/messages_hu.properties}TMo" fullword ascii
		 $a12= "org/eclipse/paho/client/mqttv3/internal/nls/messages_it.propertieseS" fullword ascii
		 $a13= "org/eclipse/paho/client/mqttv3/internal/nls/messages_it.propertiesPK" fullword ascii
		 $a14= "org/eclipse/paho/client/mqttv3/internal/nls/messages_ja.properties" fullword ascii
		 $a15= "org/eclipse/paho/client/mqttv3/internal/nls/messages_ja.propertiesPK" fullword ascii
		 $a16= "org/eclipse/paho/client/mqttv3/internal/nls/messages_ko.properties" fullword ascii
		 $a17= "org/eclipse/paho/client/mqttv3/internal/nls/messages_ko.propertiesPK" fullword ascii
		 $a18= "org/eclipse/paho/client/mqttv3/internal/nls/messages_pl.properties" fullword ascii
		 $a19= "org/eclipse/paho/client/mqttv3/internal/nls/messages_pl.propertiesPK" fullword ascii
		 $a20= "org/eclipse/paho/client/mqttv3/internal/nls/messages.propertiesPK" fullword ascii
		 $a21= "org/eclipse/paho/client/mqttv3/internal/nls/messages.properties]R" fullword ascii
		 $a22= "org/eclipse/paho/client/mqttv3/internal/nls/messages_pt_BR.propertiesmS" fullword ascii
		 $a23= "org/eclipse/paho/client/mqttv3/internal/nls/messages_pt_BR.propertiesPK" fullword ascii
		 $a24= "org/eclipse/paho/client/mqttv3/internal/nls/messages_ru.properties" fullword ascii
		 $a25= "org/eclipse/paho/client/mqttv3/internal/nls/messages_ru.propertiesPK" fullword ascii
		 $a26= "org/eclipse/paho/client/mqttv3/internal/nls/messages_zh_CN.properties" fullword ascii
		 $a27= "org/eclipse/paho/client/mqttv3/internal/nls/messages_zh_CN.propertiesPK" fullword ascii
		 $a28= "org/eclipse/paho/client/mqttv3/internal/nls/messages_zh_TW.properties" fullword ascii
		 $a29= "org/eclipse/paho/client/mqttv3/internal/nls/messages_zh_TW.propertiesPK" fullword ascii
		 $a30= "res/layout/blackscreen.xml" fullword ascii
		 $a31= "res/layout/blackscreen.xmlm" fullword ascii
		 $a32= "res/layout/blackscreen.xmlPK" fullword ascii
		 $a33= "res/raw/take_screen_shotPK" fullword ascii
		 $a34= "&.'#w2r&#g2r&#g2r&#g2r&#g" fullword ascii

		 $hex1= {246131303d20226f72}
		 $hex2= {246131313d20226f72}
		 $hex3= {246131323d20226f72}
		 $hex4= {246131333d20226f72}
		 $hex5= {246131343d20226f72}
		 $hex6= {246131353d20226f72}
		 $hex7= {246131363d20226f72}
		 $hex8= {246131373d20226f72}
		 $hex9= {246131383d20226f72}
		 $hex10= {246131393d20226f72}
		 $hex11= {2461313d202262595e}
		 $hex12= {246132303d20226f72}
		 $hex13= {246132313d20226f72}
		 $hex14= {246132323d20226f72}
		 $hex15= {246132333d20226f72}
		 $hex16= {246132343d20226f72}
		 $hex17= {246132353d20226f72}
		 $hex18= {246132363d20226f72}
		 $hex19= {246132373d20226f72}
		 $hex20= {246132383d20226f72}
		 $hex21= {246132393d20226f72}
		 $hex22= {2461323d20226f7267}
		 $hex23= {246133303d20227265}
		 $hex24= {246133313d20227265}
		 $hex25= {246133323d20227265}
		 $hex26= {246133333d20227265}
		 $hex27= {246133343d2022262e}
		 $hex28= {2461333d20226f7267}
		 $hex29= {2461343d20226f7267}
		 $hex30= {2461353d20226f7267}
		 $hex31= {2461363d20226f7267}
		 $hex32= {2461373d20226f7267}
		 $hex33= {2461383d20226f7267}
		 $hex34= {2461393d20226f7267}
		 $hex35= {2473313d2022736543}

	condition:
		4 of them
}
