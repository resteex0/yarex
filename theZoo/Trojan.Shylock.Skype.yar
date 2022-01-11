
/*
   YARA Rule Set
   Author: resteex
   Identifier: Trojan_Shylock_Skype 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Trojan_Shylock_Skype {
	meta: 
		 description= "Trojan_Shylock_Skype Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-30-50" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "8fbeb78b06985c3188562e2f1b82d57d"

	strings:

	
 		 $s1= "!$).056;>ACENQV_`eimuz" fullword wide
		 $s2= "blockInMessages" fullword wide
		 $s3= "blockOutMessages" fullword wide
		 $s4= "library routine called out of sequence" fullword wide
		 $s5= "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.0.3705)" fullword wide
		 $s6= "PARTNER_DISPNAME" fullword wide
		 $s7= "session=%s&user=%s&fids=" fullword wide
		 $s8= "Skype%smain.db" fullword wide
		 $s9= "TAccessibleCheckListBox" fullword wide
		 $s10= "TConversationForm" fullword wide
		 $s11= "TNavigableButton" fullword wide
		 $s12= "/tool/skype.php?action=%s" fullword wide
		 $s13= "user=%s|%s|%s&fnames=" fullword wide
		 $a1= "0123456789ABCDEF0123456789abcdef" fullword ascii
		 $a2= "6@6D6H6L6P6T6X66`6d6h6l6p6t6x6|6" fullword ascii
		 $a3= "@7D7H7L7P7T7X7H8L8P8T8X88`8d8h8l8p8t8" fullword ascii
		 $a4= ">]^_`aabc``defghijkkkkkkkklmlm^nopqrsttuv" fullword ascii
		 $a5= "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" fullword ascii
		 $a6= "ATEBEGINNERELEASEBETWEENOTNULLIKECASCADELETECASECOLLATECREATECURRENT_DATEDETACHIMMEDIATEJOINSERTMATC" fullword ascii
		 $a7= "/hijackcfg/plugins/plugin" fullword ascii
		 $a8= "/hijackcfg/urls_server/url_server" fullword ascii
		 $a9= "HPLANALYZEPRAGMABORTVALUESVIRTUALIMITWHENWHERENAMEAFTEREPLACEANDEFAULTAUTOINCREMENTCASTCOLUMNCOMMITC" fullword ascii
		 $a10= "InitializeCriticalSection" fullword ascii
		 $a11= "naturaleftouterightfullinnercross" fullword ascii
		 $a12= "ONFLICTCROSSCURRENT_TIMESTAMPRIMARYDEFERREDISTINCTDROPFAILFROMFULLGLOBYIFISNULLORDERESTRICTOUTERIGHT" fullword ascii
		 $a13= "RALTERAISEXCLUSIVEXISTSAVEPOINTERSECTRIGGEREFERENCESCONSTRAINTOFFSETEMPORARYUNIQUERYATTACHAVINGROUPD" fullword ascii
		 $a14= "REINDEXEDESCAPEACHECKEYBEFOREIGNOREGEXPLAINSTEADDATABASELECTABLEFTHENDEFERRABLELSEXCEPTRANSACTIONATU" fullword ascii
		 $a15= "reverse_unordered_selects" fullword ascii
		 $a16= "ROLLBACKROWUNIONUSINGVACUUMVIEWINITIALLY" fullword ascii

		 $hex1= {246131303d2022496e}
		 $hex2= {246131313d20226e61}
		 $hex3= {246131323d20224f4e}
		 $hex4= {246131333d20225241}
		 $hex5= {246131343d20225245}
		 $hex6= {246131353d20227265}
		 $hex7= {246131363d2022524f}
		 $hex8= {2461313d2022303132}
		 $hex9= {2461323d2022364036}
		 $hex10= {2461333d2022403744}
		 $hex11= {2461343d20223e5d5e}
		 $hex12= {2461353d2022616263}
		 $hex13= {2461363d2022415445}
		 $hex14= {2461373d20222f6869}
		 $hex15= {2461383d20222f6869}
		 $hex16= {2461393d202248504c}
		 $hex17= {247331303d20225443}
		 $hex18= {247331313d2022544e}
		 $hex19= {247331323d20222f74}
		 $hex20= {247331333d20227573}
		 $hex21= {2473313d2022212429}
		 $hex22= {2473323d2022626c6f}
		 $hex23= {2473333d2022626c6f}
		 $hex24= {2473343d20226c6962}
		 $hex25= {2473353d20224d6f7a}
		 $hex26= {2473363d2022504152}
		 $hex27= {2473373d2022736573}
		 $hex28= {2473383d2022536b79}
		 $hex29= {2473393d2022544163}

	condition:
		3 of them
}
