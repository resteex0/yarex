
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Vermin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Vermin {
	meta: 
		 description= "vx_underground2_Vermin Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-17-47" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "07633a79d28bb8b4ef8a6283b881be0e"
		 hash2= "0b85887358fb335ad0dd7ccbc2d64bb4"
		 hash3= "242f0ab53ac5d194af091296517ec10a"
		 hash4= "2b044a21687003c78ff8628c3a69b0a0"
		 hash5= "3293594b0eb0fada3c0c6f031a361050"
		 hash6= "3ddc543facdc43dc5b1bdfa110fcffa3"
		 hash7= "4373f3cf99a279ac0c3d442f2844a89f"
		 hash8= "46f09e5230dfced7939131d704bdb592"
		 hash9= "47161360b84388d1c254eb68ad3d6dfa"
		 hash10= "47cfac75d2158bf513bcd1ed5e3dd58c"
		 hash11= "50b1f0391995a0ce5c2d937e880b93ee"
		 hash12= "5b5060ebb405140f87a1bb65e06c9e29"
		 hash13= "5feae6cb9915c6378c4bb68740557d0a"
		 hash14= "632d08020499a6b5ee4852ecadc79f2e"
		 hash15= "71afb620857627400a648f91e6865991"
		 hash16= "752292c4d4ad51feb489ee1e06498c7f"
		 hash17= "7e859fe3d7ae323c8103567a399e87dc"
		 hash18= "80b3d1c12fb6aaedc59ce4323b0850fe"
		 hash19= "83d6588446dc3ab7ba38315ecc29fbb5"
		 hash20= "860b8735995df9e2de2126d3b8978dbf"
		 hash21= "8d8a84790c774adf4c677d2238999eb5"
		 hash22= "9f88187d774cc9eaf89dc65479c4302d"
		 hash23= "c189875f8b2bebc9f5a2e2af2f34e647"
		 hash24= "c1b8a7f861a7555a14e1a68067469a20"
		 hash25= "d2c6e6b0fbe37685ddb865cf6b523d8c"
		 hash26= "d6c9f0bd1c0c106b2caaddcdff2b5785"
		 hash27= "dc0ab74129a4be18d823b71a54b0cab0"
		 hash28= "dca799ab332b1d6b599d909e17d2574c"
		 hash29= "fdc16eb59377efecd5411fedd87fb9d2"

	strings:

	
 		 $s1= ":=:>:?:" fullword wide
		 $s2= "'&(&)&-,0/1/2/3/657598:8>=BACADAFERQutvtwtxtyt{z|z" fullword wide
		 $s3= "08E1A3FB-01DF-4CB8-9346-0AB7B5581462" fullword wide
		 $s4= "{0}FileZillarecentservers.xml" fullword wide
		 $s5= "{0}FileZillasitemanager.xml" fullword wide
		 $s6= "[{0:HH:mm:ss}][{1}][{2} ]]" fullword wide
		 $s7= "(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})" fullword wide
		 $s8= "%#(/-2/5173:5;7P?QASCTDUFZH[KM_NdReSnXzY{|^}`" fullword wide
		 $s9= "3zhw8YDz9BwX6bFCr/E1IXuvpLSY8yGGPfZWrm2Cxoo=" fullword wide
		 $s10= "%4d-%02d-%02d-%02d-%02d-%02d-%03d" fullword wide
		 $s11= "4tmpuN4lWTpU0QlWyX1/VoXI6lOgtNE6Wej7c3iiGrc=" fullword wide
		 $s12= "7>=CBEDHGIG" fullword wide
		 $s13= "7z1e5YsReuJQOTLZBdq/PpUvAcGyg2hkyvWU9vYUMno=" fullword wide
		 $s14= "9=9?>A@B@DCFEIHMLWVXVYVZV[V" fullword wide
		 $s15= ";=;>;?;@;A;CBDBEBFBGBHBIBJBONPN^]bafehg|{}{" fullword wide
		 $s16= "AdobePrintLib.Properties.Resources" fullword wide
		 $s17= "/AllowHardTerminate>" fullword wide
		 $s18= "/AllowStartOnDemand>" fullword wide
		 $s19= "B8B4B0B,B(B$B B" fullword wide
		 $s20= "BADCECGFIHLKPOWV^]_]`]a]b]" fullword wide
		 $s21= "CheckRemoteDebuggerPresent" fullword wide
		 $s22= "chO7F7xnVCKizuHGCEYlYoueoS55bRCokCPymrSe9zQ=" fullword wide
		 $s23= "CryptProtectMemory failed" fullword wide
		 $s24= "CryptUnprotectMemory failed" fullword wide
		 $s25= "d9eYsSZ+Wtli4Kuv6iGRrXUQ827dkjRcToWvKMiKr5PZDT7/W1Qe5Vl5eZn3ZcdR" fullword wide
		 $s26= "/DisallowStartIfOnBatteries>" fullword wide
		 $s27= "dsGnklxnhy9R5I8B2Ag+6gtyNidaCoZ2YDAKZ+QGdws=" fullword wide
		 $s28= "E9W9e1+LNgQzZnujpwjyqWeq9xFhf7fQbDD7EjpkHZk=" fullword wide
		 $s29= ":=:>:?:@:EDFDSRWV|{}{~{" fullword wide
		 $s30= "/ExecutionTimeLimit>" fullword wide
		 $s31= "Fc12xcrmV4ilYW2QJnwA7AOiSdlpjOYYvt/kW2Me3BE/cppq" fullword wide
		 $s32= "fSbYyuJQNuGRDDfZPWfDWroJB4RMaImv" fullword wide
		 $s33= "gcIaxzUvPrMGVFsXvyjbwS+GGN5hHSY1b0MoIKy6nigfpasJ" fullword wide
		 $s34= "GdOpnMqDrfj2mbEXYaW4oSWEA6HmhbGGa1jmCzyIQvo=" fullword wide
		 $s35= "Ge/DRW0k6F7Fh/HPoX/Img+cpEfGVmNLEdk2GQ25T8k/cppq" fullword wide
		 $s36= "gfCgUufQPDyZVfunxvhPF2yYfCqV0ohD" fullword wide
		 $s37= "gFM7+SMQykANpUTKIYQTVKV0pRrsSVOekuLq9TggwmTsW4+gC64N7F06+NPsY246" fullword wide
		 $s38= "GoogleChromeUser DataDefaultCookies" fullword wide
		 $s39= "gz2QrIB2ZWmw1GQhn5VzTIxDtIKmWK+hYMvUKdUffYY=" fullword wide
		 $s40= "HL0Xbwx+zuQbhLWzgYxuXIwwA1XVYuHl0lN84iV8PTs=" fullword wide
		 $s41= "http://freegeoip.net/xml/" fullword wide
		 $s42= "https://freegeoip.net/xml/" fullword wide
		 $s43= "iGExGFrZOmjXtyRIz5usqHfpeyq0TStE3o2OARlUAvU=" fullword wide
		 $s44= "/Interval>" fullword wide
		 $s45= "IProducerConsumerCollection`1" fullword wide
		 $s46= "LicenseProtector.Properties.Resources" fullword wide
		 $s47= "/LogonType>" fullword wide
		 $s48= "lugansk_2273_21.04.2017.exe" fullword wide
		 $s49= "lvzieirDlDtVp+X8K0QUvmGI6bE2GQzv//7FBCu920c=" fullword wide
		 $s50= "lw+tLddEXhLnJe7QKL4XrE+cTXBikwzFHJM3hXli/Sb7K3SsyDFbzTPWEPQrUPlg" fullword wide
		 $s51= "LwTocLlPjsB1egLcF+NUFiiHABRscok7A8tIf2xAIlY=" fullword wide
		 $s52= "LxTFTiZvZnGcdUjGvKWHfKcAs8/SvVMtFAVc9utXc0LWFo6w/Tj/OQEmZolnOY4S" fullword wide
		 $s53= "lYXAANNZaTyvPZrhtnl7EJmJEjKbNP0uw3omUAbAPkY=" fullword wide
		 $s54= "MetadataTimeoutMilliseconds" fullword wide
		 $s55= "Microsoft.System.Application32.sfx.exe" fullword wide
		 $s56= "Microsoft.System.Application32.tmp.icq" fullword wide
		 $s57= "MOWALmJJz5YfckoGCPROnKddVGfNXxVkXI6j1joBhs/fGOFbbqluGUcmyioWNkK8" fullword wide
		 $s58= "MozillaFirefoxProfiles" fullword wide
		 $s59= "/MultipleInstancesPolicy>" fullword wide
		 $s60= "mydbapp2015-09-16_15-33 v1.0" fullword wide
		 $s61= "NHibernate.Intercept.IFieldInterceptorAccessor" fullword wide
		 $s62= "NHibernate.Proxy.DynamicProxy.IProxy" fullword wide
		 $s63= "NHibernate.Proxy.INHibernateProxy" fullword wide
		 $s64= "NlifZyTZZhepqkJvGROuz78MLLDNIScKsnxYiH2KXfs=" fullword wide
		 $s65= "Petrucco.Properties.Resources" fullword wide
		 $s66= "pjBAgiAD0EcaFVqjmUl1woD7DU/dkXJtqpis/tDOqk3sW2gI" fullword wide
		 $s67= "ProtoBuf.ProtoAfterDeserializationAttribute" fullword wide
		 $s68= "ProtoBuf.ProtoAfterSerializationAttribute" fullword wide
		 $s69= "ProtoBuf.ProtoBeforeDeserializationAttribute" fullword wide
		 $s70= "ProtoBuf.ProtoBeforeSerializationAttribute" fullword wide
		 $s71= "ProtoBuf.ProtoContractAttribute" fullword wide
		 $s72= "ProtoBuf.ProtoEnumAttribute" fullword wide
		 $s73= "ProtoBuf.ProtoIgnoreAttribute" fullword wide
		 $s74= "ProtoBuf.ProtoIncludeAttribute" fullword wide
		 $s75= "ProtoBuf.ProtoMemberAttribute" fullword wide
		 $s76= "ProtoBuf.ProtoPartialIgnoreAttribute" fullword wide
		 $s77= "ProtoBuf.ProtoPartialMemberAttribute" fullword wide
		 $s78= "/RestartOnIdle>" fullword wide
		 $s79= "/RunLevel>" fullword wide
		 $s80= "/RunOnlyIfIdle>" fullword wide
		 $s81= "/RunOnlyIfNetworkAvailable>" fullword wide
		 $s82= "+s6gNokzOEyrMlvfCRGmYtQx0zGnk48xRRet/khT6SuL69qa8/0Na2x4hHF/97C4" fullword wide
		 $s83= "SeCreateSymbolicLinkPrivilege" fullword wide
		 $s84= "SobakenRevenge.Properties.Resources" fullword wide
		 $s85= "SoftwareMicrosoftInternet ExplorerIntelliFormsStorage2" fullword wide
		 $s86= "SoftwareMicrosoftWindowsCurrentVersion" fullword wide
		 $s87= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s88= "SOFTWAREMicrosoftWindowsCurrentVersionRunOnce" fullword wide
		 $s89= "SOFTWAREMozillaMozilla Firefox" fullword wide
		 $s90= "SOFTWAREWow6432NodeMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s91= "SOFTWAREWow6432NodeMicrosoftWindowsCurrentVersionRunOnce" fullword wide
		 $s92= "SOFTWAREWow6432NodeMozillaMozilla Firefox" fullword wide
		 $s93= "/StartBoundary>" fullword wide
		 $s94= "/StartWhenAvailable>" fullword wide
		 $s95= "/StopAtDurationEnd>" fullword wide
		 $s96= "/StopIfGoingOnBatteries>" fullword wide
		 $s97= "/StopOnIdleEnd>" fullword wide
		 $s98= "System.Collections.Concurrent.IProducerConsumerCollection`1" fullword wide
		 $s99= "System.ComponentModel.DefaultValueAttribute" fullword wide
		 $s100= "System.Data.Entity.DynamicProxies." fullword wide
		 $s101= "System.Data.Linq.EntitySet`1[[" fullword wide
		 $s102= "System.NonSerializedAttribute" fullword wide
		 $s103= "System.Runtime.Serialization.DataContractAttribute" fullword wide
		 $s104= "System.Runtime.Serialization.DataMemberAttribute" fullword wide
		 $s105= "System.Runtime.Serialization.OnDeserializedAttribute" fullword wide
		 $s106= "System.Runtime.Serialization.OnDeserializingAttribute" fullword wide
		 $s107= "System.Runtime.Serialization.OnSerializedAttribute" fullword wide
		 $s108= "System.Runtime.Serialization.OnSerializingAttribute" fullword wide
		 $s109= "System.Xml.Serialization.XmlArrayAttribute" fullword wide
		 $s110= "System.Xml.Serialization.XmlElementAttribute" fullword wide
		 $s111= "System.Xml.Serialization.XmlIgnoreAttribute" fullword wide
		 $s112= "System.Xml.Serialization.XmlTypeAttribute" fullword wide
		 $s113= "sz2NcoPqcoetw6T5VYmKHXe3ff//UO3VMhY+gZ09OLU+R49d" fullword wide
		 $s114= "__tmp_rar_sfx_access_check_%u" fullword wide
		 $s115= "tqfXnywELxM/dF++3TKgjTNtGzuwQMAKbg1DEHKFoJc=" fullword wide
		 $s116= "UgrIbb@_xc08Hx8vQ+!{z^X'$" fullword wide
		 $s117= "ur/czATPTowrree218c088dxV48e24s7+6Av/i3LBqw=" fullword wide
		 $s118= "uxMFdLuekEeWLgmKYB4JVZhOADMG4ukFVo9IMxHY2R4=" fullword wide
		 $s119= "Vitevic.EmbeddedAssembly." fullword wide
		 $s120= "/WakeToRun>" fullword wide
		 $s121= "Winston.Properties.Resources" fullword wide
		 $s122= "wQk/K1dB93kzvsEeZXbYdEFu1+1yGnY/E4pITA8lOzI=" fullword wide
		 $s123= "xClient.Properties.Resources" fullword wide
		 $s124= "xLnr.Properties.Resources" fullword wide
		 $s125= "+y73MkHmkcxMIqRwP2Cl3TepckKzmwB4G+7knh0kDJ9hbreSt+cbocpTtdn86H76" fullword wide
		 $s126= "YandexYandexBrowserUser DataDefaultCookies" fullword wide
		 $s127= "yHP85/bH85shvjOU5udbaQGDPjqhFVPGM8+7x4wBTbs=" fullword wide
		 $s128= "youfibDiN7YhgB+SywOmOyQCAHrKjgD7uczAD64kDL8=" fullword wide
		 $s129= "ytQlGICTSxFAf7vHmrCBrlQODsbmLKt0RPyEPt43XkA=" fullword wide
		 $s130= "zTl7dNYkQnOIDs/9Vuymu9ngcbBogdQOqCeRvmzHyVw=" fullword wide
		 $a1= "System.Object>.Current" fullword ascii
		 $a2= "System.String>.Current" fullword ascii
		 $a3= "System.Type>.get_Current" fullword ascii
		 $a4= "TValue>.GetEnumerator" fullword ascii
		 $a5= "Z:ProjectsVerminCryptoLibobjReleaseLicenseProtector.pdb" fullword ascii
		 $a6= "Z:ProjectsVerminKeyboardHookLibobjReleaseAdobePrintLib.pdb" fullword ascii

		 $hex1= {2461313d2022537973}
		 $hex2= {2461323d2022537973}
		 $hex3= {2461333d2022537973}
		 $hex4= {2461343d2022545661}
		 $hex5= {2461353d20225a3a50}
		 $hex6= {2461363d20225a3a50}
		 $hex7= {24733130303d202253}
		 $hex8= {24733130313d202253}
		 $hex9= {24733130323d202253}
		 $hex10= {24733130333d202253}
		 $hex11= {24733130343d202253}
		 $hex12= {24733130353d202253}
		 $hex13= {24733130363d202253}
		 $hex14= {24733130373d202253}
		 $hex15= {24733130383d202253}
		 $hex16= {24733130393d202253}
		 $hex17= {247331303d20222534}
		 $hex18= {24733131303d202253}
		 $hex19= {24733131313d202253}
		 $hex20= {24733131323d202253}
		 $hex21= {24733131333d202273}
		 $hex22= {24733131343d20225f}
		 $hex23= {24733131353d202274}
		 $hex24= {24733131363d202255}
		 $hex25= {24733131373d202275}
		 $hex26= {24733131383d202275}
		 $hex27= {24733131393d202256}
		 $hex28= {247331313d20223474}
		 $hex29= {24733132303d20222f}
		 $hex30= {24733132313d202257}
		 $hex31= {24733132323d202277}
		 $hex32= {24733132333d202278}
		 $hex33= {24733132343d202278}
		 $hex34= {24733132353d20222b}
		 $hex35= {24733132363d202259}
		 $hex36= {24733132373d202279}
		 $hex37= {24733132383d202279}
		 $hex38= {24733132393d202279}
		 $hex39= {247331323d2022373e}
		 $hex40= {24733133303d20227a}
		 $hex41= {247331333d2022377a}
		 $hex42= {247331343d2022393d}
		 $hex43= {247331353d20223b3d}
		 $hex44= {247331363d20224164}
		 $hex45= {247331373d20222f41}
		 $hex46= {247331383d20222f41}
		 $hex47= {247331393d20224238}
		 $hex48= {2473313d20223a3d3a}
		 $hex49= {247332303d20224241}
		 $hex50= {247332313d20224368}
		 $hex51= {247332323d20226368}
		 $hex52= {247332333d20224372}
		 $hex53= {247332343d20224372}
		 $hex54= {247332353d20226439}
		 $hex55= {247332363d20222f44}
		 $hex56= {247332373d20226473}
		 $hex57= {247332383d20224539}
		 $hex58= {247332393d20223a3d}
		 $hex59= {2473323d2022272628}
		 $hex60= {247333303d20222f45}
		 $hex61= {247333313d20224663}
		 $hex62= {247333323d20226653}
		 $hex63= {247333333d20226763}
		 $hex64= {247333343d20224764}
		 $hex65= {247333353d20224765}
		 $hex66= {247333363d20226766}
		 $hex67= {247333373d20226746}
		 $hex68= {247333383d2022476f}
		 $hex69= {247333393d2022677a}
		 $hex70= {2473333d2022303845}
		 $hex71= {247334303d2022484c}
		 $hex72= {247334313d20226874}
		 $hex73= {247334323d20226874}
		 $hex74= {247334333d20226947}
		 $hex75= {247334343d20222f49}
		 $hex76= {247334353d20224950}
		 $hex77= {247334363d20224c69}
		 $hex78= {247334373d20222f4c}
		 $hex79= {247334383d20226c75}
		 $hex80= {247334393d20226c76}
		 $hex81= {2473343d20227b307d}
		 $hex82= {247335303d20226c77}
		 $hex83= {247335313d20224c77}
		 $hex84= {247335323d20224c78}
		 $hex85= {247335333d20226c59}
		 $hex86= {247335343d20224d65}
		 $hex87= {247335353d20224d69}
		 $hex88= {247335363d20224d69}
		 $hex89= {247335373d20224d4f}
		 $hex90= {247335383d20224d6f}
		 $hex91= {247335393d20222f4d}
		 $hex92= {2473353d20227b307d}
		 $hex93= {247336303d20226d79}
		 $hex94= {247336313d20224e48}
		 $hex95= {247336323d20224e48}
		 $hex96= {247336333d20224e48}
		 $hex97= {247336343d20224e6c}
		 $hex98= {247336353d20225065}
		 $hex99= {247336363d2022706a}
		 $hex100= {247336373d20225072}
		 $hex101= {247336383d20225072}
		 $hex102= {247336393d20225072}
		 $hex103= {2473363d20225b7b30}
		 $hex104= {247337303d20225072}
		 $hex105= {247337313d20225072}
		 $hex106= {247337323d20225072}
		 $hex107= {247337333d20225072}
		 $hex108= {247337343d20225072}
		 $hex109= {247337353d20225072}
		 $hex110= {247337363d20225072}
		 $hex111= {247337373d20225072}
		 $hex112= {247337383d20222f52}
		 $hex113= {247337393d20222f52}
		 $hex114= {2473373d2022282e7b}
		 $hex115= {247338303d20222f52}
		 $hex116= {247338313d20222f52}
		 $hex117= {247338323d20222b73}
		 $hex118= {247338333d20225365}
		 $hex119= {247338343d2022536f}
		 $hex120= {247338353d2022536f}
		 $hex121= {247338363d2022536f}
		 $hex122= {247338373d2022536f}
		 $hex123= {247338383d2022534f}
		 $hex124= {247338393d2022534f}
		 $hex125= {2473383d2022252328}
		 $hex126= {247339303d2022534f}
		 $hex127= {247339313d2022534f}
		 $hex128= {247339323d2022534f}
		 $hex129= {247339333d20222f53}
		 $hex130= {247339343d20222f53}
		 $hex131= {247339353d20222f53}
		 $hex132= {247339363d20222f53}
		 $hex133= {247339373d20222f53}
		 $hex134= {247339383d20225379}
		 $hex135= {247339393d20225379}
		 $hex136= {2473393d2022337a68}

	condition:
		90 of them
}
