
/*
   YARA Rule Set
   Author: resteex
   Identifier: Vermin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Vermin {
	meta: 
		 description= "Vermin Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-19-12" 
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
		 $a1= "'&(&)&-,0/1/2/3/657598:8>=BACADAFERQutvtwtxtyt{z|z" fullword ascii
		 $a2= ";=;>;?;@;A;CBDBEBFBGBHBIBJBONPN^]bafehg|{}{" fullword ascii
		 $a3= "d9eYsSZ+Wtli4Kuv6iGRrXUQ827dkjRcToWvKMiKr5PZDT7/W1Qe5Vl5eZn3ZcdR" fullword ascii
		 $a4= "/DisallowStartIfOnBatteries>" fullword ascii
		 $a5= "gFM7+SMQykANpUTKIYQTVKV0pRrsSVOekuLq9TggwmTsW4+gC64N7F06+NPsY246" fullword ascii
		 $a6= "lw+tLddEXhLnJe7QKL4XrE+cTXBikwzFHJM3hXli/Sb7K3SsyDFbzTPWEPQrUPlg" fullword ascii
		 $a7= "LxTFTiZvZnGcdUjGvKWHfKcAs8/SvVMtFAVc9utXc0LWFo6w/Tj/OQEmZolnOY4S" fullword ascii
		 $a8= "MOWALmJJz5YfckoGCPROnKddVGfNXxVkXI6j1joBhs/fGOFbbqluGUcmyioWNkK8" fullword ascii
		 $a9= "/MultipleInstancesPolicy>" fullword ascii
		 $a10= "/RunOnlyIfNetworkAvailable>" fullword ascii
		 $a11= "+s6gNokzOEyrMlvfCRGmYtQx0zGnk48xRRet/khT6SuL69qa8/0Na2x4hHF/97C4" fullword ascii
		 $a12= "SoftwareMicrosoftInternet ExplorerIntelliFormsStorage2" fullword ascii
		 $a13= "SOFTWAREWow6432NodeMicrosoftWindowsCurrentVersionRun" fullword ascii
		 $a14= "SOFTWAREWow6432NodeMicrosoftWindowsCurrentVersionRunOnce" fullword ascii
		 $a15= "/StartBoundary>" fullword ascii
		 $a16= "/StopIfGoingOnBatteries>" fullword ascii
		 $a17= "System.Collections.Concurrent.IProducerConsumerCollection`1" fullword ascii
		 $a18= "System.Runtime.Serialization.DataContractAttribute" fullword ascii
		 $a19= "System.Runtime.Serialization.OnDeserializedAttribute" fullword ascii
		 $a20= "System.Runtime.Serialization.OnDeserializingAttribute" fullword ascii
		 $a21= "System.Runtime.Serialization.OnSerializedAttribute" fullword ascii
		 $a22= "System.Runtime.Serialization.OnSerializingAttribute" fullword ascii
		 $a23= "+y73MkHmkcxMIqRwP2Cl3TepckKzmwB4G+7knh0kDJ9hbreSt+cbocpTtdn86H76" fullword ascii

		 $hex1= {246131303d20222f52}
		 $hex2= {246131313d20222b73}
		 $hex3= {246131323d2022536f}
		 $hex4= {246131333d2022534f}
		 $hex5= {246131343d2022534f}
		 $hex6= {246131353d20222f53}
		 $hex7= {246131363d20222f53}
		 $hex8= {246131373d20225379}
		 $hex9= {246131383d20225379}
		 $hex10= {246131393d20225379}
		 $hex11= {2461313d2022272628}
		 $hex12= {246132303d20225379}
		 $hex13= {246132313d20225379}
		 $hex14= {246132323d20225379}
		 $hex15= {246132333d20222b79}
		 $hex16= {2461323d20223b3d3b}
		 $hex17= {2461333d2022643965}
		 $hex18= {2461343d20222f4469}
		 $hex19= {2461353d202267464d}
		 $hex20= {2461363d20226c772b}
		 $hex21= {2461373d20224c7854}
		 $hex22= {2461383d20224d4f57}
		 $hex23= {2461393d20222f4d75}
		 $hex24= {24733130303d202253}
		 $hex25= {24733130313d202253}
		 $hex26= {24733130323d202253}
		 $hex27= {24733130333d202253}
		 $hex28= {24733130343d202253}
		 $hex29= {24733130353d202253}
		 $hex30= {24733130363d202253}
		 $hex31= {24733130373d202253}
		 $hex32= {24733130383d202253}
		 $hex33= {24733130393d202253}
		 $hex34= {247331303d20222534}
		 $hex35= {24733131303d202253}
		 $hex36= {24733131313d202253}
		 $hex37= {24733131323d202253}
		 $hex38= {24733131333d202273}
		 $hex39= {24733131343d20225f}
		 $hex40= {24733131353d202274}
		 $hex41= {24733131363d202255}
		 $hex42= {24733131373d202275}
		 $hex43= {24733131383d202275}
		 $hex44= {24733131393d202256}
		 $hex45= {247331313d20223474}
		 $hex46= {24733132303d20222f}
		 $hex47= {24733132313d202257}
		 $hex48= {24733132323d202277}
		 $hex49= {24733132333d202278}
		 $hex50= {24733132343d202278}
		 $hex51= {24733132353d20222b}
		 $hex52= {24733132363d202259}
		 $hex53= {24733132373d202279}
		 $hex54= {24733132383d202279}
		 $hex55= {24733132393d202279}
		 $hex56= {247331323d2022373e}
		 $hex57= {24733133303d20227a}
		 $hex58= {247331333d2022377a}
		 $hex59= {247331343d2022393d}
		 $hex60= {247331353d20223b3d}
		 $hex61= {247331363d20224164}
		 $hex62= {247331373d20222f41}
		 $hex63= {247331383d20222f41}
		 $hex64= {247331393d20224238}
		 $hex65= {2473313d20223a3d3a}
		 $hex66= {247332303d20224241}
		 $hex67= {247332313d20224368}
		 $hex68= {247332323d20226368}
		 $hex69= {247332333d20224372}
		 $hex70= {247332343d20224372}
		 $hex71= {247332353d20226439}
		 $hex72= {247332363d20222f44}
		 $hex73= {247332373d20226473}
		 $hex74= {247332383d20224539}
		 $hex75= {247332393d20223a3d}
		 $hex76= {2473323d2022272628}
		 $hex77= {247333303d20222f45}
		 $hex78= {247333313d20224663}
		 $hex79= {247333323d20226653}
		 $hex80= {247333333d20226763}
		 $hex81= {247333343d20224764}
		 $hex82= {247333353d20224765}
		 $hex83= {247333363d20226766}
		 $hex84= {247333373d20226746}
		 $hex85= {247333383d2022476f}
		 $hex86= {247333393d2022677a}
		 $hex87= {2473333d2022303845}
		 $hex88= {247334303d2022484c}
		 $hex89= {247334313d20226874}
		 $hex90= {247334323d20226874}
		 $hex91= {247334333d20226947}
		 $hex92= {247334343d20222f49}
		 $hex93= {247334353d20224950}
		 $hex94= {247334363d20224c69}
		 $hex95= {247334373d20222f4c}
		 $hex96= {247334383d20226c75}
		 $hex97= {247334393d20226c76}
		 $hex98= {2473343d20227b307d}
		 $hex99= {247335303d20226c77}
		 $hex100= {247335313d20224c77}
		 $hex101= {247335323d20224c78}
		 $hex102= {247335333d20226c59}
		 $hex103= {247335343d20224d65}
		 $hex104= {247335353d20224d69}
		 $hex105= {247335363d20224d69}
		 $hex106= {247335373d20224d4f}
		 $hex107= {247335383d20224d6f}
		 $hex108= {247335393d20222f4d}
		 $hex109= {2473353d20227b307d}
		 $hex110= {247336303d20226d79}
		 $hex111= {247336313d20224e48}
		 $hex112= {247336323d20224e48}
		 $hex113= {247336333d20224e48}
		 $hex114= {247336343d20224e6c}
		 $hex115= {247336353d20225065}
		 $hex116= {247336363d2022706a}
		 $hex117= {247336373d20225072}
		 $hex118= {247336383d20225072}
		 $hex119= {247336393d20225072}
		 $hex120= {2473363d20225b7b30}
		 $hex121= {247337303d20225072}
		 $hex122= {247337313d20225072}
		 $hex123= {247337323d20225072}
		 $hex124= {247337333d20225072}
		 $hex125= {247337343d20225072}
		 $hex126= {247337353d20225072}
		 $hex127= {247337363d20225072}
		 $hex128= {247337373d20225072}
		 $hex129= {247337383d20222f52}
		 $hex130= {247337393d20222f52}
		 $hex131= {2473373d2022282e7b}
		 $hex132= {247338303d20222f52}
		 $hex133= {247338313d20222f52}
		 $hex134= {247338323d20222b73}
		 $hex135= {247338333d20225365}
		 $hex136= {247338343d2022536f}
		 $hex137= {247338353d2022536f}
		 $hex138= {247338363d2022536f}
		 $hex139= {247338373d2022536f}
		 $hex140= {247338383d2022534f}
		 $hex141= {247338393d2022534f}
		 $hex142= {2473383d2022252328}
		 $hex143= {247339303d2022534f}
		 $hex144= {247339313d2022534f}
		 $hex145= {247339323d2022534f}
		 $hex146= {247339333d20222f53}
		 $hex147= {247339343d20222f53}
		 $hex148= {247339353d20222f53}
		 $hex149= {247339363d20222f53}
		 $hex150= {247339373d20222f53}
		 $hex151= {247339383d20225379}
		 $hex152= {247339393d20225379}
		 $hex153= {2473393d2022337a68}

	condition:
		102 of them
}
