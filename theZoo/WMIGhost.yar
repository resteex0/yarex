
/*
   YARA Rule Set
   Author: resteex
   Identifier: WMIGhost 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_WMIGhost {
	meta: 
		 description= "WMIGhost Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-35-41" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "0df40b226a4913a57668b83b7c7b443c"
		 hash2= "0e7db6b6a6e4993a01a01df578d65bf0"
		 hash3= "11b8142c08b1820420f8802f18cc2bc0"
		 hash4= "1b83b315b7a729cb685270496ae68802"
		 hash5= "34409aba1f76045aa0255e49de16d586"
		 hash6= "460b288a581cdeb5f831d102cb6d198b"
		 hash7= "68bfa1b82dc0e2de10d0cf8551938dea"
		 hash8= "6b8ea12d811acf88f94b734bf5cfbfb3"
		 hash9= "6eb39bd2f4ae46101ed9782f3ff38e98"
		 hash10= "70a2fd5bd44482de36790309079fd9ac"
		 hash11= "71661cb05ac3beef85615bdecc5b3ede"
		 hash12= "77b645ef1c599f289f3d462a09048c49"
		 hash13= "a0e874f05c2d6938c35d41e38e691b51"
		 hash14= "a5bd39bf17d389340b2d80d060860d7b"
		 hash15= "bb49e068c25707c7149acff2834f89c9"
		 hash16= "c249cb532699e15b3cb6e9deb6264240"
		 hash17= "d076814db477d73051610386fae69fca"
		 hash18= "e0e092ea23f534d8c89b9f607d50168b"
		 hash19= "ec9ae4c3935b717769a5b3a3fa712943"

	strings:

	
 		 $s1= "ActiveScriptEventConsumer" fullword wide
		 $s2= "ActiveScriptEventConsumer.Name='ProbeScriptFint'" fullword wide
		 $s3= "__EventFilter.Name='ProbeScriptFint'" fullword wide
		 $s4= "__FilterToConsumerBinding" fullword wide
		 $s5= "IntervalBetweenEvents" fullword wide
		 $s6= "__IntervalTimerInstruction" fullword wide
		 $s7= "ProbeScriptFint" fullword wide
		 $s8= "ScriptingEngine" fullword wide
		 $s9= "select * from __timerevent where timerid='ProbeScriptFint'" fullword wide
		 $s10= "strings: Warning: 'theZoo/malware/Binaries/WMIGhost/WMIGhost/WMIGhost' is a directory" fullword wide
		 $a1= "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" fullword ascii
		 $a2= "0%29y#4xj7>#y'0#q8laj8m%8%=4" fullword ascii
		 $a3= "??0Init@ios_base@std@@QAE@XZ" fullword ascii
		 $a4= "1(era3`d}va.1q`~1(era3^RZ].uf}pgz|};:h7.g{z`(7=xvj.4D4(7=`UvvwFa" fullword ascii
		 $a5= "??1Init@ios_base@std@@QAE@XZ" fullword ascii
		 $a6= "2222222133232222222x22232322822222222" fullword ascii
		 $a7= ";4;48p|}grz}vaHzN=gvkg84:4:=p|~~r}w(nnzu;p|~~r}w`2.}f" fullword ascii
		 $a8= "=4?6%9oax*#4%$#?j,,,20%29y4x*,,,}" fullword ascii
		 $a9= "4:(7=|@gavr~.}vd37=Lk;4RWWQ=@gavr~4:(7=Tvg@Z}u|;:(7=Tvg^rpRwwav``;:(7=Tv}vargvFa" fullword ascii
		 $a10= "|}.487=eva`z|}(7=`FA_Crar~8.45g.48gz~v=tvg^z}fgv`;:8gz~v=tvg@vp|}w`;:(n?P" fullword ascii
		 $a11= "4yv58'vxj7>#y'0#q8laj8m2>?%08?4#" fullword ascii
		 $a12= "~~~~~~(7.~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" fullword ascii
		 $a13= "?7>k7$?2%8>?yx*'0#q4l?4&q" fullword ascii
		 $a14= "(7=Lk.RpgzevKqyvpg(n(^RZ]=ca|g|gjcv.hZ}zgqyvpg`)3uf}pgz|};:h7=|D^Z.Tvgqyvpg;4dz}~t~g`)hz~cva`|}rg" fullword ascii
		 $a15= "&9Kity~Hxirko]ruo97i5Ruo~imzwY~ol~~u^m~uoh&-~(7i5KnoD327i&~oTyq~xo3u09!DD^m~uo]rwo~i925hkzluruhozux" fullword ascii
		 $a16= "=9,OO=c{c4:(zu;g~c`ga2.}f" fullword ascii
		 $a17= "~c002`?5hCvwNiw&NiwWrho@Niwru" fullword ascii
		 $a18= "C:DOCUME~1ADMINI~1LOCALS~1Tempdw20.EXE" fullword ascii
		 $a19= "C:e1d852f2ea8436ac33bc8fe200aca4af4fb15f33ecda6441741589daa44115c5" fullword ascii
		 $a20= "Crar~;:(n?D^Z)uf}pgz|};`b" fullword ascii
		 $a21= "Crar~)uf}pgz|};:hera3gz~v.}vd3Wrgv;:(7=`FA_Crar~.4p`gjcv.`vaeva5rfg{}r~v.`vaeva}r~v5rfg{cr``.`vaevac" fullword ascii
		 $a22= "C:UsersitbpAppDataLocalTempdw20.EXE" fullword ascii
		 $a23= "C:UsersNewAppDataLocalTempdw20.EXE" fullword ascii
		 $a24= "C:UsersuserAppDataLocalTempdw20.EXE" fullword ascii
		 $a25= "C:Windowssystem32Instell.exe" fullword ascii
		 $a26= "C:Windowssystem32sysprepcryptbase.dll" fullword ascii
		 $a27= "C:WINDOWSsystem32sysprepcryptbase.dll" fullword ascii
		 $a28= "(era3v.}vd3V}f~varg|a;7=D^Z;1@v" fullword ascii
		 $a29= "fv::(nprgp{;v:hnzu;z-#:hp|~~r}wav`f" fullword ascii
		 $a30= "fv=~rgp{;4S;=9:S4:(zu;g~c`ga2.}f" fullword ascii
		 $a31= "g.44(u|a;era3z.#(z/3p|~~r}w`=" fullword ascii
		 $a32= "g8.4148p|~~r}w`HzN=zw841)148v`prcv;av`f" fullword ascii
		 $a33= "g84n4(7=|[ggc=cv};4C@G4?7=`K~" fullword ascii
		 $a34= "g8.@gaz}t=ua|~P{raP|wv;er" fullword ascii
		 $a35= "GAIsProcessorFeaturePresent" fullword ascii
		 $a36= ".g`ga(n7=|[ggc=cv};4TVG4?uvvwFa" fullword ascii
		 $a37= "g:(nnnn?Uzav)3uf}pgz|};:h7=Z}zgqyvpg`;:(gajh7=^rz}_||c;:(nprgp{;v:hn7=P" fullword ascii
		 $a38= ":havgfa}37=|D^Z=VkvpBfvaj;`b" fullword ascii
		 $a39= "http://127.0.0.1/sosblogs.xml" fullword ascii
		 $a40= "http://192.168.66.184/sosblogs.xml" fullword ascii
		 $a41= ":huwHupN.g~c`ga(up88(nnnzu;uw=" fullword ascii
		 $a42= "h~w~xo;1;}itv;DDorv~i~m~uo;ls~i~;orv~ir" fullword ascii
		 $a43= "H~w~xo;1;}itv;Lru()DU~oltipZ" fullword ascii
		 $a44= "`HzNMxvjp|wv:3(navgfa}3av`f" fullword ascii
		 $a45= "InitializeCriticalSection" fullword ascii
		 $a46= "JanFebMarAprMayJunJulAugSepOctNovDec" fullword ascii
		 $a47= "lwzmpvw10b=7vQmmi$w|n9=7Fa1>Tpzkvjv" fullword ascii
		 $a48= "lwzmpvw10boxk9|$w|n9wlt|kxmvk1=7NTP1>J|u|zm939" fullword ascii
		 $a49= ":(n?Tvg@Z}u|)3uf}pgz|};:hera3v.}vd3V}f~varg|a;7=D^Z;4@v" fullword ascii
		 $a50= "~!}nuxortu3htnix~Hoi2`mzi;p~bxt" fullword ascii
		 $a51= "~!}nuxortu3hx2`mzi;yzh~&hx5xsziXt" fullword ascii
		 $a52= "Q~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" fullword ascii
		 $a53= "r``5{|`g}r~v.487=`[|`g]r~v845|`gjcv.487=`@Gjcv845~rprwwa.487=`^rpRwwav``845|d}va.487=`d}va845eva`z" fullword ascii
		 $a54= "|rwK^_;av`c|}`v:(era3p|}grz}va3.3|K~" fullword ascii
		 $a55= "|rwK^_;av`c|}`v:(era3zgv~`.|K~" fullword ascii
		 $a56= "SetUnhandledExceptionFilter" fullword ascii
		 $a57= ".uwHcra`vZ}g;^rg{=ar}w|~;:9uw=" fullword ascii
		 $a58= "v4:(era3uw.}vd3Raarj;:(u|a;era3z.#?up.#(z/zgv~`=" fullword ascii
		 $a59= "`v:(7=|[ggc=`vgAvbfv`g[vrwva;4F`va>Rtv}g4?4^|iz" fullword ascii
		 $a60= "`v:(7=|[ggc=`vgAvbfv`g[vrwva;4P]GV]G>GJCV4?4rcc" fullword ascii
		 $a61= "v}p|wvw4:(7=|[ggc=@v}w;7=`FA_Crar~845p|~~r}w.av`f" fullword ascii
		 $a62= "v}p|wvw4:(7=|[ggc=@v}w;7=`FA_Crar~:(era3av`c|}`v.7=|[ggc=Av`c|}`vGvkg=avc" fullword ascii
		 $a63= "vr}qyvpg`;:(nn(}vd3^RZ];:=Uzav;:(" fullword ascii
		 $a64= "vr}qyvpg`)uf}pgz|};:h7=|@{v" fullword ascii
		 $a65= "v}tg{(}88:hgajhera3g`ga.uvvwFa" fullword ascii
		 $a66= "v}tg{:N(qavrx(nnprgp{;v:hnn7=|[ggc=cv};4C@G4?7=`K~" fullword ascii
		 $a67= "v}tg{(z88:hera3zgv~.zgv~`HzN(era3g~c`ga.zgv~=uza`gP{z" fullword ascii
		 $a68= "v~v}g`QjGrt]r~v;4wze4:(u|a;era3z.#(z/p|}grz}va=" fullword ascii
		 $a69= ".z~cva`|}rgvn2OOOO=OOa||gOOpz~e!4:(7=|@{v" fullword ascii
		 $a70= "zg;4(4:(u|a3;era3}.#(}/uvvwFa" fullword ascii
		 $a71= "zkkwrxzortu4c6lll6}tiv6niw~uxt" fullword ascii
		 $a72= "zko~i;ls~i~;KUK_~mrx~R_;wrp~;GGG9>KXR>GGG9;zu" fullword ascii
		 $a73= "zxv346CPZ643r}w3]vgP|}}vpgz|}@grgf`.!1::(zu;2v=rgV}w;::h7=`^rpRwwav``.v=zgv~;:=^RPRwwav``(nn?Tv}varg" fullword ascii

		 $hex1= {246131303d20227c7d}
		 $hex2= {246131313d20223479}
		 $hex3= {246131323d20227e7e}
		 $hex4= {246131333d20223f37}
		 $hex5= {246131343d20222837}
		 $hex6= {246131353d20222639}
		 $hex7= {246131363d20223d39}
		 $hex8= {246131373d20227e63}
		 $hex9= {246131383d2022433a}
		 $hex10= {246131393d2022433a}
		 $hex11= {2461313d20227e7e7e}
		 $hex12= {246132303d20224372}
		 $hex13= {246132313d20224372}
		 $hex14= {246132323d2022433a}
		 $hex15= {246132333d2022433a}
		 $hex16= {246132343d2022433a}
		 $hex17= {246132353d2022433a}
		 $hex18= {246132363d2022433a}
		 $hex19= {246132373d2022433a}
		 $hex20= {246132383d20222865}
		 $hex21= {246132393d20226676}
		 $hex22= {2461323d2022302532}
		 $hex23= {246133303d20226676}
		 $hex24= {246133313d2022672e}
		 $hex25= {246133323d20226738}
		 $hex26= {246133333d20226738}
		 $hex27= {246133343d20226738}
		 $hex28= {246133353d20224741}
		 $hex29= {246133363d20222e67}
		 $hex30= {246133373d2022673a}
		 $hex31= {246133383d20223a68}
		 $hex32= {246133393d20226874}
		 $hex33= {2461333d20223f3f30}
		 $hex34= {246134303d20226874}
		 $hex35= {246134313d20223a68}
		 $hex36= {246134323d2022687e}
		 $hex37= {246134333d2022487e}
		 $hex38= {246134343d20226048}
		 $hex39= {246134353d2022496e}
		 $hex40= {246134363d20224a61}
		 $hex41= {246134373d20226c77}
		 $hex42= {246134383d20226c77}
		 $hex43= {246134393d20223a28}
		 $hex44= {2461343d2022312865}
		 $hex45= {246135303d20227e21}
		 $hex46= {246135313d20227e21}
		 $hex47= {246135323d2022517e}
		 $hex48= {246135333d20227260}
		 $hex49= {246135343d20227c72}
		 $hex50= {246135353d20227c72}
		 $hex51= {246135363d20225365}
		 $hex52= {246135373d20222e75}
		 $hex53= {246135383d20227634}
		 $hex54= {246135393d20226076}
		 $hex55= {2461353d20223f3f31}
		 $hex56= {246136303d20226076}
		 $hex57= {246136313d2022767d}
		 $hex58= {246136323d2022767d}
		 $hex59= {246136333d20227672}
		 $hex60= {246136343d20227672}
		 $hex61= {246136353d2022767d}
		 $hex62= {246136363d2022767d}
		 $hex63= {246136373d2022767d}
		 $hex64= {246136383d2022767e}
		 $hex65= {246136393d20222e7a}
		 $hex66= {2461363d2022323232}
		 $hex67= {246137303d20227a67}
		 $hex68= {246137313d20227a6b}
		 $hex69= {246137323d20227a6b}
		 $hex70= {246137333d20227a78}
		 $hex71= {2461373d20223b343b}
		 $hex72= {2461383d20223d343f}
		 $hex73= {2461393d2022343a28}
		 $hex74= {247331303d20227374}
		 $hex75= {2473313d2022416374}
		 $hex76= {2473323d2022416374}
		 $hex77= {2473333d20225f5f45}
		 $hex78= {2473343d20225f5f46}
		 $hex79= {2473353d2022496e74}
		 $hex80= {2473363d20225f5f49}
		 $hex81= {2473373d202250726f}
		 $hex82= {2473383d2022536372}
		 $hex83= {2473393d202273656c}

	condition:
		10 of them
}
