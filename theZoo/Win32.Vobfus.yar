
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Vobfus 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Vobfus {
	meta: 
		 description= "Win32_Vobfus Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-39-26" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "4e15d812491ff0454f1e9393675b1c60"
		 hash2= "634aa845f5b0b519b6d8a8670b994906"
		 hash3= "70f0b7bd55b91de26f9ed6f1ef86b456"
		 hash4= "7b19b2b8aed0285eb2b2c5cb81313569"

	strings:

	
 		 $s1= "aggfigvokblqlqmelekmn" fullword wide
		 $s2= "ajlxwcgachfqbkcpfxukkweqsgykpf" fullword wide
		 $s3= "aokxxgommpzwxgyzj" fullword wide
		 $s4= "bpbjtchitthvkhtquiyvkbkrnth" fullword wide
		 $s5= "bqqdroyycfihslhpoohqzytalnyl" fullword wide
		 $s6= "bqxotuzhkyfkxrqirgbitxg" fullword wide
		 $s7= "cjjmffglaxhstwokjiyxyvugu" fullword wide
		 $s8= "crnpbjxehpytjqdrt" fullword wide
		 $s9= "czromwcfyolrisrojppfcvfil" fullword wide
		 $s10= "daytime changed" fullword wide
		 $s11= "dpmhkmbnojztbrkllddazbqkdx" fullword wide
		 $s12= "drerytzwckshkdjwbbaia" fullword wide
		 $s13= "duskingtide.exe" fullword wide
		 $s14= "dvmsqvnjeocqtfv" fullword wide
		 $s15= "dzybttvipbyvoflasaunpccmbehyni" fullword wide
		 $s16= "emgkgtgnnmnmninigthkgogggvmkhinjggnvm" fullword wide
		 $s17= "evpfgfwpjeiggbhmwtvn" fullword wide
		 $s18= "evxeegnvuvnmntdmsh" fullword wide
		 $s19= "faondkmnncncwey" fullword wide
		 $s20= "gbqmsfnimhckffqnucokvofbklmi" fullword wide
		 $s21= "gcezfgwpahpyzajsgnexyvlcf" fullword wide
		 $s22= "gfxcombat.bmp" fullword wide
		 $s23= "gfxcursor.bmp" fullword wide
		 $s24= "gfxdamage.bmp" fullword wide
		 $s25= "gfxexplo1.bmp" fullword wide
		 $s26= "gfxexplo2.bmp" fullword wide
		 $s27= "gfxexplo3.bmp" fullword wide
		 $s28= "gfxloading.bmp" fullword wide
		 $s29= "hcutfnxwjwjxlgkfrctxt" fullword wide
		 $s30= "hkyacavjnkteptjmv" fullword wide
		 $s31= "IID_IDirect3DHALDevice" fullword wide
		 $s32= "ivstbtjbuegpxsmsnbcc" fullword wide
		 $s33= "kjbfbuiioxwbrfbj" fullword wide
		 $s34= "kpqqkjpjoxltraum" fullword wide
		 $s35= "krztyrxztfbhksedarmphjgssyhtx" fullword wide
		 $s36= "ktmnqumaxvgrohpbsr" fullword wide
		 $s37= "kzowkgptylrzzeydvlydewyqiavmz" fullword wide
		 $s38= "lnrjhepzjcqrjqmqxz" fullword wide
		 $s39= "lrahvhlopuhfzibod" fullword wide
		 $s40= "lrmsqxiliqtyizqqwyorcvbon" fullword wide
		 $s41= "lsdkfcnlxikjlwrybamxrsocv" fullword wide
		 $s42= "lvwgetyigyadtsiwloxsxwvhlc" fullword wide
		 $s43= "mrgjozqdxqbwneitb" fullword wide
		 $s44= "muagphipprtuypesinyszfgtavhhb" fullword wide
		 $s45= "nrcfpfvozvjocicnucplpeqnihyrz" fullword wide
		 $s46= "ommzfysasihuatdrzjpxw" fullword wide
		 $s47= "OriginalFilename" fullword wide
		 $s48= "qceljixltaoyeavvrwuairuier" fullword wide
		 $s49= "qglzewcpuqtorzef" fullword wide
		 $s50= "qicjuorvmpdmzxolgufmifdojqn" fullword wide
		 $s51= "qjcpxonlldxiilikywpgtju" fullword wide
		 $s52= "qjnbwcjerviphfuohhrlfltx" fullword wide
		 $s53= "rfbzfruvrtlilsnkpx" fullword wide
		 $s54= "rjxekrawgdaehqoitusfud" fullword wide
		 $s55= "rkzptfefareoehrsovnixbifxigks" fullword wide
		 $s56= "schematonics Diradarai" fullword wide
		 $s57= "slntiqfqjkaaahebnqfkylsz" fullword wide
		 $s58= "sndenginee.wav" fullword wide
		 $s59= "sndenginep.wav" fullword wide
		 $s60= "sndexplobig.wav" fullword wide
		 $s61= "sndexplosmall.wav" fullword wide
		 $s62= "swqrmywpcdvimjpbehhykhnihtc" fullword wide
		 $s63= "tbqbzkwlidxtoftccgxkyzlzw" fullword wide
		 $s64= "thusbzxncaqmdrtovatk" fullword wide
		 $s65= "tlssdwplvekyhesfbfgunyxlg" fullword wide
		 $s66= "txfvwraujzoelakiq" fullword wide
		 $s67= "uarhdvpahruhqxuyzgi" fullword wide
		 $s68= "ufnwijyaydcfcfjjhokaobjlw" fullword wide
		 $s69= "uggnbvmprutpiugoduavdpqm" fullword wide
		 $s70= "uwjwppgkjscpcrdukozlad" fullword wide
		 $s71= "VS_VERSION_INFO" fullword wide
		 $s72= "wesmbitnkheykcobqpkim" fullword wide
		 $s73= "wirmplmnjkgwovkaerbjayzcgak" fullword wide
		 $s74= "wxcukmhbcunqkteuswadqhajkh" fullword wide
		 $s75= "xjnipmfyxflnsiwgxphtcat" fullword wide
		 $s76= "xqontuphupimliflgg" fullword wide
		 $s77= "yofryblhwegljnargkhbsdaggtpso" fullword wide
		 $s78= "zcgmleuaojfpuzikzphi" fullword wide
		 $s79= "znjxvsebwpknvygsibuvsjbn" fullword wide
		 $a1= "emgkgtgnnmnmninigthkgogggvmkhinjggnvm" fullword ascii

		 $hex1= {2461313d2022656d67}
		 $hex2= {247331303d20226461}
		 $hex3= {247331313d20226470}
		 $hex4= {247331323d20226472}
		 $hex5= {247331333d20226475}
		 $hex6= {247331343d20226476}
		 $hex7= {247331353d2022647a}
		 $hex8= {247331363d2022656d}
		 $hex9= {247331373d20226576}
		 $hex10= {247331383d20226576}
		 $hex11= {247331393d20226661}
		 $hex12= {2473313d2022616767}
		 $hex13= {247332303d20226762}
		 $hex14= {247332313d20226763}
		 $hex15= {247332323d20226766}
		 $hex16= {247332333d20226766}
		 $hex17= {247332343d20226766}
		 $hex18= {247332353d20226766}
		 $hex19= {247332363d20226766}
		 $hex20= {247332373d20226766}
		 $hex21= {247332383d20226766}
		 $hex22= {247332393d20226863}
		 $hex23= {2473323d2022616a6c}
		 $hex24= {247333303d2022686b}
		 $hex25= {247333313d20224949}
		 $hex26= {247333323d20226976}
		 $hex27= {247333333d20226b6a}
		 $hex28= {247333343d20226b70}
		 $hex29= {247333353d20226b72}
		 $hex30= {247333363d20226b74}
		 $hex31= {247333373d20226b7a}
		 $hex32= {247333383d20226c6e}
		 $hex33= {247333393d20226c72}
		 $hex34= {2473333d2022616f6b}
		 $hex35= {247334303d20226c72}
		 $hex36= {247334313d20226c73}
		 $hex37= {247334323d20226c76}
		 $hex38= {247334333d20226d72}
		 $hex39= {247334343d20226d75}
		 $hex40= {247334353d20226e72}
		 $hex41= {247334363d20226f6d}
		 $hex42= {247334373d20224f72}
		 $hex43= {247334383d20227163}
		 $hex44= {247334393d20227167}
		 $hex45= {2473343d2022627062}
		 $hex46= {247335303d20227169}
		 $hex47= {247335313d2022716a}
		 $hex48= {247335323d2022716a}
		 $hex49= {247335333d20227266}
		 $hex50= {247335343d2022726a}
		 $hex51= {247335353d2022726b}
		 $hex52= {247335363d20227363}
		 $hex53= {247335373d2022736c}
		 $hex54= {247335383d2022736e}
		 $hex55= {247335393d2022736e}
		 $hex56= {2473353d2022627171}
		 $hex57= {247336303d2022736e}
		 $hex58= {247336313d2022736e}
		 $hex59= {247336323d20227377}
		 $hex60= {247336333d20227462}
		 $hex61= {247336343d20227468}
		 $hex62= {247336353d2022746c}
		 $hex63= {247336363d20227478}
		 $hex64= {247336373d20227561}
		 $hex65= {247336383d20227566}
		 $hex66= {247336393d20227567}
		 $hex67= {2473363d2022627178}
		 $hex68= {247337303d20227577}
		 $hex69= {247337313d20225653}
		 $hex70= {247337323d20227765}
		 $hex71= {247337333d20227769}
		 $hex72= {247337343d20227778}
		 $hex73= {247337353d2022786a}
		 $hex74= {247337363d20227871}
		 $hex75= {247337373d2022796f}
		 $hex76= {247337383d20227a63}
		 $hex77= {247337393d20227a6e}
		 $hex78= {2473373d2022636a6a}
		 $hex79= {2473383d202263726e}
		 $hex80= {2473393d2022637a72}

	condition:
		26 of them
}
