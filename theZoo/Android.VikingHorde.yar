
/*
   YARA Rule Set
   Author: resteex
   Identifier: Android_VikingHorde 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Android_VikingHorde {
	meta: 
		 description= "Android_VikingHorde Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-37-13" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "390e66ffaccaa557a8d5c43c8f3a20a9"

	strings:

	
 		 $s1= "$*1:CKRX]bgmt|" fullword wide
		 $s2= "%& $1EV`^SC6/2>KA" fullword wide
		 $s3= "$/JK?+CXZfd_mldJ=NKK,!(" fullword wide
		 $s4= ":0" fullword wide
		 $s5= "#++))+.0220,(&()#" fullword wide
		 $s6= "!),0%4()'B>/-('$)6/(//&*)$ " fullword wide
		 $s7= "&/0/7??GJN'9,*." fullword wide
		 $s8= "#.0GAJV]bbigtpuhnvruq" fullword wide
		 $s9= "0NlqqC7L86@8H]og`nym?N" fullword wide
		 $s10= ":1" fullword wide
		 $s11= "1LftsdN9*&->ThO" fullword wide
		 $s12= ",-++1>MX[VL@724?G?' " fullword wide
		 $s13= "%.20,.8DPUSKA946;CJM9" fullword wide
		 $s14= "&2-4241'5&8,0QI=?NRRA[e" fullword wide
		 $s15= ">@@3" fullword wide
		 $s16= "*37FYipmaUQVamiI#" fullword wide
		 $s17= "3@MYchgaXPLMS[XH'" fullword wide
		 $s18= "*3;PZHQPfY_Ybcdbiivzz||" fullword wide
		 $s19= "'&&46.8ELI[hgZdj" fullword wide
		 $s20= "%5HVTLLOQQPLIFFGILNOL2" fullword wide
		 $s21= "5Wb[QOU_jqsof^XVY`]C" fullword wide
		 $s22= "60*%" fullword wide
		 $s23= ";6/(%%).4663/+))+.1331/,++,.0110/-,*& " fullword wide
		 $s24= "6%/(-%'7RH.&;RYSBGlV]cagjuiiZdWS_oxtq^bt" fullword wide
		 $s25= "(6?C@;76:BMW_bcb`belt|" fullword wide
		 $s26= ".=%(6MKWVcmfj}" fullword wide
		 $s27= "73.)% " fullword wide
		 $s28= "78&+3:&" fullword wide
		 $s29= "84#'" fullword wide
		 $s30= "!896=:G>I[IfSXM[\\WOqRdTaTw]hMl>mHb=_IW@N9V:b-^5P" fullword wide
		 $s31= "8EKLVadO@LF;3*':G>54GVckkwwxupd" fullword wide
		 $s32= ";96312469:98643356788761" fullword wide
		 $s33= ">?AABCEGIKMNPQRTUWY[^`acdfgikmoprsuwyz|~" fullword wide
		 $s34= "*?A;EP@USTQWRQOM/%" fullword wide
		 $s35= "AHNPOJE@>@CGKLKHECABDFHIIGE:" fullword wide
		 $s36= "]^ambQX`gXBM_iM72789/" fullword wide
		 $s37= "+@'B$>&=(-&!#-." fullword wide
		 $s38= "?BEHKORTWZ]`cfilorux{~" fullword wide
		 $s39= "beqkX@.%)6GW^[PB7." fullword wide
		 $s40= "BFJGRV[LXXAEG`fj[YbvsbuymfjrzujZCX`ZDBIZaS=?-'" fullword wide
		 $s41= "+'.;CCBFFUFPKE6:HO_fmrmmob`_tidZOPQABJMFHJDF4''" fullword wide
		 $s42= "CEB;1$" fullword wide
		 $s43= "C[ii[Of~kmnx" fullword wide
		 $s44= "CJMLHB=:;>CN" fullword wide
		 $s45= "CJOQNIC?>?CB8*" fullword wide
		 $s46= "com.Jump.vikingJump" fullword wide
		 $s47= "DD?6,'&*18==:5/,+-1699741/./24665420002355432111234432-%" fullword wide
		 $s48= "!.;DFA>DQ_hkf_ZQC3 " fullword wide
		 $s49= "@DHKNQTWZ^aehlorux|" fullword wide
		 $s50= "d]lbcgWSc~pcupgWUR^K>44*" fullword wide
		 $s51= "'./)##.D]pxveJ0" fullword wide
		 $s52= "?DRH^WWO^|tr|n`JEWtcJA*" fullword wide
		 $s53= "%Ectq^D/'.?WfaE" fullword wide
		 $s54= "!+FU@4kwq]bjhbOIGGs" fullword wide
		 $s55= "-@;FY_ippdb`o~~|talWwXR$" fullword wide
		 $s56= "GH?Xg_f`_WV]`UYNG;)68.$" fullword wide
		 $s57= "(HcnhS;( $2F]sv])" fullword wide
		 $s58= ";@HLNJNTQG62" fullword wide
		 $s59= "JB1+1)*" fullword wide
		 $s60= "'J[QJJ/)4355;06>[|" fullword wide
		 $s61= "+K6$ *=Scg_N=5@" fullword wide
		 $s62= "|kUV_lx~}vlc^_dkrvvrlgddgkprrpli" fullword wide
		 $s63= "':LWXO@2)->NURF7,&(1;EJHBAFOX_`UNIHJPUY?" fullword wide
		 $s64= ",Mkyt_D/%(7M^]H'" fullword wide
		 $s65= "`mXxzUKKgyzywJ[c^@" fullword wide
		 $s66= "N_fkfedt}vpw|z" fullword wide
		 $s67= "#:N[]TE6-+.379852%" fullword wide
		 $s68= "o]OIMYgrwtk`WSVelomhaY[^dhjifb_]^`cegfdb`W " fullword wide
		 $s69= ",@ORI9*#&2BP^jjK" fullword wide
		 $s70= "Pgw}vfUGCHTblplcXPU" fullword wide
		 $s71= "~qeZ`isz{wphcadjptusoeA" fullword wide
		 $s72= "q^[lzq[B1,3CVdicVG," fullword wide
		 $s73= "qW:'#.CYhkcSB639FS^ZQA-" fullword wide
		 $s74= "rjdS^kapn{vjwuw" fullword wide
		 $s75= "rpoceZQbhXB135," fullword wide
		 $s76= "||s]ciqyneppsohfb_cjXXSU864F." fullword wide
		 $s77= "#;SM]yk`K:0*/53(;Ecn" fullword wide
		 $s78= ":SQ[UUEHnpNO>ECG9,1L9" fullword wide
		 $s79= "tcZ[`GGMZbSU;A/" fullword wide
		 $s80= "t^ieihjai`TgPhPh7U1" fullword wide
		 $s81= "t_LBCN_mvul`TNNT^gllg`YTTX^cggd_[YXZ^accb_][[^`aa`_]`|" fullword wide
		 $s82= "tna_cdMF;K6(',%" fullword wide
		 $s83= "ulf^WSSW]_YL>3./+" fullword wide
		 $s84= "(?VeeYF4*)2?MVP" fullword wide
		 $s85= "vJNhz~s_K>;BP]R5" fullword wide
		 $s86= "}vmebchouxwsmhI" fullword wide
		 $s87= "WFIUesyvmaVQSZdlpoib[X4" fullword wide
		 $s88= "wj_Z]dnwzyskebcgmrutplhffilpqqoljhijlnoonlkjn" fullword wide
		 $s89= "|wtbha[RYYfNTXbpdgbQdiek" fullword wide
		 $s90= "wYm{kd`jkV@)00(5$,5@" fullword wide
		 $s91= "}xsojfaXSNIE@;72-($" fullword wide
		 $s92= "~{xvspmjheb_ZWTQNKHFC@=:741.,)&# " fullword wide
		 $s93= "xxlfcfPE;;9-*531" fullword wide
		 $s94= "ycebZNE@BHQY[VOIFGKPUWWTPLJ" fullword wide
		 $s95= "y~scgoaLA>RFlTVU[c]SJZonhvz|~" fullword wide
		 $s96= "|yvspmjgda_YVSPMJGDA>;8520-*'$!" fullword wide
		 $s97= "z`D-!%4JecWF812;HSYXQG?:P" fullword wide
		 $s98= ";ZdWfheE6ES_PA@NJNTddlsqthr" fullword wide
		 $s99= "zupkfaWRMID?:5/+&!" fullword wide
		 $a1= ">@@3" fullword ascii
		 $a2= ";6/(%%).4663/+))+.1331/,++,.0110/-,*& " fullword ascii
		 $a3= "6%/(-%'7RH.&;RYSBGlV]cagjuiiZdWS_oxtq^bt" fullword ascii
		 $a4= "!896=:G>I[IfSXM[\\WOqRdTaTw]hMl>mHb=_IW@N9V:b-^5P" fullword ascii
		 $a5= "8EKLVadO@LF;3*':G>54GVckkwwxupd" fullword ascii
		 $a6= ";96312469:98643356788761" fullword ascii
		 $a7= ">?AABCEGIKMNPQRTUWY[^`acdfgikmoprsuwyz|~" fullword ascii
		 $a8= "AHNPOJE@>@CGKLKHECABDFHIIGE:" fullword ascii
		 $a9= "BFJGRV[LXXAEG`fj[YbvsbuymfjrzujZCX`ZDBIZaS=?-'" fullword ascii
		 $a10= "+'.;CCBFFUFPKE6:HO_fmrmmob`_tidZOPQABJMFHJDF4''" fullword ascii
		 $a11= "DD?6,'&*18==:5/,+-1699741/./24665420002355432111234432-%" fullword ascii
		 $a12= ";@HLNJNTQG62" fullword ascii
		 $a13= "':LWXO@2)->NURF7,&(1;EJHBAFOX_`UNIHJPUY?" fullword ascii
		 $a14= "o]OIMYgrwtk`WSVelomhaY[^dhjifb_]^`cegfdb`W " fullword ascii
		 $a15= "t_LBCN_mvul`TNNT^gllg`YTTX^cggd_[YXZ^accb_][[^`aa`_]`|" fullword ascii
		 $a16= "wj_Z]dnwzyskebcgmrutplhffilpqqoljhijlnoonlkjn" fullword ascii

		 $hex1= {246131303d20222b27}
		 $hex2= {246131313d20224444}
		 $hex3= {246131323d20223b40}
		 $hex4= {246131333d2022273a}
		 $hex5= {246131343d20226f5d}
		 $hex6= {246131353d2022745f}
		 $hex7= {246131363d2022776a}
		 $hex8= {2461313d20223e4040}
		 $hex9= {2461323d20223b362f}
		 $hex10= {2461333d202236252f}
		 $hex11= {2461343d2022213839}
		 $hex12= {2461353d202238454b}
		 $hex13= {2461363d20223b3936}
		 $hex14= {2461373d20223e3f41}
		 $hex15= {2461383d202241484e}
		 $hex16= {2461393d202242464a}
		 $hex17= {247331303d20223a31}
		 $hex18= {247331313d2022314c}
		 $hex19= {247331323d20222c2d}
		 $hex20= {247331333d2022252e}
		 $hex21= {247331343d20222632}
		 $hex22= {247331353d20223e40}
		 $hex23= {247331363d20222a33}
		 $hex24= {247331373d20223340}
		 $hex25= {247331383d20222a33}
		 $hex26= {247331393d20222726}
		 $hex27= {2473313d2022242a31}
		 $hex28= {247332303d20222535}
		 $hex29= {247332313d20223557}
		 $hex30= {247332323d20223630}
		 $hex31= {247332333d20223b36}
		 $hex32= {247332343d20223625}
		 $hex33= {247332353d20222836}
		 $hex34= {247332363d20222e3d}
		 $hex35= {247332373d20223733}
		 $hex36= {247332383d20223738}
		 $hex37= {247332393d20223834}
		 $hex38= {2473323d2022252620}
		 $hex39= {247333303d20222138}
		 $hex40= {247333313d20223845}
		 $hex41= {247333323d20223b39}
		 $hex42= {247333333d20223e3f}
		 $hex43= {247333343d20222a3f}
		 $hex44= {247333353d20224148}
		 $hex45= {247333363d20225d5e}
		 $hex46= {247333373d20222b40}
		 $hex47= {247333383d20223f42}
		 $hex48= {247333393d20226265}
		 $hex49= {2473333d2022242f4a}
		 $hex50= {247334303d20224246}
		 $hex51= {247334313d20222b27}
		 $hex52= {247334323d20224345}
		 $hex53= {247334333d2022435b}
		 $hex54= {247334343d2022434a}
		 $hex55= {247334353d2022434a}
		 $hex56= {247334363d2022636f}
		 $hex57= {247334373d20224444}
		 $hex58= {247334383d2022212e}
		 $hex59= {247334393d20224044}
		 $hex60= {2473343d20223a3022}
		 $hex61= {247335303d2022645d}
		 $hex62= {247335313d2022272e}
		 $hex63= {247335323d20223f44}
		 $hex64= {247335333d20222545}
		 $hex65= {247335343d2022212b}
		 $hex66= {247335353d20222d40}
		 $hex67= {247335363d20224748}
		 $hex68= {247335373d20222848}
		 $hex69= {247335383d20223b40}
		 $hex70= {247335393d20224a42}
		 $hex71= {2473353d2022232b2b}
		 $hex72= {247336303d2022274a}
		 $hex73= {247336313d20222b4b}
		 $hex74= {247336323d20227c6b}
		 $hex75= {247336333d2022273a}
		 $hex76= {247336343d20222c4d}
		 $hex77= {247336353d2022606d}
		 $hex78= {247336363d20224e5f}
		 $hex79= {247336373d2022233a}
		 $hex80= {247336383d20226f5d}
		 $hex81= {247336393d20222c40}
		 $hex82= {2473363d202221292c}
		 $hex83= {247337303d20225067}
		 $hex84= {247337313d20227e71}
		 $hex85= {247337323d2022715e}
		 $hex86= {247337333d20227157}
		 $hex87= {247337343d2022726a}
		 $hex88= {247337353d20227270}
		 $hex89= {247337363d20227c7c}
		 $hex90= {247337373d2022233b}
		 $hex91= {247337383d20223a53}
		 $hex92= {247337393d20227463}
		 $hex93= {2473373d2022262f30}
		 $hex94= {247338303d2022745e}
		 $hex95= {247338313d2022745f}
		 $hex96= {247338323d2022746e}
		 $hex97= {247338333d2022756c}
		 $hex98= {247338343d2022283f}
		 $hex99= {247338353d2022764a}
		 $hex100= {247338363d20227d76}
		 $hex101= {247338373d20225746}
		 $hex102= {247338383d2022776a}
		 $hex103= {247338393d20227c77}
		 $hex104= {2473383d2022232e30}
		 $hex105= {247339303d20227759}
		 $hex106= {247339313d20227d78}
		 $hex107= {247339323d20227e7b}
		 $hex108= {247339333d20227878}
		 $hex109= {247339343d20227963}
		 $hex110= {247339353d2022797e}
		 $hex111= {247339363d20227c79}
		 $hex112= {247339373d20227a60}
		 $hex113= {247339383d20223b5a}
		 $hex114= {247339393d20227a75}
		 $hex115= {2473393d2022304e6c}

	condition:
		38 of them
}
