
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
		 date = "2022-01-14_22-50-51" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "390e66ffaccaa557a8d5c43c8f3a20a9"

	strings:

	
 		 $s1= "!),0%4()'B>/-('$)6/(//&*)$ " fullword wide
		 $s2= ">@@3" fullword wide
		 $s3= ";6/(%%).4663/+))+.1331/,++,.0110/-,*& " fullword wide
		 $s4= "6%/(-%'7RH.&;RYSBGlV]cagjuiiZdWS_oxtq^bt" fullword wide
		 $s5= "84#'" fullword wide
		 $s6= "!896=:G>I[IfSXM[\\WOqRdTaTw]hMl>mHb=_IW@N9V:b-^5P" fullword wide
		 $s7= "8EKLVadO@LF;3*':G>54GVckkwwxupd" fullword wide
		 $s8= ";96312469:98643356788761" fullword wide
		 $s9= ">?AABCEGIKMNPQRTUWY[^`acdfgikmoprsuwyz|~" fullword wide
		 $s10= "AHNPOJE@>@CGKLKHECABDFHIIGE:" fullword wide
		 $s11= "+@'B$>&=(-&!#-." fullword wide
		 $s12= "?BEHKORTWZ]`cfilorux{~" fullword wide
		 $s13= "BFJGRV[LXXAEG`fj[YbvsbuymfjrzujZCX`ZDBIZaS=?-'" fullword wide
		 $s14= "+'.;CCBFFUFPKE6:HO_fmrmmob`_tidZOPQABJMFHJDF4''" fullword wide
		 $s15= "C[ii[Of~kmnx" fullword wide
		 $s16= "CJMLHB=:;>CN" fullword wide
		 $s17= "DD?6,'&*18==:5/,+-1699741/./24665420002355432111234432-%" fullword wide
		 $s18= "@DHKNQTWZ^aehlorux|" fullword wide
		 $s19= "d]lbcgWSc~pcupgWUR^K>44*" fullword wide
		 $s20= "-@;FY_ippdb`o~~|talWwXR$" fullword wide
		 $s21= "GH?Xg_f`_WV]`UYNG;)68.$" fullword wide
		 $s22= ";@HLNJNTQG62" fullword wide
		 $s23= "JB1+1)*" fullword wide
		 $s24= "|kUV_lx~}vlc^_dkrvvrlgddgkprrpli" fullword wide
		 $s25= "':LWXO@2)->NURF7,&(1;EJHBAFOX_`UNIHJPUY?" fullword wide
		 $s26= "o]OIMYgrwtk`WSVelomhaY[^dhjifb_]^`cegfdb`W " fullword wide
		 $s27= "||s]ciqyneppsohfb_cjXXSU864F." fullword wide
		 $s28= "t_LBCN_mvul`TNNT^gllg`YTTX^cggd_[YXZ^accb_][[^`aa`_]`|" fullword wide
		 $s29= "wj_Z]dnwzyskebcgmrutplhffilpqqoljhijlnoonlkjn" fullword wide
		 $s30= "~{xvspmjheb_ZWTQNKHFC@=:741.,)&# " fullword wide
		 $s31= "ycebZNE@BHQY[VOIFGKPUWWTPLJ" fullword wide
		 $s32= "y~scgoaLA>RFlTVU[c]SJZonhvz|~" fullword wide
		 $s33= "|yvspmjgda_YVSPMJGDA>;8520-*'$!" fullword wide
		 $s34= "z`D-!%4JecWF812;HSYXQG?:P" fullword wide
		 $s35= ";ZdWfheE6ES_PA@NJNTddlsqthr" fullword wide
		 $a1= "!896=:G>I[IfSXM[\\WOqRdTaTw]hMl>mHb=_IW@N9V:b-^5P" fullword ascii
		 $a2= ";96312469:98643356788761" fullword ascii
		 $a3= ">?AABCEGIKMNPQRTUWY[^`acdfgikmoprsuwyz|~" fullword ascii
		 $a4= "AHNPOJE@>@CGKLKHECABDFHIIGE:" fullword ascii
		 $a5= "DD?6,'&*18==:5/,+-1699741/./24665420002355432111234432-%" fullword ascii
		 $a6= "t_LBCN_mvul`TNNT^gllg`YTTX^cggd_[YXZ^accb_][[^`aa`_]`|" fullword ascii

		 $hex1= {2461313d2022213839}
		 $hex2= {2461323d20223b3936}
		 $hex3= {2461333d20223e3f41}
		 $hex4= {2461343d202241484e}
		 $hex5= {2461353d202244443f}
		 $hex6= {2461363d2022745f4c}
		 $hex7= {247331303d20224148}
		 $hex8= {247331313d20222b40}
		 $hex9= {247331323d20223f42}
		 $hex10= {247331333d20224246}
		 $hex11= {247331343d20222b27}
		 $hex12= {247331353d2022435b}
		 $hex13= {247331363d2022434a}
		 $hex14= {247331373d20224444}
		 $hex15= {247331383d20224044}
		 $hex16= {247331393d2022645d}
		 $hex17= {2473313d202221292c}
		 $hex18= {247332303d20222d40}
		 $hex19= {247332313d20224748}
		 $hex20= {247332323d20223b40}
		 $hex21= {247332333d20224a42}
		 $hex22= {247332343d20227c6b}
		 $hex23= {247332353d2022273a}
		 $hex24= {247332363d20226f5d}
		 $hex25= {247332373d20227c7c}
		 $hex26= {247332383d2022745f}
		 $hex27= {247332393d2022776a}
		 $hex28= {2473323d20223e4040}
		 $hex29= {247333303d20227e7b}
		 $hex30= {247333313d20227963}
		 $hex31= {247333323d2022797e}
		 $hex32= {247333333d20227c79}
		 $hex33= {247333343d20227a60}
		 $hex34= {247333353d20223b5a}
		 $hex35= {2473333d20223b362f}
		 $hex36= {2473343d202236252f}
		 $hex37= {2473353d2022383423}
		 $hex38= {2473363d2022213839}
		 $hex39= {2473373d202238454b}
		 $hex40= {2473383d20223b3936}
		 $hex41= {2473393d20223e3f41}

	condition:
		27 of them
}
