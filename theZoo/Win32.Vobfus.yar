
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Win32_Vobfus 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Win32_Vobfus {
	meta: 
		 description= "theZoo_Win32_Vobfus Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-37-03" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "4e15d812491ff0454f1e9393675b1c60"
		 hash2= "634aa845f5b0b519b6d8a8670b994906"
		 hash3= "70f0b7bd55b91de26f9ed6f1ef86b456"
		 hash4= "7b19b2b8aed0285eb2b2c5cb81313569"

	strings:

	
 		 $s1= "ajlxwcgachfqbkcpfxukkweqsgykpf" fullword wide
		 $s2= "bpbjtchitthvkhtquiyvkbkrnth" fullword wide
		 $s3= "bqqdroyycfihslhpoohqzytalnyl" fullword wide
		 $s4= "cjjmffglaxhstwokjiyxyvugu" fullword wide
		 $s5= "czromwcfyolrisrojppfcvfil" fullword wide
		 $s6= "dpmhkmbnojztbrkllddazbqkdx" fullword wide
		 $s7= "dzybttvipbyvoflasaunpccmbehyni" fullword wide
		 $s8= "emgkgtgnnmnmninigthkgogggvmkhinjggnvm" fullword wide
		 $s9= "gbqmsfnimhckffqnucokvofbklmi" fullword wide
		 $s10= "gcezfgwpahpyzajsgnexyvlcf" fullword wide
		 $s11= "krztyrxztfbhksedarmphjgssyhtx" fullword wide
		 $s12= "kzowkgptylrzzeydvlydewyqiavmz" fullword wide
		 $s13= "lrmsqxiliqtyizqqwyorcvbon" fullword wide
		 $s14= "lsdkfcnlxikjlwrybamxrsocv" fullword wide
		 $s15= "lvwgetyigyadtsiwloxsxwvhlc" fullword wide
		 $s16= "muagphipprtuypesinyszfgtavhhb" fullword wide
		 $s17= "nrcfpfvozvjocicnucplpeqnihyrz" fullword wide
		 $s18= "qceljixltaoyeavvrwuairuier" fullword wide
		 $s19= "qicjuorvmpdmzxolgufmifdojqn" fullword wide
		 $s20= "rkzptfefareoehrsovnixbifxigks" fullword wide
		 $s21= "swqrmywpcdvimjpbehhykhnihtc" fullword wide
		 $s22= "tbqbzkwlidxtoftccgxkyzlzw" fullword wide
		 $s23= "tlssdwplvekyhesfbfgunyxlg" fullword wide
		 $s24= "ufnwijyaydcfcfjjhokaobjlw" fullword wide
		 $s25= "wirmplmnjkgwovkaerbjayzcgak" fullword wide
		 $s26= "wxcukmhbcunqkteuswadqhajkh" fullword wide
		 $s27= "yofryblhwegljnargkhbsdaggtpso" fullword wide

		 $hex1= {247331303d20226763}
		 $hex2= {247331313d20226b72}
		 $hex3= {247331323d20226b7a}
		 $hex4= {247331333d20226c72}
		 $hex5= {247331343d20226c73}
		 $hex6= {247331353d20226c76}
		 $hex7= {247331363d20226d75}
		 $hex8= {247331373d20226e72}
		 $hex9= {247331383d20227163}
		 $hex10= {247331393d20227169}
		 $hex11= {2473313d2022616a6c}
		 $hex12= {247332303d2022726b}
		 $hex13= {247332313d20227377}
		 $hex14= {247332323d20227462}
		 $hex15= {247332333d2022746c}
		 $hex16= {247332343d20227566}
		 $hex17= {247332353d20227769}
		 $hex18= {247332363d20227778}
		 $hex19= {247332373d2022796f}
		 $hex20= {2473323d2022627062}
		 $hex21= {2473333d2022627171}
		 $hex22= {2473343d2022636a6a}
		 $hex23= {2473353d2022637a72}
		 $hex24= {2473363d202264706d}
		 $hex25= {2473373d2022647a79}
		 $hex26= {2473383d2022656d67}
		 $hex27= {2473393d2022676271}

	condition:
		18 of them
}
