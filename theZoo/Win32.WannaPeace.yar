
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_WannaPeace 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_WannaPeace {
	meta: 
		 description= "Win32_WannaPeace Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-39-27" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "eefa6f98681d78b63f15d7e58934c6cc"

	strings:

	
 		 $s1= "=>?@[]_" fullword wide
		 $s2= "$this.BackgroundImage" fullword wide
		 $s3= "17W7XEfA6gVwCpUJghVFPTwTWwwDnnRJU5" fullword wide
		 $s4= "4.12.4863.12691" fullword wide
		 $s5= "@AnonymousBr Done!!" fullword wide
		 $s6= "Arquivos totalmente" fullword wide
		 $s7= "Assembly Version" fullword wide
		 $s8= "btnDecrypt.BackgroundImage" fullword wide
		 $s9= "button4.BackgroundImage" fullword wide
		 $s10= "can't SetLength" fullword wide
		 $s11= "dd':'hh':'mm':'ss''" fullword wide
		 $s12= "FileDescription" fullword wide
		 $s13= "https://pt.wikipedia.org/wiki/Bitcoin" fullword wide
		 $s14= "https://www.mercadobitcoin.com.br/" fullword wide
		 $s15= "http://www.horacerta.com.br/" fullword wide
		 $s16= "imageList1.ImageStream" fullword wide
		 $s17= "Invalid Parameter" fullword wide
		 $s18= "LastDrive: Unknown" fullword wide
		 $s19= "LegalTrademarks" fullword wide
		 $s20= "lock_warning.ico" fullword wide
		 $s21= "o desbloqueados." fullword wide
		 $s22= "OriginalFilename" fullword wide
		 $s23= "panel1.BackgroundImage" fullword wide
		 $s24= "pictureBox1.BackgroundImage" fullword wide
		 $s25= "pictureBox2.BackgroundImage" fullword wide
		 $s26= "pictureBox3.BackgroundImage" fullword wide
		 $s27= "pictureBox4.BackgroundImage" fullword wide
		 $s28= "pictureBox5.BackgroundImage" fullword wide
		 $s29= "pictureBox6.BackgroundImage" fullword wide
		 $s30= "pnldone.BackgroundImage" fullword wide
		 $s31= "PrivateLocker.Properties.Resources" fullword wide
		 $s32= "Product: Unknown" fullword wide
		 $s33= "resstandalone.cs" fullword wide
		 $s34= "Ris3ITInGS@WannaPeace" fullword wide
		 $s35= "VERIFIQUE URGENTE!!!" fullword wide
		 $s36= "VolumeSerialNumber" fullword wide
		 $s37= "VS_VERSION_INFO" fullword wide
		 $a1= "https://pt.wikipedia.org/wiki/Bitcoin" fullword ascii

		 $hex1= {2461313d2022687474}
		 $hex2= {247331303d20226361}
		 $hex3= {247331313d20226464}
		 $hex4= {247331323d20224669}
		 $hex5= {247331333d20226874}
		 $hex6= {247331343d20226874}
		 $hex7= {247331353d20226874}
		 $hex8= {247331363d2022696d}
		 $hex9= {247331373d2022496e}
		 $hex10= {247331383d20224c61}
		 $hex11= {247331393d20224c65}
		 $hex12= {2473313d20223d3e3f}
		 $hex13= {247332303d20226c6f}
		 $hex14= {247332313d20226f20}
		 $hex15= {247332323d20224f72}
		 $hex16= {247332333d20227061}
		 $hex17= {247332343d20227069}
		 $hex18= {247332353d20227069}
		 $hex19= {247332363d20227069}
		 $hex20= {247332373d20227069}
		 $hex21= {247332383d20227069}
		 $hex22= {247332393d20227069}
		 $hex23= {2473323d2022247468}
		 $hex24= {247333303d2022706e}
		 $hex25= {247333313d20225072}
		 $hex26= {247333323d20225072}
		 $hex27= {247333333d20227265}
		 $hex28= {247333343d20225269}
		 $hex29= {247333353d20225645}
		 $hex30= {247333363d2022566f}
		 $hex31= {247333373d20225653}
		 $hex32= {2473333d2022313757}
		 $hex33= {2473343d2022342e31}
		 $hex34= {2473353d202240416e}
		 $hex35= {2473363d2022417271}
		 $hex36= {2473373d2022417373}
		 $hex37= {2473383d202262746e}
		 $hex38= {2473393d2022627574}

	condition:
		12 of them
}
