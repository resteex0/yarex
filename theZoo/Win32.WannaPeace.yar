
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Win32_WannaPeace 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Win32_WannaPeace {
	meta: 
		 description= "theZoo_Win32_WannaPeace Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-37-04" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "eefa6f98681d78b63f15d7e58934c6cc"

	strings:

	
 		 $s1= "=>?@[]_" fullword wide
		 $s2= "17W7XEfA6gVwCpUJghVFPTwTWwwDnnRJU5" fullword wide
		 $s3= "btnDecrypt.BackgroundImage" fullword wide
		 $s4= "https://pt.wikipedia.org/wiki/Bitcoin" fullword wide
		 $s5= "https://www.mercadobitcoin.com.br/" fullword wide
		 $s6= "http://www.horacerta.com.br/" fullword wide
		 $s7= "pictureBox1.BackgroundImage" fullword wide
		 $s8= "pictureBox2.BackgroundImage" fullword wide
		 $s9= "pictureBox3.BackgroundImage" fullword wide
		 $s10= "pictureBox4.BackgroundImage" fullword wide
		 $s11= "pictureBox5.BackgroundImage" fullword wide
		 $s12= "pictureBox6.BackgroundImage" fullword wide
		 $s13= "PrivateLocker.Properties.Resources" fullword wide

		 $hex1= {247331303d20227069}
		 $hex2= {247331313d20227069}
		 $hex3= {247331323d20227069}
		 $hex4= {247331333d20225072}
		 $hex5= {2473313d20223d3e3f}
		 $hex6= {2473323d2022313757}
		 $hex7= {2473333d202262746e}
		 $hex8= {2473343d2022687474}
		 $hex9= {2473353d2022687474}
		 $hex10= {2473363d2022687474}
		 $hex11= {2473373d2022706963}
		 $hex12= {2473383d2022706963}
		 $hex13= {2473393d2022706963}

	condition:
		8 of them
}
