
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Powersniff 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Powersniff {
	meta: 
		 description= "vx_underground2_Powersniff Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-13-47" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "12dadc25957270ac3717a9b8afc268b6"
		 hash2= "212522417b4c4009708c08dd0f62f15c"
		 hash3= "256f96d2b31a781888b43f5f68b10b83"
		 hash4= "2f021e0ee94d7d21df12968fffd7ea51"
		 hash5= "54e5be141a385f40505c99212bcb361e"
		 hash6= "62967bf585eef49f065bac233b506b36"
		 hash7= "654948fda9ce97a5b9fd42af1c1f2434"
		 hash8= "667f2bffa3723d003ff7fffa0d6fc5d2"
		 hash9= "727ea9ce8cb583c450a3771cd0fabd23"
		 hash10= "7b90942b853c1e39814c40accc6d4ccc"
		 hash11= "881fcbf71e02d46f90b5e359ac93ca8f"
		 hash12= "88506544fc62464cf92a0ae2b12557e5"
		 hash13= "9e85fee4dd9fbc26878f5c43aee23b0e"
		 hash14= "c52ec3aba54aaf48e144035e83d99938"
		 hash15= "d31055bf1b227b4e715272138dfeec12"
		 hash16= "dabbe915b785db82d3276d47feac0180"
		 hash17= "f0483b9cfb8deb7ff97962b30fc779ad"
		 hash18= "fba6b329876533f28d317e60fe53c8d3"

	strings:

	
 		 $s1= ",2iz*vpg,*bb,e.*:fgztza,v*j" fullword wide
		 $s2= "2i,zv,*pg,bbe*,.\\:f*,gzt*zav,j" fullword wide
		 $s3= "AhZMVWxKEDknBJRfPNYCzvati" fullword wide
		 $s4= "cGWEVSJZwBbNgiLHxkMaQCtfDlRmAh" fullword wide
		 $s5= ",c,hgengFffrpbe**C_2,3,av*J," fullword wide
		 $s6= "ch,gengF,ffrp*beC*_,23a*v,J" fullword wide
		 $s7= "C:UsersuserDocuments1123whGXxju.png" fullword wide
		 $s8= "DocumentSummaryInformation" fullword wide
		 $s9= "dowsSysWOW64stdole2.tlb#OLE Automation" fullword wide
		 $s10= "ebuXCoJDRPHMrsaYyzNwOkQKZqfpAVcEjnlShtTGmxFvWULg" fullword wide
		 $s11= "eGkBZCMjmNUqfiOLaFIrbXuxY" fullword wide
		 $s12= "eskhKouiyjlHTxIMGDbWfNVEUagBdzYSRqntLQFPJvrO" fullword wide
		 $s13= "eTxpvHqDGnuXRgaBmEWMwzjSdhZFPsUYCJtyILQ" fullword wide
		 $s14= "ff,rp*b*eC*_23a,v*J:*2i,,z*v,p*g,bbe**.,\\*:f*,gz*tzavj" fullword wide
		 $s15= "*ff**rpbe*C_2,3a*v,J:*2izvp*g*b*be**.,*:fgzt,*zav*j" fullword wide
		 $s16= "*G{000204EF-0_VBA_PROJECT" fullword wide
		 $s17= "*G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.5#0#C:Prodir" fullword wide
		 $s18= "GOhvEiaPgMuLScQbNtUKZrTRHAYezVJDkpXwymIWdo" fullword wide
		 $s19= "hMIGbqLnTWCDepgAxPRtwZifJBEsSrvQFmNXjuzUYdyOa" fullword wide
		 $s20= "http://go.microsoft.com/fwlink/?LinkId=316963" fullword wide
		 $s21= "http://go.microsoft.com/fwlink/?LinkId=316964" fullword wide
		 $s22= "https://go.microsoft.com/fwlink/p/?LinkId=316967" fullword wide
		 $s23= "https://go.microsoft.com/fwlink/p/?LinkId=316968" fullword wide
		 $s24= "https://go.microsoft.com/fwlink/p/?LinkId=316970" fullword wide
		 $s25= "https://go.microsoft.com/fwlink/p/?LinkId=316971" fullword wide
		 $s26= "imlUsBkXYQAJRzeZHoICjGONFbxDMdwgtpuPSVKcnEar" fullword wide
		 $s27= "IUCZxOjXWdSNieRmwQfqbJTAMVvYHPDEBtuL" fullword wide
		 $s28= "IUCZxOjXWdSNieRmwQfqbJTAMVvYHPDEBtuLKFszckpGgnroy" fullword wide
		 $s29= "jqORKuwkgCzUZDcYNlMmFeyoEAdBVhSHibWIvftnxTXLaQJ" fullword wide
		 $s30= "jrptQhLZvXEblMkxdCsYSFaOq" fullword wide
		 $s31= "KjUpBZkEJTyPHaOowrbtAYzSVXxqQDWvf" fullword wide
		 $s32= "KrsAZtckOphDvFQNUGyjwldMPaRqHJu" fullword wide
		 $s33= "kSiPKswQJTZbAcLBxvUYferIgGqMmhanEdDOlN" fullword wide
		 $s34= "KuqxmFJVYztGwRBUksXpPZhfiOcoECjrNvL" fullword wide
		 $s35= "MdjclxOqPuseobmHZwDAKJiSQrRfyapnkCvYTWNtg" fullword wide
		 $s36= "microsoft-word-2016-mac-icon-100597392-gallery" fullword wide
		 $s37= "oKNmbldAYTxJsHQFuIBrDEpGUZhgqzeRnXCWOySPavLkcf" fullword wide
		 $s38= "Project.NewMacros.AutoOpen" fullword wide
		 $s39= "PvVflDTqIMxEndyeKpUNtOkwjZsgGSRCYFcmBuzrobaHh " fullword wide
		 $s40= "rHUWBKdqhmAeXayscQFuVGxMjPCtfwkNZvoE" fullword wide
		 $s41= "RzkaNSopOwLTbKvFjxfHhPnBYqyDreMCIQEGcZum " fullword wide
		 $s42= "TiGERnMcPBDUtlxfIhmqdSzoKLpVQJWbsHaXuyvr" fullword wide
		 $s43= "tSrgeJlaypIDcxHOumCMsAUvRzY" fullword wide
		 $s44= "VGqyOzPjXsBcZtFbSmauwdEUCgovTnYlkhpeiLDxWJIHQKfrAR" fullword wide
		 $s45= "vrnLGzDYVqNmbAtCMPHKXsfWlyhuc" fullword wide
		 $s46= "WgoBwlYHIJLCDimXFKcbMrAphNeuZzVfdnqjxO" fullword wide
		 $s47= "wtaTlLRKeOVGmkuvjxECrhQoYsI" fullword wide
		 $s48= "xseYPGdtopBWIUJNqgKCzEfiVHuAcbjSmTLO" fullword wide
		 $s49= "ZbsugCTwxeYaBoRIJNiSjpVrmzPdUcQFqGWAvM" fullword wide
		 $a1= ",ffr,p*be*C,*_23*a*v,J,:*2i*,zv,p*g,b*b,e*.*,\\:*f*gztz*a,vj" fullword ascii
		 $a2= "ff,rp*b*eC*_23a,v*J:*2i,,z*v,p*g,bbe**.,\\*:f*,gz*tzavj AibG" fullword ascii

		 $hex1= {2461313d20222c6666}
		 $hex2= {2461323d202266662c}
		 $hex3= {247331303d20226562}
		 $hex4= {247331313d20226547}
		 $hex5= {247331323d20226573}
		 $hex6= {247331333d20226554}
		 $hex7= {247331343d20226666}
		 $hex8= {247331353d20222a66}
		 $hex9= {247331363d20222a47}
		 $hex10= {247331373d20222a47}
		 $hex11= {247331383d2022474f}
		 $hex12= {247331393d2022684d}
		 $hex13= {2473313d20222c3269}
		 $hex14= {247332303d20226874}
		 $hex15= {247332313d20226874}
		 $hex16= {247332323d20226874}
		 $hex17= {247332333d20226874}
		 $hex18= {247332343d20226874}
		 $hex19= {247332353d20226874}
		 $hex20= {247332363d2022696d}
		 $hex21= {247332373d20224955}
		 $hex22= {247332383d20224955}
		 $hex23= {247332393d20226a71}
		 $hex24= {2473323d202232692c}
		 $hex25= {247333303d20226a72}
		 $hex26= {247333313d20224b6a}
		 $hex27= {247333323d20224b72}
		 $hex28= {247333333d20226b53}
		 $hex29= {247333343d20224b75}
		 $hex30= {247333353d20224d64}
		 $hex31= {247333363d20226d69}
		 $hex32= {247333373d20226f4b}
		 $hex33= {247333383d20225072}
		 $hex34= {247333393d20225076}
		 $hex35= {2473333d202241685a}
		 $hex36= {247334303d20227248}
		 $hex37= {247334313d2022527a}
		 $hex38= {247334323d20225469}
		 $hex39= {247334333d20227453}
		 $hex40= {247334343d20225647}
		 $hex41= {247334353d20227672}
		 $hex42= {247334363d20225767}
		 $hex43= {247334373d20227774}
		 $hex44= {247334383d20227873}
		 $hex45= {247334393d20225a62}
		 $hex46= {2473343d2022634757}
		 $hex47= {2473353d20222c632c}
		 $hex48= {2473363d202263682c}
		 $hex49= {2473373d2022433a55}
		 $hex50= {2473383d2022446f63}
		 $hex51= {2473393d2022646f77}

	condition:
		34 of them
}
