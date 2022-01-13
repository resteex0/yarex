
/*
   YARA Rule Set
   Author: resteex
   Identifier: BandarChor_Ransomware 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_BandarChor_Ransomware {
	meta: 
		 description= "BandarChor_Ransomware Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-13_15-14-40" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "226b276b333804a0a5aac78d8e11ddf0"
		 hash2= "5f7e9108d4fa09a6cd9c89f39bb51229"
		 hash3= "5fab6fbdff1a72cd5eafdd27b5ee11a9"
		 hash4= "7c9ee8c189f40e2f9ebd2660a2d2f65d"
		 hash5= "81597a3dca5e7302766352fdcc2637a2"
		 hash6= "8ac04f77862e7778b0950e2beb397b79"
		 hash7= "9146ae0009e78aa23b05850a9027a9f8"

	strings:

	
 		 $s1= "055056052052054053054067054057054068" fullword wide
		 $s2= "28C4C820-401A-101B-A3C9-08002B2F49FB" fullword wide
		 $s3= "78E1BDD1-9941-11cf-9756-00AA00C00908" fullword wide
		 $s4= "C4145310-469C-11d1-B182-00A0C922E820" fullword wide
		 $s5= "dD1B20A40-59D5-101B-A3C9-08002B2F49FB" fullword wide
		 $s6= "E3920CD0-1C87-11d0-8E8A-00A0C90F26F8" fullword wide
		 $s7= "e72E67120-5959-11cf-91F6-C2863C385E30" fullword wide
		 $s8= "emgkgtgnnmnmninigthkgogggvmkhinjggnvm" fullword wide
		 $s9= "mgkgtgnnmnmninigthkgogggvmkhinjggnvm" fullword wide
		 $s10= "r1F3D5522-3F42-11d1-B2FA-00A0C908FB55" fullword wide

		 $hex1= {247331303d20227231}
		 $hex2= {2473313d2022303535}
		 $hex3= {2473323d2022323843}
		 $hex4= {2473333d2022373845}
		 $hex5= {2473343d2022433431}
		 $hex6= {2473353d2022644431}
		 $hex7= {2473363d2022453339}
		 $hex8= {2473373d2022653732}
		 $hex9= {2473383d2022656d67}
		 $hex10= {2473393d20226d676b}

	condition:
		1 of them
}
