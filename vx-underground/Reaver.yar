
/*
   YARA Rule Set
   Author: resteex
   Identifier: Reaver 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Reaver {
	meta: 
		 description= "Reaver Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-18-06" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "06b79a19d510c706df6324a0734c298e"
		 hash2= "11a5b1901243396984670af7acc6cf72"
		 hash3= "17587683361d8458aebd9b8fdd07137a"
		 hash4= "2d563bf83bddca1f24e8a0ffb951a7e9"
		 hash5= "47cc3592bbf8c3b516ae74c95efb3344"
		 hash6= "5eb3a846092cae378fcd45bdf5453536"
		 hash7= "6b3804bf4a75f77fec98aeb50ab24746"
		 hash8= "7dcf79a66192e88b92ccc12810e61329"
		 hash9= "892350b2a44efd9fa1e7c88aec013818"
		 hash10= "9f289cce6f95949450e3f4c96a187f5d"
		 hash11= "aab319d9715d38a37a10d82e87478dfc"
		 hash12= "ae185e9c43bb1498a3c653a0886896e3"
		 hash13= "af6a25fc28e0560860c01d74854a2cba"
		 hash14= "c629f8f3206e5a6de83b4c996a2bacfb"
		 hash15= "d07b2738840ce3419df651d3a0a3a246"
		 hash16= "dadf3d3dd411bc02d7c05ee3a18259ea"
		 hash17= "dc195d814ec16fe91690b7e949e696f6"
		 hash18= "dd7edadd019bc120978a4dad284fbea6"

	strings:

	
 		 $s1= "{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}" fullword wide
		 $s2= "[BindToClientContext]:AllocateNewContext failed." fullword wide
		 $s3= "[BindToCompletionPort]:CreateIoCompletionPort failed." fullword wide
		 $s4= "[CreateCompletionPort]:CreateIoCompletionPort failed." fullword wide
		 $s5= "JavaUpdata.dll FunctionWork`" fullword wide
		 $s6= "[OnIoWrite]:WSASend failed." fullword wide
		 $s7= "r[AllocateNewBuffer]:Allocate faled." fullword wide
		 $s8= "S-1-5-21-1705746745-4242136614-396898037-1000" fullword wide
		 $s9= "%sGoogleChromeUser DataDefault" fullword wide
		 $s10= "SoftWareMicrosoftWindowsCurrentVersionUninstall" fullword wide
		 $s11= "[StartIocpServer]:WSAStartup failed." fullword wide
		 $s12= "[StartIoWorkThread]:CreateEvent failed." fullword wide
		 $s13= "[StartIoWorkThread]:CreateThread failed." fullword wide
		 $s14= "[StartListenThread]:bind failed." fullword wide
		 $s15= "[StartListenThread]:CreateEvent failed." fullword wide
		 $s16= "[StartListenThread]:CreateThread failed." fullword wide
		 $s17= "[StartListenThread]:listen failed." fullword wide
		 $s18= "[StartListenThread]:WSACreateEvent failed." fullword wide
		 $s19= "[StartListenThread]:WSAEventSelect failed." fullword wide
		 $s20= "[ThreadListenProc]:WSAAccept INVALID_SOCKET." fullword wide
		 $a1= "[BindToCompletionPort]:CreateIoCompletionPort failed." fullword ascii
		 $a2= "[CreateCompletionPort]:CreateIoCompletionPort failed." fullword ascii
		 $a3= "SoftWareMicrosoftWindowsCurrentVersionUninstall" fullword ascii

		 $hex1= {2461313d20225b4269}
		 $hex2= {2461323d20225b4372}
		 $hex3= {2461333d2022536f66}
		 $hex4= {247331303d2022536f}
		 $hex5= {247331313d20225b53}
		 $hex6= {247331323d20225b53}
		 $hex7= {247331333d20225b53}
		 $hex8= {247331343d20225b53}
		 $hex9= {247331353d20225b53}
		 $hex10= {247331363d20225b53}
		 $hex11= {247331373d20225b53}
		 $hex12= {247331383d20225b53}
		 $hex13= {247331393d20225b53}
		 $hex14= {2473313d20227b3442}
		 $hex15= {247332303d20225b54}
		 $hex16= {2473323d20225b4269}
		 $hex17= {2473333d20225b4269}
		 $hex18= {2473343d20225b4372}
		 $hex19= {2473353d20224a6176}
		 $hex20= {2473363d20225b4f6e}
		 $hex21= {2473373d2022725b41}
		 $hex22= {2473383d2022532d31}
		 $hex23= {2473393d2022257347}

	condition:
		15 of them
}
