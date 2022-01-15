
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
		 date = "2022-01-14_20-55-27" 
		 license = "https://github.com/resteex0/yarex"
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
		 $a1= "ActiveScriptEventConsumer.Name='ProbeScriptFint'" fullword ascii
		 $a2= "__EventFilter.Name='ProbeScriptFint'" fullword ascii

		 $hex1= {2461313d2022416374}
		 $hex2= {2461323d20225f5f45}
		 $hex3= {2473313d2022416374}
		 $hex4= {2473323d2022416374}
		 $hex5= {2473333d20225f5f45}
		 $hex6= {2473343d20225f5f46}
		 $hex7= {2473353d2022496e74}
		 $hex8= {2473363d20225f5f49}
		 $hex9= {2473373d202250726f}
		 $hex10= {2473383d2022536372}

	condition:
		1 of them
}
