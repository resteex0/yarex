
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Blackhole_EK 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Blackhole_EK {
	meta: 
		 description= "vx_underground2_Blackhole_EK Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-53-46" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "02d8e6daef5a4723621c25cfb766a23d"
		 hash2= "06997228f2769859ef5e4cd8a454d650"
		 hash3= "06ba331ac5ae3cd1986c82cb1098029e"
		 hash4= "0d3acb5285cfe071e30be051d2aaf28a"
		 hash5= "0d95c666ea5d5c28fca5381bd54304b3"
		 hash6= "103ef0314607d28b3c54cd07e954cb25"
		 hash7= "10ce7956266bfd98fe310d7568bfc9d0"
		 hash8= "11062eea9b7f2a2675c1e60047e8735c"
		 hash9= "16c002dc45976caae259d7cabc95b2c3"
		 hash10= "17ab5b85f2e1f2b5da436555ea94f859"
		 hash11= "1967503a69a594c18314fefae0f4b1c6"
		 hash12= "1c78d96bb8d8f8a71294bc1e6d374b0f"
		 hash13= "1e2ba0176787088e3580dfce0245bc16"
		 hash14= "25a87e6da4baa57a9d6a2cdcb2d43249"
		 hash15= "287dca9469c8f7f0cb6e5bdd9e2055cd"
		 hash16= "2e72a317d07aa1603f8d138787a2c582"
		 hash17= "386cb76d46b281778c8c54ac001d72dc"
		 hash18= "3bda0765cf990a351ceb96e23d5423da"
		 hash19= "3f47452c1e40f68160beff4bb2a3e5f4"
		 hash20= "40db66bf212dd953a169752ba9349c6a"
		 hash21= "425ebdfcf03045917d90878d264773d2"
		 hash22= "467199178ac940ca311896c7d116954f"
		 hash23= "4bdfff8de0bb5ea2d623333a4a82c7f9"
		 hash24= "4ec720cfafabd1c9b1034bb82d368a30"
		 hash25= "5189b77b98f59a0592f623e10d8b761f"
		 hash26= "530d31a0c45b79c1ee0c5c678e242c02"
		 hash27= "58265fc893ed5a001e3a7c925441298c"
		 hash28= "60024caf40f4239d7e796916fb52dc8c"
		 hash29= "6702efdee17e0cd6c29349978961d9fa"
		 hash30= "6f27377115ba5fd59f007d2cb3f50b35"
		 hash31= "6f4c64a1293c03c9f881a4ef4e1491b3"
		 hash32= "705e2d7e6b721a90c65cc2625e17ac47"
		 hash33= "7b6cdc67077fc3ca75a54dea0833afe3"
		 hash34= "7cbb58412554327fe8b643204a046e2b"
		 hash35= "82f108d4e6f997f8fc4cc02aad02629a"
		 hash36= "83704d531c9826727016fec285675eb1"
		 hash37= "86946ec2d2031f2b456e804cac4ade6d"
		 hash38= "8f8e8fc17dc4892e7284aba53b42d3e6"
		 hash39= "9236e7f96207253b4684f3497bcd2b3d"
		 hash40= "926429bf5fe1fbd531eb100fc6e53524"
		 hash41= "92e21e491a90e24083449fd906515684"
		 hash42= "9440d49e1ed0794c90547758ef6023f7"
		 hash43= "95c6462d0f21181c5003e2a74c8d3529"
		 hash44= "9664a16c65782d56f02789e7d52359cd"
		 hash45= "98b302a504a7ad0e3515ab6b96d623f9"
		 hash46= "9bc9f925f60bd8a7b632ae3a6147cb9e"
		 hash47= "a09bcf1a1bdabe4e6e7e52e7f8898012"
		 hash48= "a15417c132e2bdecd63743f399c170c4"
		 hash49= "a5f94d7bdeb88b57be67132473e48286"
		 hash50= "a899dedb50ad81d9dbba660747828c7b"
		 hash51= "a91d885ef4c4a0d16c88b956db9c6f43"
		 hash52= "b43b6a1897c2956c2a0c9407b74c4232"
		 hash53= "b85e083660c04114f3d339946d83d20e"
		 hash54= "bd819c3714dffb5d4988d2f19d571918"
		 hash55= "c104eef553bb63f561207d2ddbe587a5"
		 hash56= "c3c35e465e316a71abccca296ff6cd22"
		 hash57= "c7abd2142f121bd64e55f145d4b860fa"
		 hash58= "c7b417a4d650c72efebc2c45eefbac2a"
		 hash59= "cede690558887af115154b94044139e6"
		 hash60= "d8336f7ae9b3a4db69317aea105f49be"
		 hash61= "dadf69ce2124283a59107708ffa9c900"
		 hash62= "e89b56df597688c489f06a0a6dd9efed"
		 hash63= "eba5daf0442dff5b249274c99552177b"
		 hash64= "ecd7d11dc9bb6ee842e2a2dce56edc6f"
		 hash65= "f5e16a6cd2c2ac71289aaf1c087224ee"
		 hash66= "f7ffe1fd1a57d337a04d3c777cddc065"
		 hash67= "fccb8f71663620a5a8b53dcfb396cfb5"
		 hash68= "fd84d695ac3f2ebfb98d3255b3a4e1de"

	strings:

	
 		 $s1= "@10550,10551;1;0;;0,128,128" fullword wide
		 $a1= "7IWWFA3DBOWWG5OLqKFD..@qCAD..FAsWaWVISTlArbBOSTlIWT|ArDBOWT" fullword ascii
		 $a2= "H}Sl.}Wl5PLlP]=l56=A21Wl5]=b=DGlP]=maO5Dpswl5]=N5PLb.bGl.SarbTD" fullword ascii

		 $hex1= {2461313d2022374957}
		 $hex2= {2461323d2022487d53}
		 $hex3= {2473313d2022403130}

	condition:
		2 of them
}
