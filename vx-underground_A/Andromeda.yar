
/*
   YARA Rule Set
   Author: resteex
   Identifier: Andromeda 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Andromeda {
	meta: 
		 description= "Andromeda Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-12_23-59-40" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8bd17f87077eff55850ad48dbe69ce87"
		 hash2= "b2f86dfec72c4bf1fb4584b0fb54d2e5"
		 hash3= "e81050d5efdc8b6b9de50477cad71962"
		 hash4= "efd22a479d2e64324fad2d6e352a7266"
		 hash5= "f221ee40a190218401c6f012c0cae48e"
		 hash6= "f94158ad393ccfa6c30e699ba113eae7"

	strings:

	
 		 $s1= "ChampionAviate WellheadCricketersUpon" fullword wide
		 $s2= "ChronometerAcknowledgements.Properties.Resources" fullword wide
		 $s3= "fovemasofupiniwatoc kalecehisabiw wironanejuhoxicisopihuceter" fullword wide
		 $s4= "lihitomozecavizudovinegefi danutimir xuyatedekoxijokayewewopom" fullword wide
		 $s5= "luyokacedagus riviwatef mifayoxehumenamakevehekulavi" fullword wide
		 $s6= "migacuvodiyusicodunap jidusajifuwado fudozevusobovunoti" fullword wide
		 $s7= "pebecazahekurutelafovoyosakakume neyejopoxibuyaxikamife kahahabafekevifunuvudozavom" fullword wide
		 $s8= "tugiledetijafoxa vocogipexopege soxesoxuhehevuyisoxeyuhirogoto" fullword wide

		 $hex1= {2473313d2022436861}
		 $hex2= {2473323d2022436872}
		 $hex3= {2473333d2022666f76}
		 $hex4= {2473343d20226c6968}
		 $hex5= {2473353d20226c7579}
		 $hex6= {2473363d20226d6967}
		 $hex7= {2473373d2022706562}
		 $hex8= {2473383d2022747567}

	condition:
		1 of them
}
