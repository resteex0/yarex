
/*
   YARA Rule Set
   Author: resteex
   Identifier: NetWire_RAT 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_NetWire_RAT {
	meta: 
		 description= "NetWire_RAT Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-15-52" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "35a80e79a290dfce0d019d467ec8dc9c"
		 hash2= "51e38c5c7a3a24dd8092f94d915de981"
		 hash3= "5413d7925b6e67e27e6ffdab67974dbf"
		 hash4= "587f6655380282c9fb7997fa2225438e"

	strings:

	
 		 $s1= "B8B4B0B,B(B$B B" fullword wide
		 $s2= "btnBezier.BackgroundImage" fullword wide
		 $s3= "btnCircle.BackgroundImage" fullword wide
		 $s4= "btnSelect.BackgroundImage" fullword wide
		 $s5= "btnSquare.BackgroundImage" fullword wide
		 $s6= "ConsoleApp42.Properties.Resources" fullword wide
		 $s7= "NavigationLib.Properties.Resources" fullword wide
		 $s8= "openFileDialog1.TrayLocation" fullword wide

		 $hex1= {2473313d2022423842}
		 $hex2= {2473323d202262746e}
		 $hex3= {2473333d202262746e}
		 $hex4= {2473343d202262746e}
		 $hex5= {2473353d202262746e}
		 $hex6= {2473363d2022436f6e}
		 $hex7= {2473373d20224e6176}
		 $hex8= {2473383d20226f7065}

	condition:
		5 of them
}
