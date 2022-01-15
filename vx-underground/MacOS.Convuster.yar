
/*
   YARA Rule Set
   Author: resteex
   Identifier: MacOS_Convuster 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_MacOS_Convuster {
	meta: 
		 description= "MacOS_Convuster Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-14-15" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "12e7af714b80b8ca7539c76801160f76"
		 hash2= "196878757f2e301fdf0e40600f2760cc"
		 hash3= "1baa17183df02bb8f367fb913dc11e80"
		 hash4= "341f6c548763397bcdde1c52a534c4ba"
		 hash5= "44a135d96a4d06baa4ff73e2e9953e23"
		 hash6= "7776b7551fe96bbb850190c8194df1ac"
		 hash7= "7a35cb74459f38cd44c8672b40482539"
		 hash8= "80253edf1ceef5030e3fa7cf55c7fb92"
		 hash9= "82303c6caeb68820890173f359bbfe7c"
		 hash10= "d34ac81bd6acbe58d0e34d58a328c548"
		 hash11= "e94dc192942a132b01a07eb8bfb92385"
		 hash12= "ffba668ca384ac30fa3ff928cb3ad7a0"

	strings:

	
 		 $s1= "!$&(+,.026CEFJR]^lqstuwy}" fullword wide
		 $s2= "!$'+.158;?BEILOSVY]`cgjmqtw{~" fullword wide
		 $s3= "#%+,6=>?@BCFGHKLPSTUWX[]_`cdehijkrty{|}" fullword wide

		 $hex1= {2473313d2022212426}
		 $hex2= {2473323d2022212427}
		 $hex3= {2473333d202223252b}

	condition:
		2 of them
}
