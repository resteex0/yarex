
/*
   YARA Rule Set
   Author: resteex
   Identifier: INTC_A 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_INTC_A {
	meta: 
		 description= "INTC_A Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-26-04" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "19db73095fef6bbb9f962ed7a0ff095e"
		 hash2= "26fd86a41abc424093ea8f3734c16430"

	strings:

	
 		 $a1= "------------------------------------------------" fullword ascii
		 $a2= "00MBTRESSLER@leo.bsuvc.bsu.edu" fullword ascii
		 $a3= "D:LANGTCINCLUDEIOSTREAM.H" fullword ascii
		 $a4= "D:LANGTCINCLUDESTDLIB.H" fullword ascii
		 $a5= "document.writeln(countcall)" fullword ascii
		 $a6= "@filebuf@seekoff$ql8seek_diri" fullword ascii
		 $a7= "@iostream@$bctr$qp9streambuf" fullword ascii
		 $a8= "@iostream_withassign@$basg$qp9streambuf" fullword ascii
		 $a9= "@iostream_withassign@$basg$qr3ios" fullword ascii
		 $a10= "@iostream_withassign@$bctr$qv" fullword ascii
		 $a11= "@iostream_withassign@$bdtr$qv" fullword ascii
		 $a12= "@istream@$bctr$qiip7ostream" fullword ascii
		 $a13= "@istream@$bctr$qp9streambuf" fullword ascii
		 $a14= "@istream@$bctr$qp9streambufip7ostream" fullword ascii
		 $a15= "@istream@$brsh$qp9streambuf" fullword ascii
		 $a16= "@istream@$brsh$qpqr3ios$r3ios" fullword ascii
		 $a17= "@istream@$brsh$qpqr7istream$r7istream" fullword ascii
		 $a18= "@istream@get$qr9streambufzc" fullword ascii
		 $a19= "@istream@seekg$ql8seek_dir" fullword ascii
		 $a20= "@istream_withassign@$basg$qp9streambuf" fullword ascii
		 $a21= "@istream_withassign@$basg$qr7istream" fullword ascii
		 $a22= "@istream_withassign@$bctr$qv" fullword ascii
		 $a23= "@istream_withassign@$bdtr$qv" fullword ascii
		 $a24= "KYBD:SCRN:NULL:LPT1:LPT2:LPT3:COM1:COM2:" fullword ascii
		 $a25= "@ostream@$bctr$qp9streambuf" fullword ascii
		 $a26= "@ostream@$blsh$qp9streambuf" fullword ascii
		 $a27= "@ostream@$blsh$qpqr3ios$r3ios" fullword ascii
		 $a28= "@ostream@$blsh$qpqr7ostream$r7ostream" fullword ascii
		 $a29= "@ostream@seekp$ql8seek_dir" fullword ascii
		 $a30= "@ostream_withassign@$basg$qp9streambuf" fullword ascii
		 $a31= "@ostream_withassign@$basg$qr7ostream" fullword ascii
		 $a32= "@ostream_withassign@$bctr$qv" fullword ascii
		 $a33= "@ostream_withassign@$bdtr$qv" fullword ascii
		 $a34= "@streambuf@$basg$qr9streambuf" fullword ascii
		 $a35= "@streambuf@$bctr$qr9streambuf" fullword ascii
		 $a36= "@streambuf@do_sgetn$qpzci" fullword ascii
		 $a37= "@streambuf@do_sputn$qpxzci" fullword ascii
		 $a38= "@streambuf@out_waiting$qv" fullword ascii
		 $a39= "@streambuf@seekoff$ql8seek_diri" fullword ascii

		 $hex1= {246131303d20224069}
		 $hex2= {246131313d20224069}
		 $hex3= {246131323d20224069}
		 $hex4= {246131333d20224069}
		 $hex5= {246131343d20224069}
		 $hex6= {246131353d20224069}
		 $hex7= {246131363d20224069}
		 $hex8= {246131373d20224069}
		 $hex9= {246131383d20224069}
		 $hex10= {246131393d20224069}
		 $hex11= {2461313d20222d2d2d}
		 $hex12= {246132303d20224069}
		 $hex13= {246132313d20224069}
		 $hex14= {246132323d20224069}
		 $hex15= {246132333d20224069}
		 $hex16= {246132343d20224b59}
		 $hex17= {246132353d2022406f}
		 $hex18= {246132363d2022406f}
		 $hex19= {246132373d2022406f}
		 $hex20= {246132383d2022406f}
		 $hex21= {246132393d2022406f}
		 $hex22= {2461323d202230304d}
		 $hex23= {246133303d2022406f}
		 $hex24= {246133313d2022406f}
		 $hex25= {246133323d2022406f}
		 $hex26= {246133333d2022406f}
		 $hex27= {246133343d20224073}
		 $hex28= {246133353d20224073}
		 $hex29= {246133363d20224073}
		 $hex30= {246133373d20224073}
		 $hex31= {246133383d20224073}
		 $hex32= {246133393d20224073}
		 $hex33= {2461333d2022443a4c}
		 $hex34= {2461343d2022443a4c}
		 $hex35= {2461353d2022646f63}
		 $hex36= {2461363d2022406669}
		 $hex37= {2461373d202240696f}
		 $hex38= {2461383d202240696f}
		 $hex39= {2461393d202240696f}

	condition:
		4 of them
}
