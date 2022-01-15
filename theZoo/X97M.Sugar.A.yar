
/*
   YARA Rule Set
   Author: resteex
   Identifier: X97M_Sugar_A 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_X97M_Sugar_A {
	meta: 
		 description= "X97M_Sugar_A Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-39-38" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "051f2f03d0ad1f8931d3ebaef24850d6"
		 hash2= "4635b30179f9cf8fbf2e1e3f4bf1490b"
		 hash3= "c441cafdba84b56b63004272caa037a4"
		 hash4= "d374c8da41b5008b28483133a31c0738"
		 hash5= "fed7b61bd85e989dbfa6b8238a1f4550"

	strings:

	
 		 $s1= "DocumentSummaryInformation" fullword wide
		 $s2= "SummaryInformation" fullword wide
		 $s3= "_VBA_PROJECT_CUR" fullword wide

		 $hex1= {2473313d2022446f63}
		 $hex2= {2473323d202253756d}
		 $hex3= {2473333d20225f5642}

	condition:
		1 of them
}
