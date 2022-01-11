
/*
   YARA Rule Set
   Author: resteex
   Identifier: Waski_Upatre 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Waski_Upatre {
	meta: 
		 description= "Waski_Upatre Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-31-26" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "41859ac8b90080471dfb315bf439d6f4"
		 hash2= "4d6c045c4cca49f8e556a7fb96e28635"
		 hash3= "6e67fb3835da739a11570bba44a19dbc"
		 hash4= "7a1f26753d6e70076f15149feffbe233"
		 hash5= "f44b714297a01a8d72e21fe658946782"

	strings:

	
 		 $s1= "guswdfpjqmhujolohbpulannxkeqeem" fullword wide
		 $s2= "iiwudavrcrrlduv" fullword wide
		 $s3= "jjoiewbstfyjvworwmohmvkshxjv" fullword wide
		 $s4= "msdxxfitboclbcmvc" fullword wide
		 $s5= "nphwtkgsia, orgjibwiv " fullword wide
		 $a1= "%$'&)(+DFHJLNprtvxz|~`bdfhjln" fullword ascii
		 $a2= "??4CPlex@@QAEAAU0@ABU0@@Z" fullword ascii
		 $a3= "??4CString@@QAEABV0@ABV0@@Z" fullword ascii
		 $a4= "??4CString@@QAEABV0@PBD@Z" fullword ascii
		 $a5= "??4CString@@QAEABV0@PBE@Z" fullword ascii
		 $a6= "??4CString@@QAEABV0@PBG@Z" fullword ascii
		 $a7= "5/wIss6MDE0eKudnvQxoTMmMOFkc/GcMXgyMSBgETE0cKudMFEh8KucmfhRMBAQE5wSPxwlMLMdIxI9D+oBMfqhPAajHSI1Mf4WP" fullword ascii
		 $a8= "??8@YG_NABVCString@@PBG@Z" fullword ascii
		 $a9= "??8@YG_NPBGABVCString@@@Z" fullword ascii
		 $a10= "??9@YG_NABVCString@@PBG@Z" fullword ascii
		 $a11= "??9@YG_NPBGABVCString@@@Z" fullword ascii
		 $a12= "aruywgmvjqevmfxsyykbeavrysuxkiluvqkqvwjgysdforqgkmmukvjrpeirngoxrotsscgwocoyxechonuqidoibfcgcat" fullword ascii
		 $a13= "aT9pPxxMaT8QHEwj7EdMTU2vY2ZMLTw8IFQlLy3tS5xMCwkYTEwBLTYlICAtTGN5YnxMOTgljCA6JSk7Ygy6jExMOAl8eHtiOCFM" fullword ascii
		 $a14= "a/ZMARbMTE1MTEzOSEx8s7NMTPRMdGFNTAxIdFVMJExAQlNM9kJM+EWBbfRMTQCBbRgkJT9ObExILWwcCWwpTDQpLzk4LS4gTClB" fullword ascii
		 $a15= "azn4jRPMRjm7f0iFHQ01zB0dHbNcORT9SUxaHLM5fJiz33RsRixFcdpMGsE5jPTEX0xMTMVKJkgaJkrh7k8cjWDsTU7qTRJsRRdM" fullword ascii
		 $a16= "BRKKKKMGN5lzstL@IKhsvz];GGCosvzzhGHHKHKHHKGBI" fullword ascii
		 $a17= "CLM5TLM5TE9Uze1EtEw4qvVKzFZsFHeNOkQsSqVkpcxNpQKMHRusCKwlbEkuQGxJDJ2sbHBIQk7kHCZOTUIMREKczEsOFM1ACB0c" fullword ascii
		 $a18= "CreateEllipticRgnIndirect" fullword ascii
		 $a19= "DEgVyUyMrZHFCVxDyAZ+PHXbXE8dGp5swWwJYBwaGnxP+E1DGk9df50MDU+UxQlABbxGi9uNS1xrBA1AjwYNmEx/uiZO7ElMTEt8" fullword ascii
		 $a20= "DGrI32jtU6JNOaqsR0y8GhwaJkwmSl4VDhHfDC8AqsUJRHAmTy1OxQlgJkZIT018jEkB+MVNTMeExQl49AxTDU1X/M8BoLOsNwxM" fullword ascii
		 $a21= "dwmQOQfHGYhNbdKcx04MxU7HTAH8z7RJOlQKzM+0RjpezY1OSkwB/H+MxU71jExrRUzJujlcJkpNDFuNXSr0TWWzbBlkxwmY7ENP" fullword ascii
		 $a22= "f0SMDMUuyrKIOO4sxwFcr0eMSG0kzwwpXEzHAUCkTUD8TIsJSK0TrT7s7RJHrj5sPXCoPk8Vf7rsHRoaJk8sTBwP3WDGgE83DEgI" fullword ascii
		 $a23= "f4XFAVzFTAGYxQFAxQGgTMUJTPXMyFJMTE+NzY2sShZMTMUJsE+N9bNDTWxYCRTHtA3HvUxPjcUJGE+NT1yKxQn4LU3wsxkIUPNN" fullword ascii
		 $a24= "G05AUJeMSk5NpAxIzVYk7VdIVxJLU1dEV4xtqUCuR1cAfQ9CszkApVZsNLQbCShZGyhZszkY70TJbIxDyKpPzUsMG58rS0JaMUyM" fullword ascii
		 $a25= "GHHM@@@KHHITNGKM@CHNNKKICIIMNKRMIHMHMHHMMMG@I" fullword ascii
		 $a26= "gtnucggsynjlvkounxjlqjrkyycbieintyidxkvhsadivcckrfeybrsehplrmnnklwtdevaheopgcnkphyfkxmgrjjujcjd" fullword ascii
		 $a27= "HBxOHPTMwRc8TLTtVE5N7lSNrU7HCaRPjI0fx1T0CM1D3EFMQGQaHc+KSJ1MpceKnaUFx7RM4X+PD+eutSZMXhQVF8dIVMfMvxd3" fullword ascii
		 $a28= "jUPJj+xeVTxIsojdX9lI9E+ETMdNxwJId404blrcWSr0SK1kf4zMdQlcOGqlVxxB/sHcKyYMThVMCHyedUwqxwpET4rHAQwcs5yn" fullword ascii
		 $a29= "KD76T0zeRm6/4Ph0TWBvTEzsdG1MTJh0TRZ8TeYUfE2sdE04fE0ofE0dQ0xMTCA8TTZ8TMQZfEzWfEzkfEz6fEyGGXxMlnxMpHxM" fullword ascii
		 $a30= "KufGjY1RDU7HCUiMHIgoG8e0x7skJmoUzWo6TE1MK+ccx4oSHMxxEMxxz0iIQA9atceyp1pccEw5/o1cxzmAzH+FDafHsoUOflUO" fullword ascii
		 $a31= "nfhgbdxsvaglaxdmhekecaxahdfxqqdvgkcwwpektnyovmnjokbxwxcpptxpqbcwbrochvvmqueflgoevvwsxscrxhxonfcarppk" fullword ascii
		 $a32= "nkpnkkmkkpppkkmknnknkknnnnkpmk|" fullword ascii
		 $a33= "nyYcerQFbXDfKG1A3xQeTGy5HkxEHkxgHExDTENMQ0yzQ0xDTENMQ0xDTENMQ0xDTLNDTENMQ0xDTENMQ0xDTENMI0NMQ0xDTEdM" fullword ascii
		 $a34= "OCk+Ai0hT05OfU0YJS8nDyNQOSJti71MjU8fJTarnUqcTK1PDSgMHG5IXU0sASMoOSBuShZIKQwhPBwtOCS5TBpMKT4/JSMiCTQt" fullword ascii
		 $a35= "PEcnKT4iKSB/bH5iKCAgnU4EOEw4PAM8KSIeKSw9OSk/OH5FfU0fBCkiKHVNBSL8XCJQKTj9Tk1NuUwPIyIyIsxJdk43VBlN1UF5" fullword ascii
		 $a36= "PEx1eWJ9dH1MYnh6Yn90TCMMOjUmIz9/Dk4vTCQpLyclPGIoTDUiKCI/YiM+TCtMY0w8Kc38TCItIis/OD4pTCk4KiMjKGIiTCk4" fullword ascii
		 $a37= "pgyfbyhfndmfksjcxrftgyduxwhobwcdraqrxavxhpaedhfqoarsphkkylydvclttmkmndojoylcnoccekfagxbrlbcmeqmidkjw" fullword ascii
		 $a38= "RHKGGGGGKKGIIRKKGNKKMGIIGGRKNMGGKKKMGMMHGMMM@I" fullword ascii
		 $a39= "RHNEc0RzRHNE2VwPTCAjPykELSIoSCApnUw+KS04KWwKJSApG5pMHD5sIy8pPz9NTUwIRCkgKbtNCTQlOE+YTZxMCyk4DyMhTDw5" fullword ascii
		 $a40= "riitrjnqbbkclqxbvbiiissqawcjkhgcjneqrjlxlthtwghnvdanwi" fullword ascii
		 $a41= "RLPfsEwc4cFwCwVPSvhOT0CA2w1A2kgkUMzew0oas99MWF1MTCZjFCpM5+HhsoRIfSpU5/VCzEqITk+94EwmSxWyhDhc/EwYsoQq" fullword ascii
		 $a42= "RmgcCUxMRABNTkYyrExPTdZHTTBGSMxMTCleTEi2XExPbEjJTUdMekhSSkuwTHxPW01MT0pMZE1nSkv7SkpPTEwDKGyfYUykzGfO" fullword ascii
		 $a43= "SD0NfUijOMTPKUYIrEcIzGzFMZT1/40JzA85SBxtzE8AP05cOGnHShxMU0+0TGUJSDhUrpHHTAGg9E5kTEyyLog8X6U1sm3HnFOL" fullword ascii
		 $a44= "SkhYKueuvV0Z3hzNACZPvBzfTE1bTKxPTwmEHP1FDUZYxQmYFMecEWRMpb2xs7PFCUjDPAxzcDp9nHlDyIFsTb1eesEBSJUO9n0e" fullword ascii
		 $a45= "SMc5GC0FXIGsRvXNPu1RGvWNXm5NzalkVH+MHCTM7E4sJk8cJk2ubyxPoE1sX8+0szgNxQnMHCZMHLPfSMxJxMUJCMxNwQEAjGsM" fullword ascii
		 $a46= "TcdeZRdMTdAty1BPXUdMQExMRkxdQUJ1TkpDXE1Ks0wlTA==" fullword ascii
		 $a47= "TCxdcOxNjEwEzU4TTI/PiNDHoM2IbDCzs7OkzQIXzEyrvCZJwTFYfmyXHxIVDU0AT48FjAy69O0THCRNKSRMzHDrTB2z32RNL1yp" fullword ascii
		 $a48= "TGcJTHF6Bk5MTDs0xxmgz7ZMyDmazCYx+MdLnFNMh8c5TMdKDAxMCnEqKD4prLhMDAwrr/sKCgpM4WE/P3ZsOeBM4HBiPkZwdTvM" fullword ascii
		 $a49= "TGM7PGEvTCMiOCkiOGM5TDwgIy0oP2M9TDkpPzgoYjwoTCpMNTkhPD4jTCYpLzhiLyMhTV74fnx9eGN9fU1FJnx1fH85J35MfkxN" fullword ascii
		 $a50= "tnxMXBm8S2x8THx8THB8TAQZfEwUfEwufEw+fEzM53xMTUzsPEz4fEyEfEzmlHxMoHxMTrxLWnxMmU1MdDxMAvhMKDhMc0Qzc0Rz" fullword ascii
		 $a51= "TPhIsxlUxQksTN/HOVh/jCrhTMUJhMcx8Bt/TIzHhMecxXfPTI9I4HBNOEUqTOcNyIw5uKehTBTBSATFCfB/TIzgxTmkjaxOSE+8" fullword ascii
		 $a52= "TR9BTUk4jEO8TzslIiVPbE3IRR44IAgpL098VK1YDjkqKik+TRxNPzs8PiUiOCwqTEwiODxO+E4fLCQpICAJvrwMWj9PnUxIQqx7" fullword ascii
		 $a53= "TU0eKS0oTU/9TRtAPiVPRvxMACMtKEwAJS4+LT41DU39TR8gKSk8CTRN3EwaJT44OS0gLA0gICMv3U24TApQPik9T5hM/EU4KS9N" fullword ascii
		 $a54= "VAzPTewC0CRMLH3PW83Aso1vTG3MDrAb9Q9MQA3FykPNTQxJHR0cHawfBhjMD7zMS6U1zEHHSAkcSEcmbBLzpN9sTq1Z37iuXTlB" fullword ascii
		 $a55= "wwtGwwwwwwwwwwwwwwwtDDDDw" fullword ascii
		 $a56= "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii
		 $a57= "xQGMxwFMmK9vGxocxzFOFE5TxwmgsxlozEP6hLMZbNoPWkxJKuenuY/HOWScf4VPSEhNSMmFTDkqFHatOB3HZIQmeExC/Axl/GN8" fullword ascii
		 $a58= "yNRDYjgpNDjMT3AqREgEzTlHz00BLGJMPigtOC1MTN6nTTzNMUrMTUDHX8zKbYdNZkzMX0BMWEx+TE11TQtNxxnwTE0J8N6PH3+M" fullword ascii
		 $a59= "zk70wXjK4EzFCZDHhI2sT10OWKjHtExdnOHnbMeOKuEqDE3gKkznBTm8x40X+GhIHA5EiBTOTZzHTLT8Y+Z/jOb8TITBOYDFShob" fullword ascii

		 $hex1= {246131303d20223f3f}
		 $hex2= {246131313d20223f3f}
		 $hex3= {246131323d20226172}
		 $hex4= {246131333d20226154}
		 $hex5= {246131343d2022612f}
		 $hex6= {246131353d2022617a}
		 $hex7= {246131363d20224252}
		 $hex8= {246131373d2022434c}
		 $hex9= {246131383d20224372}
		 $hex10= {246131393d20224445}
		 $hex11= {2461313d2022252427}
		 $hex12= {246132303d20224447}
		 $hex13= {246132313d20226477}
		 $hex14= {246132323d20226630}
		 $hex15= {246132333d20226634}
		 $hex16= {246132343d20224730}
		 $hex17= {246132353d20224748}
		 $hex18= {246132363d20226774}
		 $hex19= {246132373d20224842}
		 $hex20= {246132383d20226a55}
		 $hex21= {246132393d20224b44}
		 $hex22= {2461323d20223f3f34}
		 $hex23= {246133303d20224b75}
		 $hex24= {246133313d20226e66}
		 $hex25= {246133323d20226e6b}
		 $hex26= {246133333d20226e79}
		 $hex27= {246133343d20224f43}
		 $hex28= {246133353d20225045}
		 $hex29= {246133363d20225045}
		 $hex30= {246133373d20227067}
		 $hex31= {246133383d20225248}
		 $hex32= {246133393d20225248}
		 $hex33= {2461333d20223f3f34}
		 $hex34= {246134303d20227269}
		 $hex35= {246134313d2022524c}
		 $hex36= {246134323d2022526d}
		 $hex37= {246134333d20225344}
		 $hex38= {246134343d2022536b}
		 $hex39= {246134353d2022534d}
		 $hex40= {246134363d20225463}
		 $hex41= {246134373d20225443}
		 $hex42= {246134383d20225447}
		 $hex43= {246134393d20225447}
		 $hex44= {2461343d20223f3f34}
		 $hex45= {246135303d2022746e}
		 $hex46= {246135313d20225450}
		 $hex47= {246135323d20225452}
		 $hex48= {246135333d20225455}
		 $hex49= {246135343d20225641}
		 $hex50= {246135353d20227777}
		 $hex51= {246135363d20227777}
		 $hex52= {246135373d20227851}
		 $hex53= {246135383d2022794e}
		 $hex54= {246135393d20227a6b}
		 $hex55= {2461353d20223f3f34}
		 $hex56= {2461363d20223f3f34}
		 $hex57= {2461373d2022352f77}
		 $hex58= {2461383d20223f3f38}
		 $hex59= {2461393d20223f3f38}
		 $hex60= {2473313d2022677573}
		 $hex61= {2473323d2022696977}
		 $hex62= {2473333d20226a6a6f}
		 $hex63= {2473343d20226d7364}
		 $hex64= {2473353d20226e7068}

	condition:
		8 of them
}
