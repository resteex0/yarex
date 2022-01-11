
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Thanos 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Thanos {
	meta: 
		 description= "Ransomware_Thanos Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-29-19" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "03b76a5130d0df8134a6bdea7fe97bcd"
		 hash2= "be60e389a0108b2871dff12dfbb542ac"
		 hash3= "d6d956267a268c9dcf48445629d2803e"
		 hash4= "e01e11dca5e8b08fc8231b1cb6e2048c"

	strings:

	
 		 $s1= "3747bdbf-0ef0-42d8-9234-70d68801f407" fullword wide
		 $s2= "3FGC7QZ13R9WNYMW1MISG70EJXK4EVFD" fullword wide
		 $s3= "=42bn9Gbul2Vc52bpNnclZFduVmcyV3QcRlTgM3dvRmbpdFX0Z2bz9mcjlWTcVkUBdFVG90U" fullword wide
		 $s4= "6WTzYKu9UTQzwhXiMl2PCy4oH9JZoJwxpmgN6J8lY3Z1Nb9RMKz29xLHbosYBVUKgcJKAJmCnQ1JZDbpA1NeT4x2aYwRajkCiOVu" fullword wide
		 $s5= "7WLFZugCsGvrkZN9154ey6cerZwgxYQFzx1FGFRLSe3vOBjhpOQmNN3B3qYA8APT0q1xhH2wns" fullword wide
		 $s6= "9O431qEAnJjrwuk9KELnLsSoUcuNak7gSsa0i4yyO7VKPv7ntf2Yo4YR6QiY51kCLDYEUtaPPWYNXHYif" fullword wide
		 $s7= "a3VwKi4qIGc6XCouc2V0IGc6XCoud2luIGc6XCouZHNr" fullword wide
		 $s8= "a3VwKi4qIGg6XCouc2V0IGg6XCoud2luIGg6XCouZHNr" fullword wide
		 $s9= "a3VwKi4qIGM6XCouc2V0IGM6XCoud2luIGM6XCouZHNr" fullword wide
		 $s10= "a3VwKi4qIGQ6XCouc2V0IGQ6XCoud2luIGQ6XCouZHNr" fullword wide
		 $s11= "a3VwKi4qIGU6XCouc2V0IGU6XCoud2luIGU6XCouZHNr" fullword wide
		 $s12= "a3VwKi4qIGY6XCouc2V0IGY6XCoud2luIGY6XCouZHNr" fullword wide
		 $s13= "Aditional KeyId:" fullword wide
		 $s14= "admin123Test123" fullword wide
		 $s15= "Administrador de tareas" fullword wide
		 $s16= "administrator123" fullword wide
		 $s17= "Administrator123" fullword wide
		 $s18= "aGFyZWRGb2xkZXIgbmFtZT0iIWRyaXZlaWQhIiBob3N0UGF0aD0iJSVkOlwiIHdyaXRhYmxlPSJ0cnVlIi9ePiA+PnNmLnR4dAog" fullword wide
		 $s19= "aHR0cCBhbmFseXplciBzdGFuZC1hbG9uZQ==" fullword wide
		 $s20= "aHR0cDovL2ljYW5oYXppcC5jb20=" fullword wide
		 $s21= "aHR0cHM6Ly93d3cucG93ZXJhZG1pbi5jb20vcGFleGVjL3BhZXhlYy5leGU=" fullword wide
		 $s22= "aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2QzNWhhL1Byb2Nlc3NIaWRlL21hc3Rlci9iaW5zL1Byb2Nlc3NIaWRl" fullword wide
		 $s23= "Assembly Version" fullword wide
		 $s24= "aW50ZXJjZXB0ZXI=" fullword wide
		 $s25= "aZnLma0ZpqTthmr" fullword wide
		 $s26= "b29kIHRvby4KCgo8L3A+CjxoMyBzdHlsZT0iY29sb3I6eWVsbG93OyB0ZXh0LWFsaWduOiBjZW50ZXI7Ij5UaGUgUHJpY2UgdG8g" fullword wide
		 $s27= "b3BlcmEzMi5leGU=" fullword wide
		 $s28= "bG9yOiAjZmYwMDAwOyI+PGltZyBzcmM9Imh0dHBzOi8vY3V0ZXdhbGxwYXBlci5vcmcvMjEvc2t1bGwtd2FsbHBhcGVyLWZyZWUv" fullword wide
		 $s29= "bGhPRHZWUWVlOXB6a0JMMHlURGdFSkUzMDRwd3RnK1c1WjVaZ29SaUdJL2owdnhuYlNxRUNHV3E2bzBMUmRxMTRVL3ZoT1hncW1x" fullword wide
		 $s30= "bGlnbjogY2VudGVyOyI+IE15IEJUQyBXYWxsZXQgSUQgOiA8cCBzdHlsZT0idGV4dC1hbGlnbjogY2VudGVyOyBjb2xvcjpyZWQ7" fullword wide
		 $s31= "bm90ZXBhZC5leGU=" fullword wide
		 $s32= "bnQtd2VpZ2h0OiBib2xkOyI+CkRvbuKAmXQgd29ycnksIHlvdSBjYW4gcmV0dXJuIGFsbCB5b3VyIGZpbGVzITxicj4KSSBkb24n" fullword wide
		 $s33= "bTJFTjd3aWh6NkIxaDJYRkx5OGsydjhPUUJ6RTFocHZuRE5WOTlJdHQzL3dPaEpJei93QTA0MTg1MVFkY3lnTmlhYkdhT2VFWUdG" fullword wide
		 $s34= "bW91bnR2b2wgfCBmaW5kICJ9XCIgPiB2LnR4dAoKKEZvciAvRiAlJWkgSW4gKHYudHh0KSBEbyAoCiAgICAgIFNldCBmcmVlZHJp" fullword wide
		 $s35= "bXlzcWxkLmV4ZQ==" fullword wide
		 $s36= "C$ /user:Admin Admin" fullword wide
		 $s37= "C$ /user:Administrator Administrator" fullword wide
		 $s38= "c3Bvb2xjdi5leGU=" fullword wide
		 $s39= "c3lzaW50ZXJuYWxzIHRjcHZpZXc=" fullword wide
		 $s40= "c3RvcCB2ZWVhbSAveQ==" fullword wide
		 $s41= "c3RvcCB6aHVkb25nZmFuZ3l1IC95" fullword wide
		 $s42= "c3RvcCBBY3JTY2gyU3ZjIC95" fullword wide
		 $s43= "c3RvcCBBY3JvbmlzQWdlbnQgL3k=" fullword wide
		 $s44= "c3RvcCBCTVIgQm9vdCBTZXJ2aWNlIC95" fullword wide
		 $s45= "c3RvcCBCYWNrdXBFeGVjQWdlbnRBY2NlbGVyYXRvciAveQ==" fullword wide
		 $s46= "c3RvcCBCYWNrdXBFeGVjQWdlbnRCcm93c2VyIC95" fullword wide
		 $s47= "c3RvcCBCYWNrdXBFeGVjRGl2ZWNpTWVkaWFTZXJ2aWNlIC95" fullword wide
		 $s48= "c3RvcCBCYWNrdXBFeGVjSm9iRW5naW5lIC95" fullword wide
		 $s49= "c3RvcCBCYWNrdXBFeGVjTWFuYWdlbWVudFNlcnZpY2UgL3k=" fullword wide
		 $s50= "c3RvcCBCYWNrdXBFeGVjUlBDU2VydmljZSAveQ==" fullword wide
		 $s51= "c3RvcCBCYWNrdXBFeGVjVlNTUHJvdmlkZXIgL3k=" fullword wide
		 $s52= "c3RvcCBDQUFSQ1VwZGF0ZVN2YyAveQ==" fullword wide
		 $s53= "c3RvcCBDQVNBRDJEV2ViU3ZjIC95" fullword wide
		 $s54= "c3RvcCBEZWZXYXRjaCAveQ==" fullword wide
		 $s55= "c3RvcCBhdnBzdXMgL3k=" fullword wide
		 $s56= "c3RvcCBJbnR1aXQuUXVpY2tCb29rcy5GQ1MgL3k=" fullword wide
		 $s57= "c3RvcCBjY0V2dE1nciAveQ==" fullword wide
		 $s58= "c3RvcCBjY1NldE1nciAveQ==" fullword wide
		 $s59= "c3RvcCBNY0FmZWVETFBBZ2VudFNlcnZpY2UgL3k=" fullword wide
		 $s60= "c3RvcCBOZXRCYWNrdXAgQk1SIE1URlRQIFNlcnZpY2UgL3k=" fullword wide
		 $s61= "c3RvcCBQRFZGU1NlcnZpY2UgL3k=" fullword wide
		 $s62= "c3RvcCBRQklEUFNlcnZpY2UgL3k=" fullword wide
		 $s63= "c3RvcCBRQkNGTW9uaXRvclNlcnZpY2UgL3k=" fullword wide
		 $s64= "c3RvcCBRQkZDU2VydmljZSAveQ==" fullword wide
		 $s65= "c3RvcCBSVFZzY2FuIC95" fullword wide
		 $s66= "c3RvcCBTYXZSb2FtIC95" fullword wide
		 $s67= "c3RvcCBtZmV3YyAveQ==" fullword wide
		 $s68= "c3RvcCBWU05BUFZTUyAveQ==" fullword wide
		 $s69= "c3RvcCBWZWVhbU5GU1N2YyAveQ==" fullword wide
		 $s70= "c3RvcCBWZWVhbURlcGxveW1lbnRTZXJ2aWNlIC95" fullword wide
		 $s71= "c3RvcCBWZWVhbVRyYW5zcG9ydFN2YyAveQ==" fullword wide
		 $s72= "c3RvcCBZb29CYWNrdXAgL3k=" fullword wide
		 $s73= "c3RvcCBZb29JVCAveQ==" fullword wide
		 $s74= "c3RvcCBzb3Bob3MgL3k=" fullword wide
		 $s75= "c3RvcCBzdGNfcmF3X2FnZW50IC95" fullword wide
		 $s76= "c3ZjaHN0LmV4ZQ==" fullword wide
		 $s77= "Cg0KWW91J3ZlIGdvdCA0OCBob3VycygyIERheXMpLCBiZWZvcmUgeW91IGxvc3QgeW91ciBmaWxlcyBmb3JldmVyLg0KSSB3aWxs" fullword wide
		 $s78= "cHJvdGVjdGlvbl9pZA==" fullword wide
		 $s79= "ciBGaWxlcyBhcmUgRW5jcnlwdGVkLjwvaDI+PGJyPgo8cCBzdHlsZT0idGV4dC1hbGlnbjogY2VudGVyOyBjb2xvcjpyZWQ7IGZv" fullword wide
		 $s80= "cifZwRsg4W7BwNGqXOztYNOmVaAlY2SdoDU6KT6XPaXbOj6dznsWobkOU2EVRHHBDeXt2JfDRbd70xYwegvuK5zMcFmSPlGITVXt" fullword wide
		 $s81= "cmUgeW91IGxvc3QgeW91ciBmaWxlcyBmb3JldmVyLjxicj4KSSB3aWxsIHRyZWF0IHlvdSBnb29kIGlmIHlvdSB0cmVhdCBtZSBn" fullword wide
		 $s82= "cmVzaXplIHNoYWRvd3N0b3JhZ2UgL2Zvcj1jOiAvb249YzogL21heHNpemU9dW5ib3VuZGVk" fullword wide
		 $s83= "cmVzaXplIHNoYWRvd3N0b3JhZ2UgL2Zvcj1jOiAvb249YzogL21heHNpemU9NDAxTUI=" fullword wide
		 $s84= "cmVzaXplIHNoYWRvd3N0b3JhZ2UgL2Zvcj1kOiAvb249ZDogL21heHNpemU9dW5ib3VuZGVk" fullword wide
		 $s85= "cmVzaXplIHNoYWRvd3N0b3JhZ2UgL2Zvcj1kOiAvb249ZDogL21heHNpemU9NDAxTUI=" fullword wide
		 $s86= "cmVzaXplIHNoYWRvd3N0b3JhZ2UgL2Zvcj1lOiAvb249ZTogL21heHNpemU9dW5ib3VuZGVk" fullword wide
		 $s87= "cmVzaXplIHNoYWRvd3N0b3JhZ2UgL2Zvcj1lOiAvb249ZTogL21heHNpemU9NDAxTUI=" fullword wide
		 $s88= "cmVzaXplIHNoYWRvd3N0b3JhZ2UgL2Zvcj1mOiAvb249ZjogL21heHNpemU9dW5ib3VuZGVk" fullword wide
		 $s89= "cmVzaXplIHNoYWRvd3N0b3JhZ2UgL2Zvcj1mOiAvb249ZjogL21heHNpemU9NDAxTUI=" fullword wide
		 $s90= "cmVzaXplIHNoYWRvd3N0b3JhZ2UgL2Zvcj1nOiAvb249ZzogL21heHNpemU9dW5ib3VuZGVk" fullword wide
		 $s91= "cmVzaXplIHNoYWRvd3N0b3JhZ2UgL2Zvcj1nOiAvb249ZzogL21heHNpemU9NDAxTUI=" fullword wide
		 $s92= "cmVzaXplIHNoYWRvd3N0b3JhZ2UgL2Zvcj1oOiAvb249aDogL21heHNpemU9dW5ib3VuZGVk" fullword wide
		 $s93= "cmVzaXplIHNoYWRvd3N0b3JhZ2UgL2Zvcj1oOiAvb249aDogL21heHNpemU9NDAxTUI=" fullword wide
		 $s94= "c net use * \\" fullword wide
		 $s95= "Copyright 2019 3fTddThVDVTaMx4" fullword wide
		 $s96= "/c rd /s /q %SYSTEMDRIVE%$Recycle.bin" fullword wide
		 $s97= "d2lyZXNoYXJrIHBvcnRhYmxl" fullword wide
		 $s98= "dCB3YW50IHRvIGxvb3NlIHlvdXIgZmlsZXMgdG9vLiBpZiBpIHdhbnQgdG8gZG8gc29tZXRoaW5nIGJhZCB0byB5b3UgaSB3b3Vs" fullword wide
		 $s99= "-d -f -h -s -n 2 -c " fullword wide
		 $s100= "dGV4dC1hbGlnbjogY2VudGVyOyBjb2xvcjpyZWQ7Ij5Db250YWN0OiBqb3NlcGhudWxsQHNlY21haWwucHJvIDwvaDI+CjwvYm9k" fullword wide
		 $s101= "DisableAntiSpyware" fullword wide
		 $s102= "DisableArchiveScanning" fullword wide
		 $s103= "DisableBehaviorMonitoring" fullword wide
		 $s104= "DisableBlockAtFirstSeen" fullword wide
		 $s105= "DisableIntrusionPreventionSystem" fullword wide
		 $s106= "DisableIOAVProtection" fullword wide
		 $s107= "DisableOnAccessProtection" fullword wide
		 $s108= "DisablePrivacyMode" fullword wide
		 $s109= "DisableRealtimeMonitoring" fullword wide
		 $s110= "DisableScanOnRealtimeEnable" fullword wide
		 $s111= "DisableScriptScanning" fullword wide
		 $s112= "dmU9MAogICAgICBGT1IgJSVkIElOIChDIEQgRSBGIEcgSCBJIEogSyBMIE0gTiBPIFAgUSBSIFMgVCBVIFYgVyBYIFkgWikgRE8g" fullword wide
		 $s113= "dnNzYWRtaW4uZXhl" fullword wide
		 $s114= "dSBkb250IHBheSwgd2Ugd2lsbCBsZWFrIHRoZW0NCj09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09" fullword wide
		 $s115= "dVlHeUEzRHhKbGJUSHh0U2lKaVU2VkNjVjNBV21zMk1DMFR4V0NRakNSNnpNRmpoK2dYMXNmRVlpMHM1RldwVnlPcnJ3PT08L01v" fullword wide
		 $s116= "eHQtYWxpZ246IGNlbnRlcjsiPkNvbnRhY3QgOiA8YnI+IGpvc2VwaG51bGxAc2VjbWFpbC5wcm8gPC9oMz4KCjxoMiBzdHlsZT0i" fullword wide
		 $s117= "eSBhbGwgb2YgeW91ciBmaWxlcyBpcyBtaW5lIG5vdyB1bnRpbCB5b3UgcGF5IHRoZSBwcmljZSBvZiB0aGVtLjxicj4KSWYgeW91" fullword wide
		 $s118= "eT4KPC9odG1sPg==" fullword wide
		 $s119= "eW91ciBmaWxlcywgZG9jdW1lbnRzLCBhbmQgYWxsIG9mIHlvdXIgbmV0d29yayBlbmNyeXB0ZWQuDQphbGwgYmFja3VwIGRyaXZl" fullword wide
		 $s120= "f6NqzeK32KNxcHlCR7XX4KUKjSDDyE4k4mN6WeYbR7EMmsEe9H7kJU6UlDGhaHExPn303pqxj6G6FHi0OiDrGUbjp3UTX1AJ3R68" fullword wide
		 $s121= "FileDescription" fullword wide
		 $s122= "Final-02.exe.bin" fullword wide
		 $s123= "g32POuYzYzghMdgcJecbNJHtXfk5inA7yK8oZ4hFHYv78XLRpt0ckP8WvJ2tKdRvyjtBe2DO" fullword wide
		 $s124= "gCLianUocZKoeIY" fullword wide
		 $s125= "GetCurrentProcessId" fullword wide
		 $s126= "Get-MpPreference -verbose" fullword wide
		 $s127= "HighThreatDefaultAction" fullword wide
		 $s128= "HOW_TO_DECYPHER_FILES" fullword wide
		 $s129= "HOW_TO_DECYPHER_FILES.hta" fullword wide
		 $s130= "HOW_TO_DECYPHER_FILES.txt" fullword wide
		 $s131= "https://www.google.com/" fullword wide
		 $s132= "HzqjyPuTRC6aGcY047is9JjjUI7rqbtl1w78RLigLL7BDfqpg9e5EP47PGOpRDm0TViUeajtYBhyMifzcSLr6ygm2AsK72OIiHss" fullword wide
		 $s133= "ICkKICAgICAgKQogICAgICBtb3VudHZvbCAhZnJlZWRyaXZlITogJSVpCiAgICAgIHBpbmcgLW4gMiAxMjcuMC4wLjEKKSkKU2V0" fullword wide
		 $s134= "IFRPVUNIIE9SIEVESVQgTE9DS0VEIEZJTEVTDQpET05UIFVTRSBSRUdVTEFSIFJFQ09WRVJZIFNPRlRXQVJFLCBFVkVOICJNSUNS" fullword wide
		 $s135= "IGFuZCB0YXBlIGRlbGV0ZWQgb2YgZm9ybWF0dGVkLg0KYWxsIHNoYWRvdyBjb3BpZXMgZGVsZXRlZC4NCj09PT09PT09PT09PT09" fullword wide
		 $s136= "IGRyaXZlaWQ9MApGT1IgJSVkIElOIChDIEQgRSBGIEcgSCBJIEogSyBMIE0gTiBPIFAgUSBSIFMgVCBVIFYgVyBYIFkgWikgRE8g" fullword wide
		 $s137= "IHdhbnQgdG8gcmVzdG9yZSB0aGVtIGNvbnRhY3QgbWUgZnJvbSB0aGUgYWRkcmVzcyBiZWxvdywgaSdsbCBiZSBoYXBweSB0byBo" fullword wide
		 $s138= "IHRoZSBub3JtYWwgOiAyMCwwMDAkDQpNeSBCVEMgV2FsbGV0IElEIDoNCjFGNnNxOFl2ZnRUZnVFNFFjWXhmSzhzNVhGVVVIQzdz" fullword wide
		 $s139= "IHRyZWF0IHlvdSBnb29kIGlmIHlvdSB0cmVhdCBtZSBnb29kIHRvby4NCg0KVGhlIFByaWNlIHRvIGdldCBhbGwgdGhpbmdzIHRv" fullword wide
		 $s140= "Ij4xRjZzcThZdmZ0VGZ1RTRRY1l4Zks4czVYRlVVSEM3c0Q5PC9wPiA8L2gzPiAKPGgzIHN0eWxlPSJjb2xvcjp5ZWxsb3c7IHRl" fullword wide
		 $s141= "Incorrect MAC address supplied!" fullword wide
		 $s142= "internet explorer" fullword wide
		 $s143= "IPInfo: Error Parsing 'arp -a' results" fullword wide
		 $s144= "IPInfo: Error Retrieving 'arp -a' Results" fullword wide
		 $s145= "jboiz6eHPBwfCC7nL6sTR9XfyUgPwA8TE3JSOTcpZQY8TAeZvi4iHLOjDJufZOVOCcaI3pZ1dD4AlZLyzGdNFaM3ojPEj7PK4J51" fullword wide
		 $s146= "jVgGJDFERN7n86pSuHJmPhdTaURfxtGbeTOdkXEBVIlbllGnR6ZxASlC1MqzwjQh" fullword wide
		 $s147= "KAogICAgICAgICAgICAgICAgICAgICAgICBTZXQgZnJlZWRyaXZlPSUlZAogICAgICAgICAgICAgICAgICApCiAgICAgICAgICAg" fullword wide
		 $s148= "KAogICAgICAgICAgICBJRiBOT1QgRVhJU1QgJSVkOlwgKAogICAgICAgICAgICAgICAgICBJRiAiIWZyZWVkcml2ZSEiPT0iMCIg" fullword wide
		 $s149= "KAogICAgICBJRiBFWElTVCAlJWQ6XCAoCiAgICAgICAgICAgIFNldCAvYSBkcml2ZWlkKz0xCiAgICAgICAgICAgIGVjaG8gXjxT" fullword wide
		 $s150= "Key is null or empty" fullword wide
		 $s151= "Key size is not valid" fullword wide
		 $s152= "KzcvSkNIVTdKRWtVVElMZ3ZhZnd6bHZtZjcxSmd5bUI3Njlvb242eVZFcXoxQVZOZHlWT3lkQnVINEFEYlI5SGlBeVFoT3dWQ0NY" fullword wide
		 $s153= "L0lNIG15ZGVza3RvcHFvcy5leGUgL0Y=" fullword wide
		 $s154= "L0lNIG15ZGVza3RvcHNlcnZpY2UuZXhlIC9G" fullword wide
		 $s155= "L0lNIG1zcHViLmV4ZSAvRg==" fullword wide
		 $s156= "L0MgcGluZyAxMjcuMC4wLjcgLW4gMyA+IE51bCAmIGZzdXRpbCBmaWxlIHNldFplcm9EYXRhIG9mZnNldD0wIGxlbmd0aD01MjQy" fullword wide
		 $s157= "L0MgY2hvaWNlIC9DIFkgL04gL0QgWSAvVCAzICYgRGVsIA==" fullword wide
		 $s158= "L3MgL2YgL3EgaDpcKi5WSEQgaDpcKi5iYWMgaDpcKi5iYWsgaDpcKi53YmNhdCBoOlwqLmJrZiBoOlxCYWNrdXAqLiogaDpcYmFj" fullword wide
		 $s159= "L3MgL2YgL3EgYzpcKi5WSEQgYzpcKi5iYWMgYzpcKi5iYWsgYzpcKi53YmNhdCBjOlwqLmJrZiBjOlxCYWNrdXAqLiogYzpcYmFj" fullword wide
		 $s160= "L3MgL2YgL3EgZDpcKi5WSEQgZDpcKi5iYWMgZDpcKi5iYWsgZDpcKi53YmNhdCBkOlwqLmJrZiBkOlxCYWNrdXAqLiogZDpcYmFj" fullword wide
		 $s161= "L3MgL2YgL3EgZjpcKi5WSEQgZjpcKi5iYWMgZjpcKi5iYWsgZjpcKi53YmNhdCBmOlwqLmJrZiBmOlxCYWNrdXAqLiogZjpcYmFj" fullword wide
		 $s162= "L3MgL2YgL3EgZTpcKi5WSEQgZTpcKi5iYWMgZTpcKi5iYWsgZTpcKi53YmNhdCBlOlwqLmJrZiBlOlxCYWNrdXAqLiogZTpcYmFj" fullword wide
		 $s163= "L3MgL2YgL3EgZzpcKi5WSEQgZzpcKi5iYWMgZzpcKi5iYWsgZzpcKi53YmNhdCBnOlwqLmJrZiBnOlxCYWNrdXAqLiogZzpcYmFj" fullword wide
		 $s164= "L3YgL2ZvIGNzdg==" fullword wide
		 $s165= "LD2WALLJZR93XK10KS892LMU006ZXO3Q" fullword wide
		 $s166= "LegalTrademarks" fullword wide
		 $s167= "Lengths of IP address and subnet mask do not match." fullword wide
		 $s168= "LNlpIoFM8mYheR0uVX0IpKQxhNypUVoeZokR5Fmg0mO0qFy7uWw6fPEA6xI5zZ2m84" fullword wide
		 $s169= "LowThreatDefaultAction" fullword wide
		 $s170= "mac>([a-f0-9]{2}-?){6})" fullword wide
		 $s171= "Maximum data length is {0}" fullword wide
		 $s172= "microsoft corporation" fullword wide
		 $s173= "MjA0OCE8UlNBS2V5VmFsdWU+PE1vZHVsdXM+bksvNHYwNlJOS2UzWU9FRTJXRVBQbE9EajF3aFh4UGxZZTcyZXRnUm9uR2JOQ3lM" fullword wide
		 $s174= "MjA0OCE8UlNBS2V5VmFsdWU+PE1vZHVsdXM+clNGdWRrWmRpQkRNVVkzRnNGcDFKQXVsYWR1Y1UrNkFjK1B4Z2ZLcks1TFM5V0Z6" fullword wide
		 $s175= "ModerateThreatDefaultAction" fullword wide
		 $s176= "MTCqPq0O1iIn1l40MaqRNRPk5iJv9hVd9eAj8NbsKtJqKNyQ3r5cFWf4EburgEOTMonXlU1988GdIiZst32Sl3Xn9FfhctLGezef" fullword wide
		 $s177= "MzhGeFFvL3BsamYzMHlDdWh3Nmd1VEtaaVRJU0dHMW5rdzE5TlQyaS91TjFHQWRPTWFlVUhJY1FSeEZDcE8wczdSZEFRPT08L01v" fullword wide
		 $s178= "NtQuerySystemInformation" fullword wide
		 $s179= "NtReadVirtualMemory" fullword wide
		 $s180= "ntWB6ohspNIoCar" fullword wide
		 $s181= "ODgg4oCcJXPigJ0gJiBEZWwgL2YgL3Eg4oCcJXPigJ0=" fullword wide
		 $s182= "OriginalFilename" fullword wide
		 $s183= "OyBiYWNrZ3JvdW5kLWNvbG9yOiBibGFjazsiPjxzcGFuIHN0eWxlPSJjb2xvcjogI2ZmMDAwMDsgYmFja2dyb3VuZC1jb2xvcjog" fullword wide
		 $s184= "PGh0bWw+Cjxib2R5IHN0eWxlPSJiYWNrZ3JvdW5kLWNvbG9yOiBibGFjazsiPgo8cCBzdHlsZT0idGV4dC1hbGlnbjogY2VudGVy" fullword wide
		 $s185= "PHAgc3R5bGU9InRleHQtYWxpZ246IGNlbnRlcjsiPg==" fullword wide
		 $s186= "PHAgc3R5bGU9InRleHQtYWxpZ246IGNlbnRlcjsiPktleSBJZGVudGlmaWVyOiA=" fullword wide
		 $s187= "\\.PhysicalDrive0" fullword wide
		 $s188= "Pjwvc3Bhbj48L3NwYW4+PC9zcGFuPjwvcD4KCjxoMiBzdHlsZT0idGV4dC1hbGlnbjogY2VudGVyOyBjb2xvcjpyZWQ7Ij4KWW91" fullword wide
		 $s189= "PQ0KaW1wb3J0YW50IGZpbGVzLCBkb2N1bWVudHMgYW5kIGV0YyBkb3dubG9hZGVkLCBhZnRlciBwdXJjaGFzZSB0aW1lIGlmIHlv" fullword wide
		 $s190= "process call create cmd.exe /c \\" fullword wide
		 $s191= "PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQ0KRE9OVCBSRVNUQVJUIFBDDQpET05U" fullword wide
		 $s192= "PT09PT09PT09PT09PT09PT09PT09PT0NCmNvbnRhY3QgOiAwMDEwMDIwMDNAc2VjbWFpbC5wcm8=" fullword wide
		 $s193= "PWWPh5jww0vweJe 4pFhUfFs2GJ1B5U" fullword wide
		 $s194= "Q0ZGIEV4cGxvcmVy" fullword wide
		 $s195= "Q2xpZW50IElQOiAg" fullword wide
		 $s196= "Q2xpZW50IFVuaXF1ZSBJZGVudGlmaWVyIEtleTog" fullword wide
		 $s197= "Q3JlYXRlU2hvcnRjdXQ=" fullword wide
		 $s198= "QnVpbGRlcl9Mb2c=" fullword wide
		 $s199= "QWxsIHlvdXIgZmlsZXMgd2VyZSBlbmNyeXB0ZWQsIGlmIHlvdSB3YW50IHRvIGdldCB0aGVtIGFsbCBiYWNrLCBwbGVhc2UgY2Fy" fullword wide
		 $s200= "R2xrSkxRVldPb2MyKzZsYlh6OEw4TXZqaTNKc3BmTXZ5WnNFZyt1R1h3aTd3QXlyRnhCbzU2NEtqL2Y1b3NFWHFicm9obTdUci90" fullword wide
		 $s201= "RDkNCg0KQ29udGFjdCA6DQpqb3NlcGhudWxsQHNlY21haWwucHJvDQo=" fullword wide
		 $s202= "RGF0ZSBvZiBlbmNyeXB0aW9uOiA=" fullword wide
		 $s203= "RGVsZXRlIFNoYWRvd3MgL2FsbCAvcXVpZXQ=" fullword wide
		 $s204= "rhr836zCweqtsp86RxMksq5TFkdL9" fullword wide
		 $s205= "RW5hYmxlTGlua2VkQ29ubmVjdGlvbnM=" fullword wide
		 $s206= "S2V5IElkZW50aWZpZXI6IA==" fullword wide
		 $s207= "S3FINE9aSm85VjJvYmF3b0ZEMHdyWHdvTlpUc0t3S2diWTFHdXdhVXpQYk1NMEJsdFZVdS8zN0V5UFYySnVYcFZybHZXYVowSVFn" fullword wide
		 $s208= "Select * from Win32_ComputerSystem" fullword wide
		 $s209= "select * from Win32_NetworkConnection" fullword wide
		 $s210= "Set-MpPreference -DisableArchiveScanning $true" fullword wide
		 $s211= "Set-MpPreference -DisableBehaviorMonitoring $true" fullword wide
		 $s212= "Set-MpPreference -DisableBlockAtFirstSeen $true" fullword wide
		 $s213= "Set-MpPreference -DisableIntrusionPreventionSystem $true" fullword wide
		 $s214= "Set-MpPreference -DisableIOAVProtection $true" fullword wide
		 $s215= "Set-MpPreference -DisablePrivacyMode $true" fullword wide
		 $s216= "Set-MpPreference -DisableRealtimeMonitoring $true" fullword wide
		 $s217= "Set-MpPreference -DisableScriptScanning $true" fullword wide
		 $s218= "Set-MpPreference -HighThreatDefaultAction 6 -Force" fullword wide
		 $s219= "Set-MpPreference -LowThreatDefaultAction 6" fullword wide
		 $s220= "Set-MpPreference -MAPSReporting 0" fullword wide
		 $s221= "Set-MpPreference -ModerateThreatDefaultAction 6" fullword wide
		 $s222= "Set-MpPreference -SevereThreatDefaultAction 6" fullword wide
		 $s223= "Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true" fullword wide
		 $s224= "Set-MpPreference -SubmitSamplesConsent 2" fullword wide
		 $s225= "SevereThreatDefaultAction" fullword wide
		 $s226= "SFRUUE5ldHdvcmtTbmlmZmVy" fullword wide
		 $s227= "SignatureDisableUpdateOnStartupWithoutEngine" fullword wide
		 $s228= "SoftwareMicrosoftWindowsCurrentVersionPoliciesSystem" fullword wide
		 $s229= "SOFTWAREMicrosoftWindows DefenderFeatures" fullword wide
		 $s230= "SOFTWAREPoliciesMicrosoftWindows Defender" fullword wide
		 $s231= "SOFTWAREPoliciesMicrosoftWindows DefenderReal-Time Protection" fullword wide
		 $s232= "SubmitSamplesConsent" fullword wide
		 $s233= "SUVXYXRjaCBQcm9mZXNzaW9uYWw=" fullword wide
		 $s234= "SW50ZXJjZXB0ZXItTkc=" fullword wide
		 $s235= "SW5mb3JtYXRpb24uLi4=" fullword wide
		 $s236= "SyQCiwOs5CsYNDYJIz1mpRtmXUlEqykLsqXLlK6gpE6YqXEXLb4tWsFAFopOKKCGbhqhpMh83U6kUV59PO3P41y9lWG7esVeBz6J" fullword wide
		 $s237= "T1IgRVZFUg0KPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09" fullword wide
		 $s238= "T1NPRlQgUkVDT1ZFUlkgVE9PTCINCg0KQUxMIE9GIFRIT1NFIE5PVEVTIFdJTEwgQ0FVU0UgWU9VIExPU1QgWU9VUiBGSUxFUyBG" fullword wide
		 $s239= "TamperProtection" fullword wide
		 $s240= "TaskManagerWindow" fullword wide
		 $s241= "TG9jYWxBY2NvdW50VG9rZW5GaWx0ZXJQb2xpY3k=" fullword wide
		 $s242= "TGVnYWxOb3RpY2VDYXB0aW9u" fullword wide
		 $s243= "TGVnYWxOb3RpY2VUZXh0" fullword wide
		 $s244= "TmV0d29ya01pbmVy" fullword wide
		 $s245= "TmV0d29ya1RyYWZmaWNWaWV3" fullword wide
		 $s246= "TnVtYmVyIG9mIGZpbGVzIGVuY3J5cHRlZDog" fullword wide
		 $s247= "TnVtYmVyIG9mIGZpbGVzIHRoYXQgd2VyZSBwcm9jZXNzZWQgaXM6IA==" fullword wide
		 $s248= "tVGdzl3UcNXZpNWas9GUc52bpNnclZFduVmcyV3QcN3dvRmbpdFX0Z2bz9mcjlWTcVkUBdFVG90U" fullword wide
		 $s249= "TWVnYUR1bXBlcg==" fullword wide
		 $s250= "U2t1bGwtV2FsbHBhcGVyLTNELVdhbGxwYXBlcnMtTGF0ZXN0LmpwZyIgYWx0PSIiIHdpZHRoPSI2NTAiIGhlaWdodD0iNDAzIiAv" fullword wide
		 $s251= "U2t5cGVBcHAuZXhl" fullword wide
		 $s252= "U2V0LU1wUHJlZmVyZW5jZSAtRW5hYmxlQ29udHJvbGxlZEZvbGRlckFjY2VzcyBEaXNhYmxlZA==" fullword wide
		 $s253= "-u EDENFIELDefadmin -p P455w0rd -d -f -h -s -n 2 -c " fullword wide
		 $s254= "UG9zc2libGUgYWZmZWN0ZWQgZmlsZXM6IA==" fullword wide
		 $s255= "UHJvY2Vzc0hhY2tlcg==" fullword wide
		 $s256= "UkRHIFBhY2tlciBEZXRlY3Rvcg==" fullword wide
		 $s257= "/USER:EDENFIELDefadmin P455w0rd" fullword wide
		 $s258= "/user:EDENFIELDefadmin /password:P455w0rd process call create cmd.exe /c " fullword wide
		 $s259= "/user:EDENFIELDefadmin /password:P455w0rd process call create cmd.exe /c \\" fullword wide
		 $s260= "/USER:SHJPOLICEamer !Omar2012" fullword wide
		 $s261= "/user:SHJPOLICEamer /password:!Omar2012 process call create cmd.exe /c " fullword wide
		 $s262= "/user:SHJPOLICEamer /password:!Omar2012 process call create cmd.exe /c \\" fullword wide
		 $s263= "-u SHJPOLICEamer -p !Omar2012 -d -f -h -s -n 2 -c " fullword wide
		 $s264= "V1NjcmlwdC5TaGVsbA==" fullword wide
		 $s265= "VGhpcyBwcm9ncmFtIHJlcXVpcmVzIE1pY3Jvc29mdCAuTkVUIEZyYW1ld29yayB2LiA0LjgyIG9yIHN1cGVyaW9yIHRvIHJ1biBw" fullword wide
		 $s266= "VolumeSerialNumber" fullword wide
		 $s267= "VS_VERSION_INFO" fullword wide
		 $s268= "VW5Db25mdXNlckV4" fullword wide
		 $s269= "VW5pdmVyc2FsX0ZpeGVy" fullword wide
		 $s270= "win32_processor" fullword wide
		 $s271= "WW91ciBGaWxlcyBhcmUgRW5jcnlwdGVkLg0KDQpEb27igJl0IHdvcnJ5LCB5b3UgY2FuIHJldHVybiBhbGwgeW91ciBmaWxlcyEN" fullword wide
		 $s272= "WW91ciBmaWxlcyB3ZXJlIHNhZmVseSBjeXBoZXJlZC4NCg0KQ29udGFjdDogbXktY29udGFjdC1lbWFpbEBwcm90b25tYWlsLmNv" fullword wide
		 $s273= "x3ERlRedA1D7hOzArg2pn2VAG6zgtT44Q4uBxi86BMgesq1XrDyl6Rk5iEKpb8tq6JrmdyMIh5naV0RZFcypeT88UzdtYTeCczhj" fullword wide
		 $s274= "Y29uZmlnIFNRTFdyaXRlciBzdGFydD0gZGlzYWJsZWQ=" fullword wide
		 $s275= "Y29uZmlnIFNRTFRFTEVNRVRSWSBzdGFydD0gZGlzYWJsZWQ=" fullword wide
		 $s276= "Y29uZmlnIFNRTFRFTEVNRVRSWSRFQ1dEQjIgc3RhcnQ9IGRpc2FibGVk" fullword wide
		 $s277= "Y29uZmlnIFNzdHBTdmMgc3RhcnQ9IGRpc2FibGVk" fullword wide
		 $s278= "Y2hyb21lMzIuZXhl" fullword wide
		 $s279= "Y3RmbW9tLmV4ZQ==" fullword wide
		 $s280= "YmxhY2s7Ij48c3BhbiBzdHlsZT0iYmFja2dyb3VuZC1jb2xvcjogIzAwMDAwMDsiPjxzcGFuIHN0eWxlPSJiYWNrZ3JvdW5kLWNv" fullword wide
		 $s281= "YOkBRITTKNBYLVa qNEQn0mbG2wNoNm" fullword wide
		 $s282= "Z2V0IGFsbCB0aGluZ3MgdG8gdGhlIG5vcm1hbCA6IDIwLDAwMCQ8L2gzPgo8aDMgc3R5bGU9ImNvbG9yOnllbGxvdzsgdGV4dC1h" fullword wide
		 $s283= "ZCd2ZSB3aXBlIGFsbCBvZiB5b3VyIG5ldHdvcmsgYnV0IHRoYXQncyBub3QgaGVscGluZyBtZS4gOik8YnI+CnNvIHRlbXBvcmFy" fullword wide
		 $s284= "ZEZvQUlOT2VyalNUaFV3S1JuQTUwcW9qekRFc1kzbHhsMFVuUjlDaGJtL3JxM2s5NHZkbFVuNk1GZGw0cVFQTkowdC9SSzdyOGFh" fullword wide
		 $s285= "ZfUhRlZoDQQt7VjYzWt1RnVpugt2h6F7VQiyDYS6CO4IhMk1C6siQz4wKpwv2gGGLTYrwuUbDxzCsMHi52zkOgqgVwoYlhEfHy6N" fullword wide
		 $s286= "ZGxsaHN0LmV4ZQ==" fullword wide
		 $s287= "ZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjwvUlNBS2V5VmFsdWU+" fullword wide
		 $s288= "ZmlyZWZveC5leGU=" fullword wide
		 $s289= "zOkUbKBMOAPeePS1EXq5MTKAVWZs56CyKjA98tQ6SOUonzyHiIFgkBwfDj8EuTRS7bT4OT3UHum79fXfiRKw0gNJwf5YuLL97CqM" fullword wide
		 $s290= "ZWxwIHlvdSB0byBnZXQgb3V0IG9mIHRoaXMgc2l0dWF0aW9uLjxicj4KWW91J3ZlIGdvdCA0OCBob3VycygyIERheXMpLCBiZWZv" fullword wide
		 $s291= "ZWZ1bGx5IHJlYWQgdGhlIHRleHQgbm90ZSBsb2NhdGVkIGluIHlvdXIgZGVza3RvcC4uLg==" fullword wide
		 $s292= "ZWZmZXRlY2ggaHR0cCBzbmlmZmVy" fullword wide
		 $a1= "$F935DC23-1CF0-11D0-ADB9-00C04FD58A0B" fullword ascii
		 $a2= ">9__CachedAnonymousMethodDelegate2" fullword ascii
		 $a3= ">9__CachedAnonymousMethodDelegate3" fullword ascii
		 $a4= ">9__CachedAnonymousMethodDelegate4" fullword ascii
		 $a5= ">9__CachedAnonymousMethodDelegate8" fullword ascii
		 $a6= ">9__CachedAnonymousMethodDelegate9" fullword ascii
		 $a7= "CheckRemoteDebuggerPresent" fullword ascii
		 $a8= "CompilationRelaxationsAttribute" fullword ascii
		 $a9= "CompilerGeneratedAttribute" fullword ascii
		 $a10= "DirectoryNotFoundException" fullword ascii
		 $a11= "GenericSecurityDescriptor" fullword ascii
		 $a12= "GetAllMacAddressesAndIppairs" fullword ascii
		 $a13= "GetKeyFromEncryptionString" fullword ascii
		 $a14= "GetProcessSecurityDescriptor" fullword ascii
		 $a15= "InvalidOperationException" fullword ascii
		 $a16= "MacAddress>k__BackingField" fullword ascii
		 $a17= "ManagementObjectCollection" fullword ascii
		 $a18= "ManagementObjectEnumerator" fullword ascii
		 $a19= "Microsoft.VisualBasic.CompilerServices" fullword ascii
		 $a20= "Microsoft.VisualBasic.Devices" fullword ascii
		 $a21= "NtQuerySystemInformation_AsmOpCode" fullword ascii
		 $a22= "NtReadVirtualMemory_AsmOpCode" fullword ascii
		 $a23= "PlatformNotSupportedException" fullword ascii
		 $a24= "PrivateImplementationDetails>{10231E92-BCE6-4007-A463-67D77912E754}" fullword ascii
		 $a25= "ProcessCompareProductName" fullword ascii
		 $a26= "RecursiveReleaseFiles>b__0" fullword ascii
		 $a27= "RecursiveReleaseFiles>b__1" fullword ascii
		 $a28= "RegistryKeyPermissionCheck" fullword ascii
		 $a29= "RemoteGetProcAddressManual" fullword ascii
		 $a30= "RuntimeCompatibilityAttribute" fullword ascii
		 $a31= "SetProcessSecurityDescriptor" fullword ascii
		 $a32= "set_RedirectStandardError" fullword ascii
		 $a33= "set_RedirectStandardOutput" fullword ascii
		 $a34= "set_StandardOutputEncoding" fullword ascii
		 $a35= "__StaticArrayInitTypeSize=240" fullword ascii
		 $a36= "__StaticArrayInitTypeSize=405" fullword ascii
		 $a37= "__StaticArrayInitTypeSize=84" fullword ascii
		 $a38= "System.Collections.Generic" fullword ascii
		 $a39= "System.Collections.Specialized" fullword ascii
		 $a40= "System.Net.NetworkInformation" fullword ascii
		 $a41= "System.Runtime.CompilerServices" fullword ascii
		 $a42= "System.Runtime.InteropServices" fullword ascii
		 $a43= "System.Security.AccessControl" fullword ascii
		 $a44= "System.Security.Cryptography" fullword ascii
		 $a45= "System.Security.Principal" fullword ascii
		 $a46= "System.Text.RegularExpressions" fullword ascii
		 $a47= "UnauthorizedAccessException" fullword ascii

		 $hex1= {246131303d20224469}
		 $hex2= {246131313d20224765}
		 $hex3= {246131323d20224765}
		 $hex4= {246131333d20224765}
		 $hex5= {246131343d20224765}
		 $hex6= {246131353d2022496e}
		 $hex7= {246131363d20224d61}
		 $hex8= {246131373d20224d61}
		 $hex9= {246131383d20224d61}
		 $hex10= {246131393d20224d69}
		 $hex11= {2461313d2022244639}
		 $hex12= {246132303d20224d69}
		 $hex13= {246132313d20224e74}
		 $hex14= {246132323d20224e74}
		 $hex15= {246132333d2022506c}
		 $hex16= {246132343d20225072}
		 $hex17= {246132353d20225072}
		 $hex18= {246132363d20225265}
		 $hex19= {246132373d20225265}
		 $hex20= {246132383d20225265}
		 $hex21= {246132393d20225265}
		 $hex22= {2461323d20223e395f}
		 $hex23= {246133303d20225275}
		 $hex24= {246133313d20225365}
		 $hex25= {246133323d20227365}
		 $hex26= {246133333d20227365}
		 $hex27= {246133343d20227365}
		 $hex28= {246133353d20225f5f}
		 $hex29= {246133363d20225f5f}
		 $hex30= {246133373d20225f5f}
		 $hex31= {246133383d20225379}
		 $hex32= {246133393d20225379}
		 $hex33= {2461333d20223e395f}
		 $hex34= {246134303d20225379}
		 $hex35= {246134313d20225379}
		 $hex36= {246134323d20225379}
		 $hex37= {246134333d20225379}
		 $hex38= {246134343d20225379}
		 $hex39= {246134353d20225379}
		 $hex40= {246134363d20225379}
		 $hex41= {246134373d2022556e}
		 $hex42= {2461343d20223e395f}
		 $hex43= {2461353d20223e395f}
		 $hex44= {2461363d20223e395f}
		 $hex45= {2461373d2022436865}
		 $hex46= {2461383d2022436f6d}
		 $hex47= {2461393d2022436f6d}
		 $hex48= {24733130303d202264}
		 $hex49= {24733130313d202244}
		 $hex50= {24733130323d202244}
		 $hex51= {24733130333d202244}
		 $hex52= {24733130343d202244}
		 $hex53= {24733130353d202244}
		 $hex54= {24733130363d202244}
		 $hex55= {24733130373d202244}
		 $hex56= {24733130383d202244}
		 $hex57= {24733130393d202244}
		 $hex58= {247331303d20226133}
		 $hex59= {24733131303d202244}
		 $hex60= {24733131313d202244}
		 $hex61= {24733131323d202264}
		 $hex62= {24733131333d202264}
		 $hex63= {24733131343d202264}
		 $hex64= {24733131353d202264}
		 $hex65= {24733131363d202265}
		 $hex66= {24733131373d202265}
		 $hex67= {24733131383d202265}
		 $hex68= {24733131393d202265}
		 $hex69= {247331313d20226133}
		 $hex70= {24733132303d202266}
		 $hex71= {24733132313d202246}
		 $hex72= {24733132323d202246}
		 $hex73= {24733132333d202267}
		 $hex74= {24733132343d202267}
		 $hex75= {24733132353d202247}
		 $hex76= {24733132363d202247}
		 $hex77= {24733132373d202248}
		 $hex78= {24733132383d202248}
		 $hex79= {24733132393d202248}
		 $hex80= {247331323d20226133}
		 $hex81= {24733133303d202248}
		 $hex82= {24733133313d202268}
		 $hex83= {24733133323d202248}
		 $hex84= {24733133333d202249}
		 $hex85= {24733133343d202249}
		 $hex86= {24733133353d202249}
		 $hex87= {24733133363d202249}
		 $hex88= {24733133373d202249}
		 $hex89= {24733133383d202249}
		 $hex90= {24733133393d202249}
		 $hex91= {247331333d20224164}
		 $hex92= {24733134303d202249}
		 $hex93= {24733134313d202249}
		 $hex94= {24733134323d202269}
		 $hex95= {24733134333d202249}
		 $hex96= {24733134343d202249}
		 $hex97= {24733134353d20226a}
		 $hex98= {24733134363d20226a}
		 $hex99= {24733134373d20224b}
		 $hex100= {24733134383d20224b}
		 $hex101= {24733134393d20224b}
		 $hex102= {247331343d20226164}
		 $hex103= {24733135303d20224b}
		 $hex104= {24733135313d20224b}
		 $hex105= {24733135323d20224b}
		 $hex106= {24733135333d20224c}
		 $hex107= {24733135343d20224c}
		 $hex108= {24733135353d20224c}
		 $hex109= {24733135363d20224c}
		 $hex110= {24733135373d20224c}
		 $hex111= {24733135383d20224c}
		 $hex112= {24733135393d20224c}
		 $hex113= {247331353d20224164}
		 $hex114= {24733136303d20224c}
		 $hex115= {24733136313d20224c}
		 $hex116= {24733136323d20224c}
		 $hex117= {24733136333d20224c}
		 $hex118= {24733136343d20224c}
		 $hex119= {24733136353d20224c}
		 $hex120= {24733136363d20224c}
		 $hex121= {24733136373d20224c}
		 $hex122= {24733136383d20224c}
		 $hex123= {24733136393d20224c}
		 $hex124= {247331363d20226164}
		 $hex125= {24733137303d20226d}
		 $hex126= {24733137313d20224d}
		 $hex127= {24733137323d20226d}
		 $hex128= {24733137333d20224d}
		 $hex129= {24733137343d20224d}
		 $hex130= {24733137353d20224d}
		 $hex131= {24733137363d20224d}
		 $hex132= {24733137373d20224d}
		 $hex133= {24733137383d20224e}
		 $hex134= {24733137393d20224e}
		 $hex135= {247331373d20224164}
		 $hex136= {24733138303d20226e}
		 $hex137= {24733138313d20224f}
		 $hex138= {24733138323d20224f}
		 $hex139= {24733138333d20224f}
		 $hex140= {24733138343d202250}
		 $hex141= {24733138353d202250}
		 $hex142= {24733138363d202250}
		 $hex143= {24733138373d20222e}
		 $hex144= {24733138383d202250}
		 $hex145= {24733138393d202250}
		 $hex146= {247331383d20226147}
		 $hex147= {24733139303d202270}
		 $hex148= {24733139313d202250}
		 $hex149= {24733139323d202250}
		 $hex150= {24733139333d202250}
		 $hex151= {24733139343d202251}
		 $hex152= {24733139353d202251}
		 $hex153= {24733139363d202251}
		 $hex154= {24733139373d202251}
		 $hex155= {24733139383d202251}
		 $hex156= {24733139393d202251}
		 $hex157= {247331393d20226148}
		 $hex158= {2473313d2022333734}
		 $hex159= {24733230303d202252}
		 $hex160= {24733230313d202252}
		 $hex161= {24733230323d202252}
		 $hex162= {24733230333d202252}
		 $hex163= {24733230343d202272}
		 $hex164= {24733230353d202252}
		 $hex165= {24733230363d202253}
		 $hex166= {24733230373d202253}
		 $hex167= {24733230383d202253}
		 $hex168= {24733230393d202273}
		 $hex169= {247332303d20226148}
		 $hex170= {24733231303d202253}
		 $hex171= {24733231313d202253}
		 $hex172= {24733231323d202253}
		 $hex173= {24733231333d202253}
		 $hex174= {24733231343d202253}
		 $hex175= {24733231353d202253}
		 $hex176= {24733231363d202253}
		 $hex177= {24733231373d202253}
		 $hex178= {24733231383d202253}
		 $hex179= {24733231393d202253}
		 $hex180= {247332313d20226148}
		 $hex181= {24733232303d202253}
		 $hex182= {24733232313d202253}
		 $hex183= {24733232323d202253}
		 $hex184= {24733232333d202253}
		 $hex185= {24733232343d202253}
		 $hex186= {24733232353d202253}
		 $hex187= {24733232363d202253}
		 $hex188= {24733232373d202253}
		 $hex189= {24733232383d202253}
		 $hex190= {24733232393d202253}
		 $hex191= {247332323d20226148}
		 $hex192= {24733233303d202253}
		 $hex193= {24733233313d202253}
		 $hex194= {24733233323d202253}
		 $hex195= {24733233333d202253}
		 $hex196= {24733233343d202253}
		 $hex197= {24733233353d202253}
		 $hex198= {24733233363d202253}
		 $hex199= {24733233373d202254}
		 $hex200= {24733233383d202254}
		 $hex201= {24733233393d202254}
		 $hex202= {247332333d20224173}
		 $hex203= {24733234303d202254}
		 $hex204= {24733234313d202254}
		 $hex205= {24733234323d202254}
		 $hex206= {24733234333d202254}
		 $hex207= {24733234343d202254}
		 $hex208= {24733234353d202254}
		 $hex209= {24733234363d202254}
		 $hex210= {24733234373d202254}
		 $hex211= {24733234383d202274}
		 $hex212= {24733234393d202254}
		 $hex213= {247332343d20226157}
		 $hex214= {24733235303d202255}
		 $hex215= {24733235313d202255}
		 $hex216= {24733235323d202255}
		 $hex217= {24733235333d20222d}
		 $hex218= {24733235343d202255}
		 $hex219= {24733235353d202255}
		 $hex220= {24733235363d202255}
		 $hex221= {24733235373d20222f}
		 $hex222= {24733235383d20222f}
		 $hex223= {24733235393d20222f}
		 $hex224= {247332353d2022615a}
		 $hex225= {24733236303d20222f}
		 $hex226= {24733236313d20222f}
		 $hex227= {24733236323d20222f}
		 $hex228= {24733236333d20222d}
		 $hex229= {24733236343d202256}
		 $hex230= {24733236353d202256}
		 $hex231= {24733236363d202256}
		 $hex232= {24733236373d202256}
		 $hex233= {24733236383d202256}
		 $hex234= {24733236393d202256}
		 $hex235= {247332363d20226232}
		 $hex236= {24733237303d202277}
		 $hex237= {24733237313d202257}
		 $hex238= {24733237323d202257}
		 $hex239= {24733237333d202278}
		 $hex240= {24733237343d202259}
		 $hex241= {24733237353d202259}
		 $hex242= {24733237363d202259}
		 $hex243= {24733237373d202259}
		 $hex244= {24733237383d202259}
		 $hex245= {24733237393d202259}
		 $hex246= {247332373d20226233}
		 $hex247= {24733238303d202259}
		 $hex248= {24733238313d202259}
		 $hex249= {24733238323d20225a}
		 $hex250= {24733238333d20225a}
		 $hex251= {24733238343d20225a}
		 $hex252= {24733238353d20225a}
		 $hex253= {24733238363d20225a}
		 $hex254= {24733238373d20225a}
		 $hex255= {24733238383d20225a}
		 $hex256= {24733238393d20227a}
		 $hex257= {247332383d20226247}
		 $hex258= {24733239303d20225a}
		 $hex259= {24733239313d20225a}
		 $hex260= {24733239323d20225a}
		 $hex261= {247332393d20226247}
		 $hex262= {2473323d2022334647}
		 $hex263= {247333303d20226247}
		 $hex264= {247333313d2022626d}
		 $hex265= {247333323d2022626e}
		 $hex266= {247333333d20226254}
		 $hex267= {247333343d20226257}
		 $hex268= {247333353d20226258}
		 $hex269= {247333363d20224324}
		 $hex270= {247333373d20224324}
		 $hex271= {247333383d20226333}
		 $hex272= {247333393d20226333}
		 $hex273= {2473333d20223d3432}
		 $hex274= {247334303d20226333}
		 $hex275= {247334313d20226333}
		 $hex276= {247334323d20226333}
		 $hex277= {247334333d20226333}
		 $hex278= {247334343d20226333}
		 $hex279= {247334353d20226333}
		 $hex280= {247334363d20226333}
		 $hex281= {247334373d20226333}
		 $hex282= {247334383d20226333}
		 $hex283= {247334393d20226333}
		 $hex284= {2473343d2022365754}
		 $hex285= {247335303d20226333}
		 $hex286= {247335313d20226333}
		 $hex287= {247335323d20226333}
		 $hex288= {247335333d20226333}
		 $hex289= {247335343d20226333}
		 $hex290= {247335353d20226333}
		 $hex291= {247335363d20226333}
		 $hex292= {247335373d20226333}
		 $hex293= {247335383d20226333}
		 $hex294= {247335393d20226333}
		 $hex295= {2473353d202237574c}
		 $hex296= {247336303d20226333}
		 $hex297= {247336313d20226333}
		 $hex298= {247336323d20226333}
		 $hex299= {247336333d20226333}
		 $hex300= {247336343d20226333}
		 $hex301= {247336353d20226333}
		 $hex302= {247336363d20226333}
		 $hex303= {247336373d20226333}
		 $hex304= {247336383d20226333}
		 $hex305= {247336393d20226333}
		 $hex306= {2473363d2022394f34}
		 $hex307= {247337303d20226333}
		 $hex308= {247337313d20226333}
		 $hex309= {247337323d20226333}
		 $hex310= {247337333d20226333}
		 $hex311= {247337343d20226333}
		 $hex312= {247337353d20226333}
		 $hex313= {247337363d20226333}
		 $hex314= {247337373d20224367}
		 $hex315= {247337383d20226348}
		 $hex316= {247337393d20226369}
		 $hex317= {2473373d2022613356}
		 $hex318= {247338303d20226369}
		 $hex319= {247338313d2022636d}
		 $hex320= {247338323d2022636d}
		 $hex321= {247338333d2022636d}
		 $hex322= {247338343d2022636d}
		 $hex323= {247338353d2022636d}
		 $hex324= {247338363d2022636d}
		 $hex325= {247338373d2022636d}
		 $hex326= {247338383d2022636d}
		 $hex327= {247338393d2022636d}
		 $hex328= {2473383d2022613356}
		 $hex329= {247339303d2022636d}
		 $hex330= {247339313d2022636d}
		 $hex331= {247339323d2022636d}
		 $hex332= {247339333d2022636d}
		 $hex333= {247339343d20226320}
		 $hex334= {247339353d2022436f}
		 $hex335= {247339363d20222f63}
		 $hex336= {247339373d20226432}
		 $hex337= {247339383d20226443}
		 $hex338= {247339393d20222d64}
		 $hex339= {2473393d2022613356}

	condition:
		42 of them
}
