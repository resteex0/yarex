
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Fareit 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Fareit {
	meta: 
		 description= "Win32_Fareit Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_22-52-19" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "15540d149889539308135fa12bedbcbf"
		 hash2= "1d34d800aa3320dc17a5786f8eec16ee"
		 hash3= "301210d5557d9ba34f401d3ef7a7276f"
		 hash4= "60c01a897dd8d60d3fea002ed3a4b764"
		 hash5= "67e4f5301851646b10a95f65a0b3bacb"
		 hash6= "8953398de47344e9c2727565af8d6f31"
		 hash7= "d883dc7acc192019f220409ee2cadd64"
		 hash8= "df5a394ad60512767d375647dbb82994"
		 hash9= "f1e546fe9d51dc96eb766ec61269edfb"
		 hash10= "f77db63cbed98391027f2525c14e161f"

	strings:

	
 		 $s1= "SoftwareMicrosoftWindowsCurrentVersion" fullword wide
		 $s2= "__tmp_rar_sfx_access_check_%u" fullword wide

		 $hex1= {2473313d2022536f66}
		 $hex2= {2473323d20225f5f74}

	condition:
		1 of them
}
