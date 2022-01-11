
/*
   YARA Rule Set
   Author: resteex
   Identifier: FancyBear_GermanParliament 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_FancyBear_GermanParliament {
	meta: 
		 description= "FancyBear_GermanParliament Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-25-59" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "77e7fb6b56c3ece4ef4e93b6dc608be0"

	strings:

	
 		 $a1= "ImpersonateNamedPipeClient" fullword ascii
		 $a2= "InitializeCriticalSection" fullword ascii
		 $a3= "InitializeSecurityDescriptor" fullword ascii
		 $a4= "\\.pipeahexec_stderr%08X" fullword ascii
		 $a5= "\\.pipeahexec_stdin%08X" fullword ascii
		 $a6= "\\.pipeahexec_stdout%08X" fullword ascii
		 $a7= "RegisterServiceCtrlHandlerA" fullword ascii
		 $a8= "_set_invalid_parameter_handler" fullword ascii
		 $a9= "SetSecurityDescriptorDacl" fullword ascii
		 $a10= "SetUnhandledExceptionFilter" fullword ascii
		 $a11= "StartServiceCtrlDispatcherA" fullword ascii

		 $hex1= {246131303d20225365}
		 $hex2= {246131313d20225374}
		 $hex3= {2461313d2022496d70}
		 $hex4= {2461323d2022496e69}
		 $hex5= {2461333d2022496e69}
		 $hex6= {2461343d20222e7069}
		 $hex7= {2461353d20222e7069}
		 $hex8= {2461363d20222e7069}
		 $hex9= {2461373d2022526567}
		 $hex10= {2461383d20225f7365}
		 $hex11= {2461393d2022536574}

	condition:
		1 of them
}
