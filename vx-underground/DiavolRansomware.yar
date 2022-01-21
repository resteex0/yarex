
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_DiavolRansomware 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_DiavolRansomware {
	meta: 
		 description= "vx_underground2_DiavolRansomware Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-54-50" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "f4928b5365a0bd6db2e9d654a77308d7"

	strings:

	
 		 $s1= "BackupExecAgentAccelerator" fullword wide
		 $s2= "BackupExecDeviceMediaService" fullword wide
		 $s3= "BackupExecManagementService" fullword wide
		 $s4= "BgIAAACkAABSU0ExAAQAAAEAAQCxVuiQzWxjl9dwh2F77Jxqt/PIrJoczV2RKluW" fullword wide
		 $s5= "McAfeeFrameworkMcAfeeFramework" fullword wide
		 $s6= "MSSQLFDLauncher$PROFXENGAGEMENT" fullword wide
		 $s7= "MSSQLFDLauncher$SBSMONITORING" fullword wide
		 $s8= "MSSQLFDLauncher$SHAREPOINT" fullword wide
		 $s9= "MSSQLFDLauncher$SYSTEM_BGC" fullword wide
		 $s10= "M+xv0gSAZrL8DncWw9hif+zsvJq6PcqC0NugL3raLFbaUCUT8KAGgrOkIPmnrQpz" fullword wide
		 $s11= "SQLAgent$CITRIX_METAFRAME" fullword wide
		 $s12= "SQLAgent$SOPHsvcGenericHost" fullword wide
		 $s13= "VeeamEnterpriseManagerSvc" fullword wide

		 $hex1= {247331303d20224d2b}
		 $hex2= {247331313d20225351}
		 $hex3= {247331323d20225351}
		 $hex4= {247331333d20225665}
		 $hex5= {2473313d2022426163}
		 $hex6= {2473323d2022426163}
		 $hex7= {2473333d2022426163}
		 $hex8= {2473343d2022426749}
		 $hex9= {2473353d20224d6341}
		 $hex10= {2473363d20224d5353}
		 $hex11= {2473373d20224d5353}
		 $hex12= {2473383d20224d5353}
		 $hex13= {2473393d20224d5353}

	condition:
		8 of them
}
