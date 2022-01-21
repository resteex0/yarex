
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_MacOS_Zuru 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_MacOS_Zuru {
	meta: 
		 description= "vx_underground2_MacOS_Zuru Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-10-34" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2786ebc3b917866d30e622325fc6f5f3"
		 hash2= "47d774e5307215c7c11151211c8d3ce2"
		 hash3= "4e245480d5f4136a49f6b0f50c6152c4"
		 hash4= "8a599494142af7c44ece6001383ee43a"
		 hash5= "b14c9a8c917c5f30c44ec3860c476e8b"
		 hash6= "fbf5372905fc4a53084ed30727ae5e82"

	strings:

	
 		 $a1= "___43-[AFHTTPRequestSerializer encodeWithCoder:]_block_invoke" fullword ascii
		 $a2= "___45-[AFHTTPRequestSerializer HTTPRequestHeaders]_block_invoke" fullword ascii
		 $a3= "___45+[AFNetworkReachabilityManager sharedManager]_block_invoke" fullword ascii
		 $a4= "+[AFHTTPRequestSerializer automaticallyNotifiesObserversForKey:]" fullword ascii
		 $a5= "-[AFHTTPRequestSerializer HTTPMethodsEncodingParametersInURI]" fullword ascii
		 $a6= "-[AFHTTPRequestSerializer setMutableObservedChangedKeyPaths:]" fullword ascii
		 $a7= "-[AFHTTPRequestSerializer setQueryStringSerializationStyle:]" fullword ascii
		 $a8= "-[AFHTTPRequestSerializer setQueryStringSerializationWithBlock:]" fullword ascii
		 $a9= "-[AFHTTPRequestSerializer setQueryStringSerializationWithStyle:]" fullword ascii
		 $a10= "-[AFHTTPRequestSerializer setRequestHeaderModificationQueue:]" fullword ascii
		 $a11= "-[AFHTTPSessionManager HEAD:parameters:headers:success:failure:]" fullword ascii
		 $a12= "-[AFHTTPSessionManager initWithBaseURL:sessionConfiguration:]" fullword ascii
		 $a13= "-[AFHTTPSessionManager PUT:parameters:headers:success:failure:]" fullword ascii
		 $a14= "-[AFMultipartBodyStream _setCFClientFlags:callback:context:]" fullword ascii
		 $a15= "-[AFNetworkReachabilityManager networkReachabilityStatusBlock]" fullword ascii
		 $a16= "-[AFNetworkReachabilityManager setNetworkReachabilityStatus:]" fullword ascii
		 $a17= "+[AFSecurityPolicy keyPathsForValuesAffectingPinnedPublicKeys]" fullword ascii
		 $a18= "-[AFStreamingMultipartFormData appendPartWithFormData:name:]" fullword ascii
		 $a19= "_AFURLSessionDownloadTaskDidMoveFileSuccessfullyNotification" fullword ascii
		 $a20= "-[AFURLSessionManager didFinishEventsForBackgroundURLSession]" fullword ascii
		 $a21= "-[AFURLSessionManager mutableTaskDelegatesKeyedByTaskIdentifier]" fullword ascii
		 $a22= "-[AFURLSessionManager sessionDidReceiveAuthenticationChallenge]" fullword ascii
		 $a23= "-[AFURLSessionManager setDataTaskDidBecomeDownloadTaskBlock:]" fullword ascii
		 $a24= "-[AFURLSessionManager setDownloadTaskDidFinishDownloadingBlock:]" fullword ascii
		 $a25= "-[AFURLSessionManager setTaskDidFinishCollectingMetricsBlock:]" fullword ascii
		 $a26= "-[AFURLSessionManager setTaskWillPerformHTTPRedirectionBlock:]" fullword ascii
		 $a27= "-[AFURLSessionManagerTaskDelegate setDownloadProgressBlock:]" fullword ascii
		 $a28= "-[AFURLSessionManager URLSession:didBecomeInvalidWithError:]" fullword ascii
		 $a29= "-[AFURLSessionManager URLSession:task:didCompleteWithError:]" fullword ascii
		 $a30= "com.alamofire.networking.session.download.file-manager-error" fullword ascii
		 $a31= "com.alamofire.networking.session.download.file-manager-succeed" fullword ascii
		 $a32= "downloadTaskWithRequest:progress:destination:completionHandler:" fullword ascii
		 $a33= "/Library/Caches/com.apple.xbs/Sources/arclite/arclite-76/source/" fullword ascii
		 $a34= "__OBJC_$_INSTANCE_VARIABLES_AFPropertyListResponseSerializer" fullword ascii
		 $a35= "__OBJC_$_PROTOCOL_INSTANCE_METHODS_AFURLRequestSerialization" fullword ascii
		 $a36= "__OBJC_$_PROTOCOL_INSTANCE_METHODS_AFURLResponseSerialization" fullword ascii
		 $a37= "__OBJC_$_PROTOCOL_INSTANCE_METHODS___ARCLiteKeyedSubscripting__" fullword ascii
		 $a38= "__OBJC_$_PROTOCOL_INSTANCE_METHODS_NSURLSessionDownloadDelegate" fullword ascii
		 $a39= "__OBJC_$_PROTOCOL_INSTANCE_METHODS_OPT_NSURLSessionDataDelegate" fullword ascii
		 $a40= "__OBJC_$_PROTOCOL_INSTANCE_METHODS_OPT_NSURLSessionTaskDelegate" fullword ascii
		 $a41= "__OBJC_$_PROTOCOL_METHOD_TYPES___ARCLiteIndexedSubscripting__" fullword ascii
		 $a42= "_OBJC_IVAR_$_AFCompoundResponseSerializer._responseSerializers" fullword ascii
		 $a43= "_OBJC_IVAR_$_AFHTTPRequestSerializer._HTTPShouldHandleCookies" fullword ascii
		 $a44= "_OBJC_IVAR_$_AFHTTPRequestSerializer._HTTPShouldUsePipelining" fullword ascii
		 $a45= "_OBJC_IVAR_$_AFHTTPRequestSerializer._mutableHTTPRequestHeaders" fullword ascii
		 $a46= "_OBJC_IVAR_$_AFHTTPRequestSerializer._queryStringSerialization" fullword ascii
		 $a47= "_OBJC_IVAR_$_AFHTTPResponseSerializer._acceptableContentTypes" fullword ascii
		 $a48= "_OBJC_IVAR_$_AFHTTPResponseSerializer._acceptableStatusCodes" fullword ascii
		 $a49= "_OBJC_IVAR_$_AFJSONResponseSerializer._removesKeysWithNullValues" fullword ascii
		 $a50= "_OBJC_IVAR_$_AFNetworkReachabilityManager._networkReachability" fullword ascii
		 $a51= "_OBJC_IVAR_$_AFURLSessionManager._authenticationChallengeHandler" fullword ascii
		 $a52= "_OBJC_IVAR_$_AFURLSessionManager._dataTaskDidBecomeDownloadTask" fullword ascii
		 $a53= "_OBJC_IVAR_$_AFURLSessionManager._dataTaskDidReceiveResponse" fullword ascii
		 $a54= "_OBJC_IVAR_$_AFURLSessionManagerTaskDelegate._completionHandler" fullword ascii
		 $a55= "_OBJC_IVAR_$_AFURLSessionManagerTaskDelegate._downloadFileURL" fullword ascii
		 $a56= "_OBJC_IVAR_$_AFURLSessionManagerTaskDelegate._downloadProgress" fullword ascii
		 $a57= "_OBJC_IVAR_$_AFURLSessionManagerTaskDelegate._sessionTaskMetrics" fullword ascii
		 $a58= "_OBJC_IVAR_$_AFURLSessionManagerTaskDelegate._uploadProgress" fullword ascii
		 $a59= "_OBJC_IVAR_$_AFURLSessionManager._taskDidFinishCollectingMetrics" fullword ascii
		 $a60= "_OBJC_IVAR_$_AFURLSessionManager._taskWillPerformHTTPRedirection" fullword ascii
		 $a61= "/sendRelease3.1/crypto.2/AFNetworking/AFHTTPSessionManager.m" fullword ascii
		 $a62= "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit" fullword ascii
		 $a63= "URLSession:downloadTask:didResumeAtOffset:expectedTotalBytes:" fullword ascii
		 $a64= "__ZGVZL30add_image_hook_autoreleasepoolPK11mach_headerlE7patches" fullword ascii
		 $a65= "__ZL36__arclite_object_setInstanceVariableP11objc_objectPKcPv" fullword ascii
		 $a66= "__ZL43__arclite_objc_retainAutoreleaseReturnValueP11objc_object" fullword ascii
		 $a67= "__ZL44__arclite_objc_retainAutoreleasedReturnValueP11objc_object" fullword ascii
		 $a68= "__ZZL30add_image_hook_autoreleasepoolPK11mach_headerlE7patches" fullword ascii

		 $hex1= {246131303d20222d5b}
		 $hex2= {246131313d20222d5b}
		 $hex3= {246131323d20222d5b}
		 $hex4= {246131333d20222d5b}
		 $hex5= {246131343d20222d5b}
		 $hex6= {246131353d20222d5b}
		 $hex7= {246131363d20222d5b}
		 $hex8= {246131373d20222b5b}
		 $hex9= {246131383d20222d5b}
		 $hex10= {246131393d20225f41}
		 $hex11= {2461313d20225f5f5f}
		 $hex12= {246132303d20222d5b}
		 $hex13= {246132313d20222d5b}
		 $hex14= {246132323d20222d5b}
		 $hex15= {246132333d20222d5b}
		 $hex16= {246132343d20222d5b}
		 $hex17= {246132353d20222d5b}
		 $hex18= {246132363d20222d5b}
		 $hex19= {246132373d20222d5b}
		 $hex20= {246132383d20222d5b}
		 $hex21= {246132393d20222d5b}
		 $hex22= {2461323d20225f5f5f}
		 $hex23= {246133303d2022636f}
		 $hex24= {246133313d2022636f}
		 $hex25= {246133323d2022646f}
		 $hex26= {246133333d20222f4c}
		 $hex27= {246133343d20225f5f}
		 $hex28= {246133353d20225f5f}
		 $hex29= {246133363d20225f5f}
		 $hex30= {246133373d20225f5f}
		 $hex31= {246133383d20225f5f}
		 $hex32= {246133393d20225f5f}
		 $hex33= {2461333d20225f5f5f}
		 $hex34= {246134303d20225f5f}
		 $hex35= {246134313d20225f5f}
		 $hex36= {246134323d20225f4f}
		 $hex37= {246134333d20225f4f}
		 $hex38= {246134343d20225f4f}
		 $hex39= {246134353d20225f4f}
		 $hex40= {246134363d20225f4f}
		 $hex41= {246134373d20225f4f}
		 $hex42= {246134383d20225f4f}
		 $hex43= {246134393d20225f4f}
		 $hex44= {2461343d20222b5b41}
		 $hex45= {246135303d20225f4f}
		 $hex46= {246135313d20225f4f}
		 $hex47= {246135323d20225f4f}
		 $hex48= {246135333d20225f4f}
		 $hex49= {246135343d20225f4f}
		 $hex50= {246135353d20225f4f}
		 $hex51= {246135363d20225f4f}
		 $hex52= {246135373d20225f4f}
		 $hex53= {246135383d20225f4f}
		 $hex54= {246135393d20225f4f}
		 $hex55= {2461353d20222d5b41}
		 $hex56= {246136303d20225f4f}
		 $hex57= {246136313d20222f73}
		 $hex58= {246136323d20222f53}
		 $hex59= {246136333d20225552}
		 $hex60= {246136343d20225f5f}
		 $hex61= {246136353d20225f5f}
		 $hex62= {246136363d20225f5f}
		 $hex63= {246136373d20225f5f}
		 $hex64= {246136383d20225f5f}
		 $hex65= {2461363d20222d5b41}
		 $hex66= {2461373d20222d5b41}
		 $hex67= {2461383d20222d5b41}
		 $hex68= {2461393d20222d5b41}

	condition:
		45 of them
}
