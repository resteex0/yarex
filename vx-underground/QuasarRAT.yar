
/*
   YARA Rule Set
   Author: resteex
   Identifier: QuasarRAT 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_QuasarRAT {
	meta: 
		 description= "QuasarRAT Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-17-06" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "742d07180cb13ef49af926500163da5d"

	strings:

	
 		 $s1= "(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})" fullword wide
		 $s2= "2HN2qpRf4gopcSrthYZdXUjkhxfVN/J8A3NbVTXwYjQ=" fullword wide
		 $s3= "4AhCdBjv5Q3oYi825KFDbkr/J0QjeArLsVbmrBFEC74=" fullword wide
		 $s4= "A@B@C@EDQPpoyx" fullword wide
		 $s5= "bDbmZ+NfPt8jbxcR51W1OcmGuwqjDSCNGPTfqbKTMzQ=" fullword wide
		 $s6= "https://freegeoip.net/xml/" fullword wide
		 $s7= "IProducerConsumerCollection`1" fullword wide
		 $s8= "MetadataTimeoutMilliseconds" fullword wide
		 $s9= "NHibernate.Intercept.IFieldInterceptorAccessor" fullword wide
		 $s10= "NHibernate.Proxy.DynamicProxy.IProxy" fullword wide
		 $s11= "NHibernate.Proxy.INHibernateProxy" fullword wide
		 $s12= "ProtoBuf.ProtoAfterDeserializationAttribute" fullword wide
		 $s13= "ProtoBuf.ProtoAfterSerializationAttribute" fullword wide
		 $s14= "ProtoBuf.ProtoBeforeDeserializationAttribute" fullword wide
		 $s15= "ProtoBuf.ProtoBeforeSerializationAttribute" fullword wide
		 $s16= "ProtoBuf.ProtoContractAttribute" fullword wide
		 $s17= "ProtoBuf.ProtoEnumAttribute" fullword wide
		 $s18= "ProtoBuf.ProtoIgnoreAttribute" fullword wide
		 $s19= "ProtoBuf.ProtoIncludeAttribute" fullword wide
		 $s20= "ProtoBuf.ProtoMemberAttribute" fullword wide
		 $s21= "ProtoBuf.ProtoPartialIgnoreAttribute" fullword wide
		 $s22= "ProtoBuf.ProtoPartialMemberAttribute" fullword wide
		 $s23= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s24= "SOFTWAREMicrosoftWindowsCurrentVersionRunOnce" fullword wide
		 $s25= "SOFTWAREWow6432NodeMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s26= "SOFTWAREWow6432NodeMicrosoftWindowsCurrentVersionRunOnce" fullword wide
		 $s27= "System.Collections.Concurrent.IProducerConsumerCollection`1" fullword wide
		 $s28= "System.ComponentModel.DefaultValueAttribute" fullword wide
		 $s29= "System.Data.Entity.DynamicProxies." fullword wide
		 $s30= "System.Data.Linq.EntitySet`1[[" fullword wide
		 $s31= "System.NonSerializedAttribute" fullword wide
		 $s32= "System.Runtime.Serialization.DataContractAttribute" fullword wide
		 $s33= "System.Runtime.Serialization.DataMemberAttribute" fullword wide
		 $s34= "System.Runtime.Serialization.OnDeserializedAttribute" fullword wide
		 $s35= "System.Runtime.Serialization.OnDeserializingAttribute" fullword wide
		 $s36= "System.Runtime.Serialization.OnSerializedAttribute" fullword wide
		 $s37= "System.Runtime.Serialization.OnSerializingAttribute" fullword wide
		 $s38= "System.Xml.Serialization.XmlArrayAttribute" fullword wide
		 $s39= "System.Xml.Serialization.XmlElementAttribute" fullword wide
		 $s40= "System.Xml.Serialization.XmlIgnoreAttribute" fullword wide
		 $s41= "System.Xml.Serialization.XmlTypeAttribute" fullword wide
		 $s42= "xClient.Properties.Resources" fullword wide
		 $a1= "SOFTWAREWow6432NodeMicrosoftWindowsCurrentVersionRun" fullword ascii
		 $a2= "SOFTWAREWow6432NodeMicrosoftWindowsCurrentVersionRunOnce" fullword ascii
		 $a3= "System.Collections.Concurrent.IProducerConsumerCollection`1" fullword ascii
		 $a4= "System.Runtime.Serialization.DataContractAttribute" fullword ascii
		 $a5= "System.Runtime.Serialization.OnDeserializedAttribute" fullword ascii
		 $a6= "System.Runtime.Serialization.OnDeserializingAttribute" fullword ascii
		 $a7= "System.Runtime.Serialization.OnSerializedAttribute" fullword ascii
		 $a8= "System.Runtime.Serialization.OnSerializingAttribute" fullword ascii

		 $hex1= {2461313d2022534f46}
		 $hex2= {2461323d2022534f46}
		 $hex3= {2461333d2022537973}
		 $hex4= {2461343d2022537973}
		 $hex5= {2461353d2022537973}
		 $hex6= {2461363d2022537973}
		 $hex7= {2461373d2022537973}
		 $hex8= {2461383d2022537973}
		 $hex9= {247331303d20224e48}
		 $hex10= {247331313d20224e48}
		 $hex11= {247331323d20225072}
		 $hex12= {247331333d20225072}
		 $hex13= {247331343d20225072}
		 $hex14= {247331353d20225072}
		 $hex15= {247331363d20225072}
		 $hex16= {247331373d20225072}
		 $hex17= {247331383d20225072}
		 $hex18= {247331393d20225072}
		 $hex19= {2473313d2022282e7b}
		 $hex20= {247332303d20225072}
		 $hex21= {247332313d20225072}
		 $hex22= {247332323d20225072}
		 $hex23= {247332333d2022536f}
		 $hex24= {247332343d2022534f}
		 $hex25= {247332353d2022534f}
		 $hex26= {247332363d2022534f}
		 $hex27= {247332373d20225379}
		 $hex28= {247332383d20225379}
		 $hex29= {247332393d20225379}
		 $hex30= {2473323d202232484e}
		 $hex31= {247333303d20225379}
		 $hex32= {247333313d20225379}
		 $hex33= {247333323d20225379}
		 $hex34= {247333333d20225379}
		 $hex35= {247333343d20225379}
		 $hex36= {247333353d20225379}
		 $hex37= {247333363d20225379}
		 $hex38= {247333373d20225379}
		 $hex39= {247333383d20225379}
		 $hex40= {247333393d20225379}
		 $hex41= {2473333d2022344168}
		 $hex42= {247334303d20225379}
		 $hex43= {247334313d20225379}
		 $hex44= {247334323d20227843}
		 $hex45= {2473343d2022414042}
		 $hex46= {2473353d2022624462}
		 $hex47= {2473363d2022687474}
		 $hex48= {2473373d2022495072}
		 $hex49= {2473383d20224d6574}
		 $hex50= {2473393d20224e4869}

	condition:
		33 of them
}
