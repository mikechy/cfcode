<cfcomponent displayname="Cloudfront Library" output="false">

<cfset variables.host = "https://cloudfront.amazonaws.com">
<cfset variables.apiversion = "2010-11-01">
<cfset variables.distributionid = "d32q088j4pz12d">
<cfset variables.awsaccesskeyid = "xxx">
<cfset variables.secretkey = "xxx">

<cffunction name="invalidate" returntype="struct" access="public" output="false">
	<cfargument name="fpaths" type="array" required="true">
	
	<cfset var body = "">
	<cfset var path = "">
	<cfset var httpresponse = "">
			
	<cfsavecontent variable="body"><cfoutput>
	<?xml version="1.0" encoding="UTF-8"?>
	<InvalidationBatch>
	<cfloop array="#arguments.fpaths#" index="path">
	<Path>#XMLFormat(path)#</Path>
	</cfloop>
	<CallerReference>#CreateUUID()#</CallerReference>
	</InvalidationBatch>
	</cfoutput></cfsavecontent>

	<cfset httpresponse = postInvalidationRequest(body=body)>
	<cfreturn httpresponse>
</cffunction>

<cffunction name="postInvalidationRequest" returntype="struct" access="private" output="false">
	<cfargument name="body" type="string" required="true">

	<cfset var httpresponse = "">
	<cfset var dateTimeString = GetHTTPTimeString(Now())>
	<cfset var authstring = "AWS " & variables.awsaccesskeyid & ":" & createSignature(dateTimeString,variables.secretkey)>
	
	<cfhttp url="#variables.host#/#variables.apiversion#/distribution/#variables.distributionid#/invalidation"
		method="post" charset="utf-8" result="httpresponse">
		<cfhttpparam type="header" name="Content-Type" value="text/xml">
		<cfhttpparam type="header" name="Date" value="#dateTimeString#">
		<cfhttpparam type="header" name="Authorization" value="#authstring#">
		<cfhttpparam type="body" value="#arguments.body#">
	</cfhttp>

	<cfreturn httpresponse>
</cffunction>

<cffunction name="HMAC_SHA1" returntype="binary" access="private" output="false" hint="NSA SHA-1 Algorithm">
   <cfargument name="signKey" type="string" required="true" />
   <cfargument name="signMessage" type="string" required="true" />

   <cfset var jMsg = JavaCast("string",arguments.signMessage).getBytes("iso-8859-1") />
   <cfset var jKey = JavaCast("string",arguments.signKey).getBytes("iso-8859-1") />
   <cfset var key = createObject("java","javax.crypto.spec.SecretKeySpec") />
   <cfset var mac = createObject("java","javax.crypto.Mac") />

   <cfset key = key.init(jKey,"HmacSHA1") />
   <cfset mac = mac.getInstance(key.getAlgorithm()) />
   <cfset mac.init(key) />
   <cfset mac.update(jMsg) />

   <cfreturn mac.doFinal() />
</cffunction>

<cffunction name="createSignature" returntype="string" access="public" output="false">
   <cfargument name="dateTimeString" type="string" required="true" />
   <cfargument name="secretAccessKey" type="string" required="true" />

	
	<cfset var fixedData = arguments.dateTimeString>
	<!--- Calculate the hash of the information --->
	<cfset var digest = HMAC_SHA1(arguments.secretAccessKey,fixedData)>
	<!--- fix the returned data to be a proper signature --->
	<cfset var signature = ToBase64("#digest#")>
	
	<cfreturn signature>
</cffunction>
	
</cfcomponent>
