from datetime import datetime

from xml.dom.minidom import parseString as xmlStringParser

#<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
#            xmlns:a="http://www.w3.org/2005/08/addressing">
#	<s:Header>
#		<a:Action s:mustUnderstand="1">http://tempuri.org/IConnectorIncidentManager/AddOrUpdateIncident2Response</a:Action>
#		<a:RelatesTo>urn:uuid:8253c2dd-df3f-4fc5-a10b-aaee8da3ea59</a:RelatesTo>
#	</s:Header>
#	<s:Body>
#		<AddOrUpdateIncident2Response xmlns="http://tempuri.org/">
#			<AddOrUpdateIncident2Result xmlns:b="http://schemas.datacontract.org/2004/07/Microsoft.AzureAd.Icm.Types"
#			                            xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
#				<b:IncidentId>393089853</b:IncidentId>
#				<b:Status>AddedNew</b:Status>
#				<b:SubStatus>None</b:SubStatus>
#				<b:UpdateProcessTime>2023-05-27T19:39:03.7966685Z</b:UpdateProcessTime>
#			</AddOrUpdateIncident2Result>
#		</AddOrUpdateIncident2Response>
#	</s:Body>
#</s:Envelope>

responseText = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing"><s:Header><a:Action s:mustUnderstand="1">http://tempuri.org/IConnectorIncidentManager/AddOrUpdateIncident2Response</a:Action><a:RelatesTo>urn:uuid:8253c2dd-df3f-4fc5-a10b-aaee8da3ea59</a:RelatesTo></s:Header><s:Body><AddOrUpdateIncident2Response xmlns="http://tempuri.org/"><AddOrUpdateIncident2Result xmlns:b="http://schemas.datacontract.org/2004/07/Microsoft.AzureAd.Icm.Types" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><b:IncidentId>393089853</b:IncidentId><b:Status>AddedNew</b:Status><b:SubStatus>None</b:SubStatus><b:UpdateProcessTime>2023-05-27T19:39:03.7966685Z</b:UpdateProcessTime></AddOrUpdateIncident2Result></AddOrUpdateIncident2Response></s:Body></s:Envelope>'
_IcM_Response_AsXMLdocument = xmlStringParser(responseText)
if	len(_IcM_Response_AsXMLdocument.getElementsByTagName('s:Body'))	>=	int(0):
	if	len(_IcM_Response_AsXMLdocument.getElementsByTagName('AddOrUpdateIncident2Response'))	>=	int(0):
		if	len(_IcM_Response_AsXMLdocument.getElementsByTagName('AddOrUpdateIncident2Result'))	>=	int(0):
			if	len(_IcM_Response_AsXMLdocument.getElementsByTagName('b:IncidentId'))	>=	int(0):
				if	len((((_IcM_Response_AsXMLdocument.getElementsByTagName('b:IncidentId'))[0]).childNodes))	>=	int(0):
					if	str(((((_IcM_Response_AsXMLdocument.getElementsByTagName('b:IncidentId'))[0]).childNodes)[0]).nodeValue)	!=	None:
						if	int(str(((((_IcM_Response_AsXMLdocument.getElementsByTagName('b:IncidentId'))[0]).childNodes)[0]).nodeValue))	>	int(0):
							_NewIncident_IncidentId		=	int(str(((((_IcM_Response_AsXMLdocument.getElementsByTagName('b:IncidentId'))[0]).childNodes)[0]).nodeValue))
			if	len(_IcM_Response_AsXMLdocument.getElementsByTagName('b:UpdateProcessTime'))	>=	int(0):
				if	len((((_IcM_Response_AsXMLdocument.getElementsByTagName('b:UpdateProcessTime'))[0]).childNodes))	>=	int(0):
					if	str(((((_IcM_Response_AsXMLdocument.getElementsByTagName('b:UpdateProcessTime'))[0]).childNodes)[0]).nodeValue)	!=	None:
						if	len(str(((((_IcM_Response_AsXMLdocument.getElementsByTagName('b:UpdateProcessTime'))[0]).childNodes)[0]).nodeValue))	>=	int(26):
							_NewIncident_UpdateProcessTime	=	datetime.strptime((str(((((_IcM_Response_AsXMLdocument.getElementsByTagName('b:UpdateProcessTime'))[0]).childNodes)[0]).nodeValue))[:26], '%Y-%m-%dT%H:%M:%S.%f')
## documentCollection = document.documentElement
## document.firstChild.tagName >> s:Envelope


## ((((_IcM_Response_AsXMLdocument.getElementsByTagName('b:IncidentId'))[0]).childNodes)[0]).nodeValue >> 393089853


####import xml.etree.ElementTree as ET
####tree = ET.ElementTree(ET.fromstring(responseText))
####root = tree.getroot()

print('loco')