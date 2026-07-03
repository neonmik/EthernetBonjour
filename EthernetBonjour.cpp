//  Copyright (C) 2010 Georg Kaindl
//  http://gkaindl.com
//
//  This file is part of Arduino EthernetBonjour.
//
//  EthernetBonjour is free software: you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public License
//  as published by the Free Software Foundation, either version 3 of
//  the License, or (at your option) any later version.
//
//  EthernetBonjour is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with EthernetBonjour. If not, see
//  <http://www.gnu.org/licenses/>.
//

#define  HAS_SERVICE_REGISTRATION      1	// disabling saves about 1.25 kilobytes
#define  HAS_NAME_BROWSING             1	// disable together with above, additionally saves about 4.3 kilobytes

#include <string.h>
#include <stdlib.h>
#include <Arduino.h>
#include <Ethernet.h>
#include <EthernetUdp.h>

extern "C" {
   #include <utility/EthernetUtil.h>
}

#include "EthernetBonjour.h"

#define  MDNS_DEFAULT_NAME       "arduino"
#define  MDNS_TLD                ".local"
#define  DNS_SD_SERVICE          "_services._dns-sd._udp.local"
#define  MDNS_SERVER_PORT        (5353)
#define  MDNS_NQUERY_RESEND_TIME (1000)		// 1 second, name query resend timeout
#define  MDNS_SQUERY_RESEND_TIME (10000)	// 10 seconds, service query resend timeout
#define  MDNS_RESPONSE_TTL       (120)		// two minutes (in seconds)

#define  MDNS_MAX_SERVICES_PER_PACKET  (16)

// Uncomment to enable low-level parser tracing via Serial
#define BONJOUR_DEBUG 1

//#define  _BROKEN_MALLOC_   1
#undef _USE_MALLOC_

static uint8_t mdnsMulticastIPAddr[] = { 224, 0, 0, 251 };
//static uint8_t mdnsHWAddr[] = { 0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb };

typedef enum _MDNSPacketType_t {
	MDNSPacketTypeMyIPAnswer,
	MDNSPacketTypeNoIPv6AddrAvailable,
	MDNSPacketTypeServiceRecord,
	MDNSPacketTypeServiceRecordRelease,
	MDNSPacketTypeNameQuery,
	MDNSPacketTypeServiceQuery,
} MDNSPacketType_t;

typedef struct _DNSHeader_t {
	uint16_t xid;
	uint8_t recursionDesired : 1;
	uint8_t truncated : 1;
	uint8_t authoritiveAnswer : 1;
	uint8_t opCode : 4;
	uint8_t queryResponse : 1;
	uint8_t responseCode : 4;
	uint8_t checkingDisabled : 1;
	uint8_t authenticatedData : 1;
	uint8_t zReserved : 1;
	uint8_t recursionAvailable : 1;
	uint16_t queryCount;
	uint16_t answerCount;
	uint16_t authorityCount;
	uint16_t additionalCount;
} __attribute__( (__packed__) ) DNSHeader_t;

typedef enum _DNSOpCode_t {
	DNSOpQuery     = 0,
	DNSOpIQuery    = 1,
	DNSOpStatus    = 2,
	DNSOpNotify    = 4,
	DNSOpUpdate    = 5
} DNSOpCode_t;

// for some reason, I get data corruption issues with normal malloc() on arduino 0017
void* my_malloc(unsigned s)
{
#if defined(_BROKEN_MALLOC_)
	char* b = (char*)malloc(s + 2);
	if (b)
		b++;

	return (void*)b;
#else
	return malloc(s);
#endif
}

void my_free(void* ptr)
{
#if defined(_BROKEN_MALLOC_)
	char* b = (char*)ptr;
	if (b)
		b--;

	free(b);
#else
	free(ptr);
#endif
}

EthernetBonjourClass::EthernetBonjourClass()
{
	memset( &this->_mdnsData, 0, sizeof(MDNSDataInternal_t) );
	memset( &this->_serviceRecords, 0, sizeof(this->_serviceRecords) );

	this->_state = MDNSStateIdle;
//   this->_sock = -1;

	this->_bonjourName = NULL;
	this->_bonjourName2 = NULL;
	this->_resolveNames[0] = NULL;
	this->_resolveNames[1] = NULL;

	this->_lastAnnounceMillis = 0;
}

EthernetBonjourClass::~EthernetBonjourClass()
{
	this->stop();
}

// return values:
// 1 on success
// 0 otherwise
int EthernetBonjourClass::begin(const char* bonjourName)
{
	// if we were called very soon after the board was booted, we need to give the
	// EthernetShield (WIZnet) some time to come up. Hence, we delay until millis() is at
	// least 3000. This is necessary, so that if we need to add a service record directly
	// after begin, the announce packet does not get lost in the bowels of the WIZnet chip.
	while (millis() < 3000) delay(100);

	int statusCode = 0;
	statusCode = this->setBonjourName(bonjourName);
	if (statusCode)
		statusCode = this->beginMulticast(mdnsMulticastIPAddr, MDNS_SERVER_PORT);

	return statusCode;
}

// return values:
// 1 on success
// 0 otherwise
int EthernetBonjourClass::begin()
{
	return this->begin(MDNS_DEFAULT_NAME);
}

// return values:
// 1 on success
// 0 otherwise
int EthernetBonjourClass::_initQuery(uint8_t idx, const char* name, unsigned long timeout)
{
	int statusCode = 0;

	if ( NULL == this->_resolveNames[idx] && NULL != ( (0 == idx) ? (void*)this->_nameFoundCallback :
							   (void*)this->_serviceFoundCallback ) ) {
		this->_resolveNames[idx] = (uint8_t*)name;

		if (timeout)
			this->_resolveTimeouts[idx] = millis() + timeout;
		else
			this->_resolveTimeouts[idx] = 0;

		statusCode = ( MDNSSuccess == this->_sendMDNSMessage(0,
								     0,
								     (idx == 0) ? MDNSPacketTypeNameQuery :
								     MDNSPacketTypeServiceQuery,
								     0) );
	} else
		my_free( (void*)name );

	return statusCode;
}

void EthernetBonjourClass::_cancelQuery(uint8_t idx)
{
	if (NULL != this->_resolveNames[idx]) {
		my_free(this->_resolveNames[idx]);
		this->_resolveNames[idx] = NULL;
	}
}

// return values:
// 1 on success
// 0 otherwise
int EthernetBonjourClass::resolveName(const char* name, unsigned long timeout)
{
	this->cancelResolveName();

	char* n = (char*)my_malloc(strlen(name) + 7);
	if (NULL == n)
		return 0;

	strcpy(n, name);
	strcat(n, MDNS_TLD);

	return this->_initQuery(0, n, timeout);
}

void EthernetBonjourClass::setNameResolvedCallback(BonjourNameFoundCallback newCallback)
{
	this->_nameFoundCallback = newCallback;
}

void EthernetBonjourClass::cancelResolveName()
{
	this->_cancelQuery(0);
}

int EthernetBonjourClass::isResolvingName()
{
	return (NULL != this->_resolveNames[0]);
}

void EthernetBonjourClass::setServiceFoundCallback(BonjourServiceFoundCallback newCallback)
{
	this->_serviceFoundCallback = newCallback;
}

// return values:
// 1 on success
// 0 otherwise
int EthernetBonjourClass::startDiscoveringService(const char* serviceName,
						  MDNSServiceProtocol_t proto,
						  unsigned long timeout)
{
	this->stopDiscoveringService();

	char* n = (char*)my_malloc(strlen(serviceName) + 13);
	if (NULL == n)
		return 0;

	strcpy(n, serviceName);

	const uint8_t* srv_type = this->_postfixForProtocol(proto);
	if (srv_type)
		strcat(n, (const char*)srv_type);

	this->_resolveServiceProto = proto;

	return this->_initQuery(1, n, timeout);
}

void EthernetBonjourClass::stopDiscoveringService()
{
	this->_cancelQuery(1);
}

int EthernetBonjourClass::isDiscoveringService()
{
	return (NULL != this->_resolveNames[1]);
}

// return value:
// A DNSError_t (DNSSuccess on success, something else otherwise)
// in "int" mode: positive on success, negative on error
MDNSError_t EthernetBonjourClass::_sendMDNSMessage(uint32_t peerAddress, uint32_t xid, int type,
						   int serviceRecord)
{
	MDNSError_t statusCode = MDNSSuccess;
	uint16_t ptr = 0;
#if defined(_USE_MALLOC_)
	DNSHeader_t* dnsHeader = NULL;
#else
	DNSHeader_t dnsHeaderBuf;
	DNSHeader_t* dnsHeader = &dnsHeaderBuf;
#endif
	uint8_t* buf;



#if defined(_USE_MALLOC_)
	dnsHeader = (DNSHeader_t*)my_malloc( sizeof(DNSHeader_t) );
	if (NULL == dnsHeader) {
		statusCode = MDNSOutOfMemory;
		goto errorReturn;
	}
#endif

	memset( dnsHeader, 0, sizeof(DNSHeader_t) );

	dnsHeader->xid = ethutil_htons(xid);
	dnsHeader->opCode = DNSOpQuery;

	switch (type) {
		case MDNSPacketTypeServiceRecordRelease:
		case MDNSPacketTypeMyIPAnswer:
			dnsHeader->answerCount = ethutil_htons(1);
			dnsHeader->queryResponse = 1;
			dnsHeader->authoritiveAnswer = 1;
			break;
		case MDNSPacketTypeServiceRecord:
			dnsHeader->answerCount = ethutil_htons(4);
			dnsHeader->additionalCount = ethutil_htons(1);
			dnsHeader->queryResponse = 1;
			dnsHeader->authoritiveAnswer = 1;
			break;
		case MDNSPacketTypeNameQuery:
		case MDNSPacketTypeServiceQuery:
			dnsHeader->queryCount = ethutil_htons(1);
			break;
		case MDNSPacketTypeNoIPv6AddrAvailable:
			dnsHeader->queryCount = ethutil_htons(1);
			dnsHeader->additionalCount = ethutil_htons(1);
			dnsHeader->responseCode = 0x03;
			dnsHeader->authoritiveAnswer = 1;
			dnsHeader->queryResponse = 1;
			break;
	}




	this->beginPacket(mdnsMulticastIPAddr,MDNS_SERVER_PORT);
	this->write( (uint8_t*)dnsHeader,sizeof(DNSHeader_t) );

	ptr += sizeof(DNSHeader_t);
	buf = (uint8_t*)dnsHeader;

	// construct the answer section
	switch (type) {
		case MDNSPacketTypeMyIPAnswer: {
			// serviceRecord param is repurposed: 0=primary, 1=secondary hostname
			uint8_t* hostName = (serviceRecord == 0) ? this->_bonjourName : this->_bonjourName2;
			this->_writeMyIPAnswerRecord( &ptr, buf, sizeof(DNSHeader_t), hostName );
			break;
		}

#if defined(HAS_SERVICE_REGISTRATION) && HAS_SERVICE_REGISTRATION

		case MDNSPacketTypeServiceRecord: {

			// SRV location record
			this->_writeServiceRecordName(serviceRecord, &ptr, buf, sizeof(DNSHeader_t), 0);

			buf[0] = 0x00;
			buf[1] = 0x21;	// SRV record
			buf[2] = 0x80;	// cache flush
			buf[3] = 0x01;	// class IN

			// ttl
			*( (uint32_t*)&buf[4] ) = ethutil_htonl(MDNS_RESPONSE_TTL);

			// data length
			*( (uint16_t*)&buf[8] ) = ethutil_htons( 8 + strlen( (char*)this->_bonjourName ) );

			this->write( (uint8_t*)buf,10 );
			ptr += 10;
			// priority and weight
			buf[0] = buf[1] = buf[2] = buf[3] = 0;

			// port
			*( (uint16_t*)&buf[4] ) = ethutil_htons(this->_serviceRecords[serviceRecord]->port);

			this->write( (uint8_t*)buf,6 );
			ptr += 6;
			// target
			this->_writeDNSName(this->_bonjourName, &ptr, buf, sizeof(DNSHeader_t), 1);

			// TXT record
			this->_writeServiceRecordName(serviceRecord, &ptr, buf, sizeof(DNSHeader_t), 0);

			buf[0] = 0x00;
			buf[1] = 0x10;	// TXT record
			buf[2] = 0x80;	// cache flush
			buf[3] = 0x01;	// class IN

			// ttl
			*( (uint32_t*)&buf[4] ) = ethutil_htonl(MDNS_RESPONSE_TTL);

			this->write( (uint8_t*)buf,8 );
			ptr += 8;

			// data length && text
			if (NULL == this->_serviceRecords[serviceRecord]->textContent) {
				buf[0] = 0x00;
				buf[1] = 0x01;
				buf[2] = 0x00;

				this->write( (uint8_t*)buf,3 );
				ptr += 3;
			} else {
				int slen = strlen( (char*)this->_serviceRecords[serviceRecord]->textContent );
				*( (uint16_t*)buf ) = ethutil_htons(slen);
				this->write( (uint8_t*)buf,2 );
				ptr += 2;

				this->write( (uint8_t*)this->_serviceRecords[serviceRecord]->textContent,slen );
				ptr += slen;
			}

			// PTR record (for the dns-sd service in general)
			this->_writeDNSName( (const uint8_t*)DNS_SD_SERVICE, &ptr, buf,
					     sizeof(DNSHeader_t), 1 );

			buf[0] = 0x00;
			buf[1] = 0x0c;	// PTR record
			buf[2] = 0x00;	// no cache flush
			buf[3] = 0x01;	// class IN

			// ttl
			*( (uint32_t*)&buf[4] ) = ethutil_htonl(MDNS_RESPONSE_TTL);

			// data length.
			uint16_t dlen = strlen( (char*)this->_serviceRecords[serviceRecord]->servName ) + 2;
			*( (uint16_t*)&buf[8] ) = ethutil_htons(dlen);

			this->write( (uint8_t*)buf, 10 );
			ptr += 10;

			this->_writeServiceRecordName(serviceRecord, &ptr, buf, sizeof(DNSHeader_t), 1);

			// PTR record (our service)
			this->_writeServiceRecordPTR(serviceRecord, &ptr, buf, sizeof(DNSHeader_t),
						     MDNS_RESPONSE_TTL);

			// finally, our IP address as additional record
			this->_writeMyIPAnswerRecord( &ptr, buf, sizeof(DNSHeader_t), this->_bonjourName );

			break;
		}

		case MDNSPacketTypeServiceRecordRelease: {
			// just send our service PTR with a TTL of zero
			this->_writeServiceRecordPTR(serviceRecord, &ptr, buf, sizeof(DNSHeader_t), 0);
			break;
		}

#endif	// defined(HAS_SERVICE_REGISTRATION) && HAS_SERVICE_REGISTRATION

#if defined(HAS_NAME_BROWSING) && HAS_NAME_BROWSING

		case MDNSPacketTypeNameQuery:
		case MDNSPacketTypeServiceQuery:
		{
			// construct a query for the currently set _resolveNames[0]
			this->_writeDNSName(
				(type == MDNSPacketTypeServiceQuery) ? this->_resolveNames[1] :
				this->_resolveNames[0],
				&ptr, buf, sizeof(DNSHeader_t), 1);

			buf[0] = buf[2] = 0x0;
			buf[1] = (type == MDNSPacketTypeServiceQuery) ? 0x0c : 0x01;
			buf[3] = 0x1;

			this->write( (uint8_t*)buf, sizeof(DNSHeader_t) );
			ptr += sizeof(DNSHeader_t);

			this->_resolveLastSendMillis[(type == MDNSPacketTypeServiceQuery) ? 1 : 0] = millis();

			break;
		}

#endif	// defined(HAS_NAME_BROWSING) && HAS_NAME_BROWSING

		case MDNSPacketTypeNoIPv6AddrAvailable: {
			// since the WIZnet doesn't have IPv6, we will respond with a Not Found message
			this->_writeDNSName(this->_bonjourName, &ptr, buf, sizeof(DNSHeader_t), 1);

			buf[0] = buf[2] = 0x0;
			buf[1] = 0x1c;	// AAAA record
			buf[3] = 0x01;

			this->write( (uint8_t*)buf, 4 );
			ptr += 4;

			// send our IPv4 address record as additional record, in case the peer wants it.
			this->_writeMyIPAnswerRecord( &ptr, buf, sizeof(DNSHeader_t), this->_bonjourName );

			break;
		}
	}


	this->endPacket();


#if defined(_USE_MALLOC_)

errorReturn:
	if (NULL != dnsHeader)
		my_free(dnsHeader);
#endif

	return statusCode;
}

// Parses a SRV record at *pOffset. Reads TTL(4)+dataLen(2) then SRV payload priority(2)+weight(2)+port(2)+target.
// Advances *pOffset past the full record. Returns false on bounds error or short payload.
bool EthernetBonjourClass::_parseSRVRecord(const uint8_t* pkt, int* pOffset, int pktLen,
                                            uint16_t* portOut, uint16_t* ipOut)
{
	if (*pOffset + 6 > pktLen) return false;
	uint8_t tmp[8];
	memcpy(tmp, pkt + *pOffset, 6);
	*pOffset += 6;
	uint16_t dataLen = ethutil_ntohs(*(uint16_t*)&tmp[4]);
	if (dataLen < 8 || *pOffset + (int)dataLen > pktLen) {
		if (*pOffset + (int)dataLen <= pktLen) *pOffset += dataLen;
		return false;
	}
	memcpy(tmp, pkt + *pOffset, 8);
	*portOut = ethutil_ntohs(*(uint16_t*)&tmp[4]);
	// SRV target: first byte >128 means DNS name compression pointer
	if (tmp[6] > 128)
		*ipOut = ((uint16_t)(tmp[6] & 0x3F) << 8) | tmp[7];
	else
		*ipOut = (uint16_t)(*pOffset + 6);
	*pOffset += dataLen;
	return true;
}

// return value:
// A DNSError_t (DNSSuccess on success, something else otherwise)
// in "int" mode: positive on success, negative on error
MDNSError_t EthernetBonjourClass::_processMDNSQuery()
{
	MDNSError_t statusCode = MDNSSuccess;
#if defined(_USE_MALLOC_)
	DNSHeader_t* dnsHeader = NULL;
#else
	DNSHeader_t dnsHeaderBuf;
	DNSHeader_t* dnsHeader = &dnsHeaderBuf;
#endif
	uint16_t i, j;
	uint8_t* buf;
	uint32_t xid;
	uint16_t udp_len, qCnt, aCnt, aaCnt, addCnt;
	uint8_t recordsAskedFor[NumMDNSServiceRecords + 3];
	uint8_t recordsFound[2];
	uint8_t wantsIPv6Addr = 0;
	uint8_t* udpBuffer = NULL;

	memset(recordsAskedFor, 0, sizeof(uint8_t) * (NumMDNSServiceRecords + 3));
	memset(recordsFound, 0, sizeof(uint8_t) * 2);

	udp_len = this->parsePacket();
	if (0 == udp_len) {
		statusCode = MDNSTryLater;
		goto errorReturn;
	}

	// Discard oversized datagrams before allocating. No legitimate mDNS packet exceeds a
	// jumbo Ethernet frame. Guards against heap exhaustion from alien multicast traffic
	// (Dante, AVB, etc.) that lands on 224.0.0.251.
	if (udp_len > 9000) {
		this->flush();
		statusCode = MDNSInvalidArgument;
		goto errorReturn;
	}

	udpBuffer = (uint8_t*)my_malloc(udp_len);
	if (NULL == udpBuffer) {
		this->flush();
		statusCode = MDNSOutOfMemory;
		goto errorReturn;
	}
	this->read((uint8_t*)udpBuffer, udp_len);

#if defined(_USE_MALLOC_)
	dnsHeader = (DNSHeader_t*)my_malloc(sizeof(DNSHeader_t));
	if (NULL == dnsHeader) {
		statusCode = MDNSOutOfMemory;
		goto errorReturn;
	}
#endif

	buf = (uint8_t*)dnsHeader;
	memcpy((uint8_t*)buf, udpBuffer, sizeof(DNSHeader_t));

	xid = ethutil_ntohs(dnsHeader->xid);
	qCnt = ethutil_ntohs(dnsHeader->queryCount);
	aCnt = ethutil_ntohs(dnsHeader->answerCount);
	aaCnt = ethutil_ntohs(dnsHeader->authorityCount);
	addCnt = ethutil_ntohs(dnsHeader->additionalCount);

	if (0 == dnsHeader->queryResponse &&
	    DNSOpQuery == dnsHeader->opCode &&
	    MDNS_SERVER_PORT == this->remotePort())
	{
		// process an incoming MDNS query (someone looking for our name/services)
		int offset = sizeof(DNSHeader_t);
		int rLen = 0, tLen = 0;

		for (i = 0; i < qCnt; i++) {
			const uint8_t* servNames[NumMDNSServiceRecords + 3];
			int servLens[NumMDNSServiceRecords + 3];
			uint8_t servNamePos[NumMDNSServiceRecords + 3];
			uint8_t servMatches[NumMDNSServiceRecords + 3];

			// primary hostname
			servNames[0] = (const uint8_t*)this->_bonjourName;
			servNamePos[0] = 0;
			servLens[0] = strlen((char*)this->_bonjourName);
			servMatches[0] = 1;

			// secondary hostname (e.g. makeitgo.local)
			if (this->_bonjourName2 != NULL) {
				servNames[1] = (const uint8_t*)this->_bonjourName2;
				servNamePos[1] = 0;
				servLens[1] = strlen((char*)this->_bonjourName2);
				servMatches[1] = 1;
			} else {
				servNames[1] = NULL;
				servNamePos[1] = 0;
				servLens[1] = 0;
				servMatches[1] = 0;
			}

			// general DNS-SD service browser entry
			servNames[2] = (const uint8_t*)DNS_SD_SERVICE;
			servNamePos[2] = 0;
			servLens[2] = strlen((char*)DNS_SD_SERVICE);
			servMatches[2] = 1;

			for (j = 3; j < NumMDNSServiceRecords + 3; j++)
				if (NULL != this->_serviceRecords[j-3] && NULL != this->_serviceRecords[j-3]->servName) {
					servNames[j] = this->_serviceRecords[j-3]->servName;
					servLens[j] = strlen((char*)servNames[j]);
					servMatches[j] = 1;
					servNamePos[j] = 0;
				} else {
					servNames[j] = NULL;
					servLens[j] = 0;
					servMatches[j] = 0;
					servNamePos[j] = 0;
				}

			tLen = 0;
			do {
				if (offset >= (int)udp_len) goto errorReturn;
				memcpy((uint8_t*)buf, udpBuffer + offset, 1);
				offset += 1;
				rLen = buf[0];
				tLen += 1;

				if (rLen > 128) {
					if (offset >= (int)udp_len) goto errorReturn;
					memcpy((uint8_t*)buf, udpBuffer + offset, 1);
					offset += 1;
					for (j = 0; j < NumMDNSServiceRecords + 3; j++) {
						if (servNamePos[j] && servNamePos[j] != buf[0])
							servMatches[j] = 0;
					}
					tLen += 1;
				} else if (rLen > 0) {
					int tr = rLen, ir;
					while (tr > 0) {
						ir = (tr > (int)sizeof(DNSHeader_t)) ? (int)sizeof(DNSHeader_t) : tr;
						if (offset + ir > (int)udp_len) goto errorReturn;
						memcpy((uint8_t*)buf, udpBuffer + offset, ir);
						offset += ir;
						tr -= ir;
						for (j = 0; j < NumMDNSServiceRecords + 3; j++) {
							if (!recordsAskedFor[j] && servMatches[j])
								servMatches[j] &= this->_matchStringPart(&servNames[j], &servLens[j], buf, ir);
						}
					}
					tLen += rLen;
				}
			} while (rLen > 0 && rLen <= 128);

			if (offset + 4 > (int)udp_len) goto errorReturn;
			memcpy((uint8_t*)buf, udpBuffer + offset, 4);
			offset += 4;

			for (j = 0; j < NumMDNSServiceRecords + 3; j++) {
				if (!recordsAskedFor[j] && servNames[j] && servMatches[j] && 0 == servLens[j]) {
					if (0 == servNamePos[j])
						servNamePos[j] = offset - 4 - tLen;
					if (buf[0] == 0 && buf[3] == 0x01 && (buf[2] == 0x00 || buf[2] == 0x80)) {
						if (((j == 0 || j == 1) && 0x01 == buf[1]) ||
						    (j > 1 && (0x0c == buf[1] || 0x10 == buf[1] || 0x21 == buf[1])))
							recordsAskedFor[j] = 1;
						else if ((j == 0 || j == 1) && 0x1c == buf[1])
							wantsIPv6Addr = 1;
					}
				}
			}
		}
	}

#if (defined(HAS_SERVICE_REGISTRATION) && HAS_SERVICE_REGISTRATION) || (defined(HAS_NAME_BROWSING) && HAS_NAME_BROWSING)

	else if (1 == dnsHeader->queryResponse &&
	         DNSOpQuery == dnsHeader->opCode &&
	         MDNS_SERVER_PORT == remotePort() &&
	         (NULL != this->_resolveNames[0] || NULL != this->_resolveNames[1]))
	{
#if defined(BONJOUR_DEBUG) && BONJOUR_DEBUG
		IPAddress rip = this->remoteIP();
		Serial.print(F("[Bonjour] resp from "));
		Serial.print(rip[0]); Serial.print('.'); Serial.print(rip[1]); Serial.print('.');
		Serial.print(rip[2]); Serial.print('.'); Serial.print(rip[3]);
		Serial.print(F(" aCnt=")); Serial.print(aCnt);
		Serial.print(F(" addCnt=")); Serial.println(addCnt);
#endif
		int offset = sizeof(DNSHeader_t);
		int rLen = 0, tLen = 0;

		uint8_t* ptrNames[MDNS_MAX_SERVICES_PER_PACKET];
		uint16_t ptrOffsets[MDNS_MAX_SERVICES_PER_PACKET];
		uint16_t ptrPorts[MDNS_MAX_SERVICES_PER_PACKET];
		uint16_t ptrIPs[MDNS_MAX_SERVICES_PER_PACKET];
		uint16_t servIPKeys[MDNS_MAX_SERVICES_PER_PACKET];
		uint8_t servIPs[MDNS_MAX_SERVICES_PER_PACKET][4];
		uint8_t* servTxt[MDNS_MAX_SERVICES_PER_PACKET];
		memset(servIPKeys, 0, sizeof(uint16_t) * MDNS_MAX_SERVICES_PER_PACKET);
		memset(servIPs, 0, sizeof(uint8_t) * MDNS_MAX_SERVICES_PER_PACKET * 4);
		memset(servTxt, 0, sizeof(uint8_t*) * MDNS_MAX_SERVICES_PER_PACKET);
		memset(ptrPorts, 0, sizeof(uint16_t) * MDNS_MAX_SERVICES_PER_PACKET);
		memset(ptrOffsets, 0, sizeof(uint16_t) * MDNS_MAX_SERVICES_PER_PACKET);
		memset(ptrIPs, 0, sizeof(uint16_t) * MDNS_MAX_SERVICES_PER_PACKET);

		const uint8_t* ptrNamesCmp[MDNS_MAX_SERVICES_PER_PACKET];
		int ptrLensCmp[MDNS_MAX_SERVICES_PER_PACKET];
		uint8_t ptrNamesMatches[MDNS_MAX_SERVICES_PER_PACKET];

		uint8_t checkAARecords = 0;
		memset(ptrNames, 0, sizeof(uint8_t*) * MDNS_MAX_SERVICES_PER_PACKET);

		const uint8_t* servNames[2];
		uint16_t servNamePos[2];
		int servLens[2];
		uint8_t servMatches[2];
		uint16_t firstNamePtrByte = 0;
		uint8_t partMatched[2];
		uint8_t lastWasCompressed[2];
		uint8_t servWasCompressed[2];

		servNamePos[0] = servNamePos[1] = 0;

		for (i = 0; i < qCnt + aCnt + aaCnt + addCnt; i++) {

			for (j = 0; j < 2; j++) {
				if (NULL != this->_resolveNames[j]) {
					servNames[j] = this->_resolveNames[j];
					servLens[j] = strlen((const char*)this->_resolveNames[j]);
					servMatches[j] = 1;
				} else {
					servNames[j] = NULL;
					servLens[j] = servMatches[j] = 0;
				}
			}

			for (j = 0; j < MDNS_MAX_SERVICES_PER_PACKET; j++) {
				if (NULL != ptrNames[j]) {
					ptrNamesCmp[j] = ptrNames[j];
					ptrLensCmp[j] = strlen((const char*)ptrNames[j]);
					ptrNamesMatches[j] = 1;
				}
			}

			partMatched[0] = partMatched[1] = 0;
			lastWasCompressed[0] = lastWasCompressed[1] = 0;
			servWasCompressed[0] = servWasCompressed[1] = 0;
			firstNamePtrByte = 0;
			tLen = 0;

			do {
				if (offset >= (int)udp_len) goto parseDone;
				memcpy((uint8_t*)buf, udpBuffer + offset, 1);
				offset += 1;
				rLen = buf[0];
				tLen += 1;

				if (rLen > 128) {
					if (offset >= (int)udp_len) goto parseDone;
					memcpy((uint8_t*)buf, udpBuffer + offset, 1);
					offset += 1;

					uint16_t compressedOffset = ((uint16_t)(rLen & 0x3F) << 8) | buf[0];

					for (j = 0; j < 2; j++) {
						if (servNamePos[j] && servNamePos[j] != compressedOffset)
							servMatches[j] = 0;
						else
							servWasCompressed[j] = 1;
						lastWasCompressed[j] = 1;
					}

					tLen += 1;

					if (0 == firstNamePtrByte)
						firstNamePtrByte = compressedOffset;
				} else if (rLen > 0) {
					if (i < qCnt) {
						if (offset + rLen > (int)udp_len) goto parseDone;
						offset += rLen;
					} else {
						int tr = rLen, ir;

						if (0 == firstNamePtrByte)
							firstNamePtrByte = offset - 1;	// -1: already consumed length byte

						while (tr > 0) {
							ir = (tr > (int)sizeof(DNSHeader_t)) ? (int)sizeof(DNSHeader_t) : tr;
							if (offset + ir > (int)udp_len) goto parseDone;
							memcpy((uint8_t*)buf, udpBuffer + offset, ir);
							offset += ir;
							tr -= ir;

							for (j = 0; j < 2; j++) {
								if (!recordsFound[j] && servMatches[j] && servNames[j])
									servMatches[j] &= this->_matchStringPart(&servNames[j], &servLens[j], buf, ir);
								if (!partMatched[j])
									partMatched[j] = servMatches[j];
								lastWasCompressed[j] = 0;
							}

							for (j = 0; j < MDNS_MAX_SERVICES_PER_PACKET; j++) {
								if (NULL != ptrNames[j] && ptrNamesMatches[j]) {
									// ponytail: partial-match only; fine in practice since real
									// implementations use DNS compression for the service suffix
									if (ptrLensCmp[j] >= ir)
										ptrNamesMatches[j] &= this->_matchStringPart(&ptrNamesCmp[j], &ptrLensCmp[j], buf, ir);
								}
							}
						}

						tLen += rLen;
					}
				}
			} while (rLen > 0 && rLen <= 128);

			if (i < qCnt) {
				if (offset + 4 > (int)udp_len) goto parseDone;
				offset += 4;
			} else if (i >= qCnt) {
				if (i >= qCnt + aCnt && !checkAARecords)
					break;

				uint8_t packetHandled = 0;

				if (offset + 4 > (int)udp_len) goto parseDone;
				memcpy((uint8_t*)buf, udpBuffer + offset, 4);
				offset += 4;

				if (i < qCnt + aCnt) {
#if defined(BONJOUR_DEBUG) && BONJOUR_DEBUG
					Serial.print(F("[Bonjour] ans rec type=0x")); Serial.print(buf[1], HEX);
					Serial.print(F(" fNPB=0x")); Serial.print(firstNamePtrByte, HEX);
					Serial.print(F(" sM=")); Serial.print(servMatches[1]);
					Serial.print(F(" sL=")); Serial.println(servLens[1]);
#endif
					for (j = 0; j < 2; j++) {
						// Only anchor the compression offset on a confirmed full match.
						// Setting it on non-matching records corrupts pointer checks for later records
						// (e.g. a Mio4 TXT record before PTR records would lock the wrong offset).
						if (0 == servNamePos[j] && servMatches[j] && 0 == servLens[j])
							servNamePos[j] = offset - 4 - tLen;

						if (servNames[j] &&
						    ((servMatches[j] && 0 == servLens[j]) ||
						     (partMatched[j] && lastWasCompressed[j]) ||
						     (servWasCompressed[j] && servMatches[j]))) {

							if (buf[0] == 0 && buf[1] == ((0 == j) ? 0x01 : 0x0c) &&
							    (buf[2] == 0x00 || buf[2] == 0x80) && buf[3] == 0x01) {
								recordsFound[j] = 1;

								if (offset + 6 > (int)udp_len) goto parseDone;
								memcpy((uint8_t*)buf, udpBuffer + offset, 6);
								offset += 6;
								uint32_t ttl = ethutil_ntohl(*(uint32_t*)buf);
								uint16_t dataLen = ethutil_ntohs(*(uint16_t*)&buf[4]);

								if (0 == j && 4 == dataLen) {
									// A record: IP address for name resolution
									if (offset + 4 > (int)udp_len) goto parseDone;
									memcpy((uint8_t*)buf, udpBuffer + offset, 4);
									this->_finishedResolvingName((char*)this->_resolveNames[0], (const byte*)buf);
								} else if (1 == j) {
									if (0 == ttl) {
										// Goodbye packet (RFC 6762 §11.3): service is going away.
										// Notify upper layers via callback with NULL ip so they can clean up.
										if (this->_serviceFoundCallback && this->_resolveNames[1]) {
											int l = (int)dataLen - 2;
											if (l > 1 && offset + (int)dataLen <= (int)udp_len) {
												uint8_t* ptrName = (uint8_t*)my_malloc(l);
												if (ptrName) {
													memcpy((uint8_t*)buf, udpBuffer + offset, 1);
													memcpy(ptrName, udpBuffer + offset + 1, l - 1);
													ptrName[(buf[0] < (uint8_t)(l-1)) ? buf[0] : (uint8_t)(l-1)] = '\0';
													char* p = (char*)this->_resolveNames[1];
													while (*p && *p != '.') p++;
													*p = '\0';
													this->_serviceFoundCallback((char*)this->_resolveNames[1],
														this->_resolveServiceProto,
														(const char*)ptrName, NULL, 0, NULL);
													*p = '.';
													my_free(ptrName);
												}
											}
										}
										offset += dataLen;
										packetHandled = 1;
										break;
									}

									// PTR record: extract instance name and queue for SRV/A lookup
									uint8_t k;
									for (k = 0; k < MDNS_MAX_SERVICES_PER_PACKET; k++)
										if (NULL == ptrNames[k])
											break;

									if (k < MDNS_MAX_SERVICES_PER_PACKET) {
										int l = (int)dataLen - 2;	// -2: compressed service type suffix
										if (l <= 0 || offset + (int)dataLen > (int)udp_len)
											goto parseDone;
										uint8_t* ptrName = (uint8_t*)my_malloc(l);
										if (ptrName) {
											memcpy((uint8_t*)buf, udpBuffer + offset, 1);
											memcpy((uint8_t*)ptrName, udpBuffer + offset + 1, l - 1);
											if (buf[0] < l - 1)
												ptrName[buf[0]] = '\0';
											else
												ptrName[l - 1] = '\0';
											ptrNames[k] = ptrName;
											ptrOffsets[k] = (uint16_t)(offset);
											checkAARecords = 1;
										}
									}
								}
								offset += dataLen;
								packetHandled = 1;
							}
						}
					}

					// SRV records may appear in the answer section (non-standard but used by
					// devices such as the iConnectivity Mio4).
					if (!packetHandled && buf[1] == 0x21) {
						for (j = 0; j < MDNS_MAX_SERVICES_PER_PACKET; j++) {
							if (ptrNames[j] &&
							    ((firstNamePtrByte && firstNamePtrByte == ptrOffsets[j]) ||
							     (0 == ptrLensCmp[j] && ptrNamesMatches[j]))) {
								if (this->_parseSRVRecord(udpBuffer, &offset, (int)udp_len,
								                          &ptrPorts[j], &ptrIPs[j]))
									packetHandled = 1;
								break;
							}
						}
					}
				} else if (i >= qCnt + aCnt + aaCnt) {
#if defined(BONJOUR_DEBUG) && BONJOUR_DEBUG
					Serial.print(F("[Bonjour] add rec type=0x")); Serial.print(buf[1], HEX);
					Serial.print(F(" fNPB=0x")); Serial.print(firstNamePtrByte, HEX);
					Serial.print(F(" offset=")); Serial.println(offset);
#endif
					if (buf[1] == 0x21) {	// SRV record
						for (j = 0; j < MDNS_MAX_SERVICES_PER_PACKET; j++) {
							if (ptrNames[j] &&
							    ((firstNamePtrByte && firstNamePtrByte == ptrOffsets[j]) ||
							     (0 == ptrLensCmp[j] && ptrNamesMatches[j]))) {
								if (this->_parseSRVRecord(udpBuffer, &offset, (int)udp_len,
								                          &ptrPorts[j], &ptrIPs[j]))
									packetHandled = 1;
								break;
							}
						}
#if defined(BONJOUR_DEBUG) && BONJOUR_DEBUG
						Serial.print(F("[Bonjour]  SRV matched j=")); Serial.print(packetHandled ? j : -1);
						Serial.print(F(" port=")); Serial.print(ptrPorts[packetHandled ? j : 0]);
						Serial.print(F(" ptrIP=0x")); Serial.println(ptrIPs[packetHandled ? j : 0], HEX);
#endif
					} else if (buf[1] == 0x10) {	// TXT record
						for (j = 0; j < MDNS_MAX_SERVICES_PER_PACKET; j++) {
							if (ptrNames[j] &&
							    ((firstNamePtrByte && firstNamePtrByte == ptrOffsets[j]) ||
							     (0 == ptrLensCmp[j] && ptrNamesMatches[j]))) {
								if (offset + 6 > (int)udp_len) goto parseDone;
								memcpy((uint8_t*)buf, udpBuffer + offset, 6);
								offset += 6;
								uint16_t dataLen = ethutil_ntohs(*(uint16_t*)&buf[4]);
								if (dataLen > 1 && NULL == servTxt[j]) {
									if (offset + (int)dataLen > (int)udp_len) goto parseDone;
									servTxt[j] = (uint8_t*)my_malloc(dataLen + 1);
									if (NULL != servTxt[j]) {
										memcpy((uint8_t*)servTxt[j], udpBuffer + offset, dataLen);
										servTxt[j][dataLen] = '\0';
									}
								}
								offset += dataLen;
								packetHandled = 1;
								break;
							}
						}
					} else if (buf[1] == 0x01) {	// A record (IPv4 address)
						for (j = 0; j < MDNS_MAX_SERVICES_PER_PACKET; j++) {
							if (0 == servIPKeys[j]) {
								servIPKeys[j] = firstNamePtrByte ? firstNamePtrByte : 0xFFFF;
								if (offset + 6 > (int)udp_len) goto parseDone;
								memcpy((uint8_t*)buf, udpBuffer + offset, 6);
								offset += 6;
								uint16_t dataLen = ethutil_ntohs(*(uint16_t*)&buf[4]);
								if (4 == dataLen) {
									if (offset + 4 <= (int)udp_len)
										memcpy((uint8_t*)servIPs[j], udpBuffer + offset, 4);
								}
								offset += dataLen;
								packetHandled = 1;
								break;
							}
						}
					}
				}

				if (!packetHandled) {
					// skip a record we don't care about: TTL(4) + dataLen(2) + data
					if (offset + 4 > (int)udp_len) goto parseDone;
					offset += 4;
					if (offset + 2 > (int)udp_len) goto parseDone;
					memcpy((uint8_t*)buf, udpBuffer + offset, 2);
					offset += 2;
					uint16_t skipLen = ethutil_ntohs(*(uint16_t*)buf);
					if (offset + (int)skipLen > (int)udp_len) goto parseDone;
					offset += skipLen;
				}
			}
		}

		parseDone:
		// deliver the services discovered in this packet
		if (NULL != this->_resolveNames[1]) {
			char* typeName = (char*)this->_resolveNames[1];
			char* p = (char*)this->_resolveNames[1];
			while (*p && *p != '.')
				p++;
			*p = '\0';

#if defined(BONJOUR_DEBUG) && BONJOUR_DEBUG
			Serial.print(F("[Bonjour] parseDone. PTR slots:"));
			for (i = 0; i < MDNS_MAX_SERVICES_PER_PACKET; i++)
				if (ptrNames[i]) {
					Serial.print(' '); Serial.print(i);
					Serial.print('='); Serial.print((const char*)ptrNames[i]);
					Serial.print(" ptrOff=0x"); Serial.print(ptrOffsets[i], HEX);
					Serial.print(" port="); Serial.print(ptrPorts[i]);
					Serial.print(" ptrIP=0x"); Serial.println(ptrIPs[i], HEX);
				}
			for (j = 0; j < MDNS_MAX_SERVICES_PER_PACKET; j++)
				if (servIPKeys[j]) {
					Serial.print(F("[Bonjour] A-slot ")); Serial.print(j);
					Serial.print(F(" key=0x")); Serial.print(servIPKeys[j], HEX);
					Serial.print(F(" ip="));
					for (uint8_t b = 0; b < 4; b++) { Serial.print(servIPs[j][b]); if (b<3) Serial.print('.'); }
					Serial.println();
				}
#endif

			for (i = 0; i < MDNS_MAX_SERVICES_PER_PACKET; i++)
				if (ptrNames[i]) {
					const uint8_t* ipAddr = NULL;
					const uint8_t* fallbackIpAddr = NULL;

					for (j = 0; j < MDNS_MAX_SERVICES_PER_PACKET; j++) {
						// ponytail: only match on ptrIPs[i] when SRV was found (non-zero);
						// avoids false 0==0 match that produced 0.0.0.0 deliveries.
						if (0 != ptrIPs[i] && (servIPKeys[j] == ptrIPs[i] || servIPKeys[j] == 0xFFFF)) {
							ipAddr = servIPs[j];
							break;
						} else if (NULL == fallbackIpAddr && 0 != servIPKeys[j])
							fallbackIpAddr = servIPs[j];
					}

					// if we can't match SRV target to A record, use the first A record found.
					// this covers devices that send PTR+A in one packet but SRV separately
					// (or not at all). port will be 0; upper layer should supply a default.
					if (NULL == ipAddr) ipAddr = fallbackIpAddr;

					if (ipAddr && (ipAddr[0] || ipAddr[1] || ipAddr[2] || ipAddr[3])
					    && this->_serviceFoundCallback) {
						this->_serviceFoundCallback(typeName,
						                            this->_resolveServiceProto,
						                            (const char*)ptrNames[i],
						                            (const byte*)ipAddr,
						                            (unsigned short)ptrPorts[i],
						                            (const char*)servTxt[i]);
					}
				}
			*p = '.';
		}

		uint8_t k;
		for (k = 0; k < MDNS_MAX_SERVICES_PER_PACKET; k++)
			if (NULL != ptrNames[k]) {
				my_free(ptrNames[k]);
				if (NULL != servTxt[k])
					my_free(servTxt[k]);
			}
	}

#endif	// (defined(HAS_SERVICE_REGISTRATION) && HAS_SERVICE_REGISTRATION) || (defined(HAS_NAME_BROWSING) && HAS_NAME_BROWSING)

	my_free(udpBuffer);

errorReturn:

#if defined(_USE_MALLOC_)
	if (NULL != dnsHeader)
		my_free(dnsHeader);
#endif

	// now, handle the requests
	for (j = 0; j < NumMDNSServiceRecords + 3; j++) {
		if (recordsAskedFor[j]) {
			if (j == 0)
				(void)this->_sendMDNSMessage(this->remoteIP(), xid, (int)MDNSPacketTypeMyIPAnswer, 0);
			else if (j == 1)
				(void)this->_sendMDNSMessage(this->remoteIP(), xid, (int)MDNSPacketTypeMyIPAnswer, 1);
			else if (j == 2) {
				uint8_t k = 3;
				for (k = 0; k < NumMDNSServiceRecords; k++)
					recordsAskedFor[k + 3] = 1;
			} else if (NULL != this->_serviceRecords[j - 3])
				(void)this->_sendMDNSMessage(this->remoteIP(), xid, (int)MDNSPacketTypeServiceRecord, j - 3);
		}
	}

	// if we were asked for our IPv6 address, say that we don't have any
	if (wantsIPv6Addr)
		(void)this->_sendMDNSMessage(this->remoteIP(), xid, (int)MDNSPacketTypeNoIPv6AddrAvailable, 0);

	return statusCode;
}

void EthernetBonjourClass::run()
{
	uint8_t i;
	unsigned long now = millis();

	// first, look for MDNS queries to handle
	(void)_processMDNSQuery();

	// are we querying a name or service? if so, should we resend the packet or time out?
	for (i = 0; i < 2; i++) {
		if (NULL != this->_resolveNames[i]) {
			// Hint: _resolveLastSendMillis is updated in _sendMDNSMessage
			if ( now - this->_resolveLastSendMillis[i] > ( (i == 0) ? (uint32_t)MDNS_NQUERY_RESEND_TIME :
								       (uint32_t)MDNS_SQUERY_RESEND_TIME ) )
				(void)this->_sendMDNSMessage(0,
							     0,
							     (0 == i) ? MDNSPacketTypeNameQuery :
							     MDNSPacketTypeServiceQuery,
							     0);

			if (this->_resolveTimeouts[i] > 0 && now > this->_resolveTimeouts[i]) {
				if (i == 0)
					this->_finishedResolvingName( (char*)this->_resolveNames[0], NULL );
				else if (i == 1) {
					if (this->_serviceFoundCallback) {
						char* typeName = (char*)this->_resolveNames[1];
						char* p = (char*)this->_resolveNames[1];
						while(*p && *p != '.')
							p++;
						*p = '\0';

						this->_serviceFoundCallback(typeName,
									    this->_resolveServiceProto,
									    NULL,
									    NULL,
									    0,
									    NULL);
					}
				}

				if (NULL != this->_resolveNames[i]) {
					my_free(this->_resolveNames[i]);
					this->_resolveNames[i] = NULL;
				}
			}
		}
	}

	// now, should we re-announce our services again?
	unsigned long announceTimeOut = ( ( (uint32_t)MDNS_RESPONSE_TTL / 2 ) + ( (uint32_t)MDNS_RESPONSE_TTL / 4 ) );
	if ( (now - this->_lastAnnounceMillis) > 1000 * announceTimeOut ) {
		for (i = 0; i < NumMDNSServiceRecords; i++) {
			if (NULL != this->_serviceRecords[i])
				(void)this->_sendMDNSMessage(0, 0, (int)MDNSPacketTypeServiceRecord, i);
		}

		this->_lastAnnounceMillis = now;
	}
}

// return values:
// 1 on success
// 0 otherwise
int EthernetBonjourClass::setBonjourName(const char* bonjourName)
{
	if (NULL == bonjourName)
		return 0;

	if (this->_bonjourName != NULL)
		my_free(this->_bonjourName);

	this->_bonjourName = (uint8_t*)my_malloc(strlen(bonjourName) + 7);
	if (NULL == this->_bonjourName)
		return 0;

	strcpy( (char*)this->_bonjourName, bonjourName );
	strcpy( (char*)this->_bonjourName + strlen(bonjourName), MDNS_TLD );

	return 1;
}

// return values:
// 1 on success
// 0 otherwise
int EthernetBonjourClass::setSecondaryHostname(const char* secondaryName)
{
	if (NULL == secondaryName)
		return 0;

	if (this->_bonjourName2 != NULL)
		my_free(this->_bonjourName2);

	this->_bonjourName2 = (uint8_t*)my_malloc(strlen(secondaryName) + 7);
	if (NULL == this->_bonjourName2)
		return 0;

	strcpy( (char*)this->_bonjourName2, secondaryName );
	strcpy( (char*)this->_bonjourName2 + strlen(secondaryName), MDNS_TLD );

	return 1;
}

// return values:
// 1 on success
// 0 otherwise
int EthernetBonjourClass::addServiceRecord(const char* name, uint16_t port,
					   MDNSServiceProtocol_t proto)
{
#if defined(__MK20DX128__) || defined(__MK20DX256__)
	return this->addServiceRecord(name, port, proto, NULL);	//works for Teensy 3 (32-bit Arm Cortex)
#else
	return this->addServiceRecord(name, port, proto, "");	//works for Teensy 2 (8-bit Atmel)
#endif
}

// return values:
// 1 on success
// 0 otherwise
int EthernetBonjourClass::addServiceRecord(const char* name, uint16_t port,
					   MDNSServiceProtocol_t proto, const char* textContent)
{
	int i, status = 0;
	MDNSServiceRecord_t* record = NULL;

	if (NULL != name && 0 != port) {
		for (i = 0; i < NumMDNSServiceRecords; i++) {
			if (NULL == this->_serviceRecords[i]) {
				record = (MDNSServiceRecord_t*)my_malloc( sizeof(MDNSServiceRecord_t) );
				if (NULL != record) {
					record->name = record->textContent = NULL;

					record->name = (uint8_t*)my_malloc( strlen( (char*)name ) + 1 );
					memset(record->name, 0, strlen( (char*)name ) + 1);
					if (NULL == record->name)
						goto errorReturn;

					if (NULL != textContent) {
						record->textContent = (uint8_t*)my_malloc( strlen( (char*)textContent ) + 1);
						memset(record->textContent, 0, strlen( (char*)textContent ) + 1);
						if (NULL == record->textContent)
							goto errorReturn;

						strcpy( (char*)record->textContent, textContent );
					}

					record->port = port;
					record->proto = proto;
					strcpy( (char*)record->name, name );

					uint8_t* s = this->_findFirstDotFromRight(record->name);
					record->servName = (uint8_t*)my_malloc(strlen( (char*)s ) + 13);
					memset(record->servName, 0, strlen( (char*)s ) + 13);
					if (record->servName) {
						strcpy( (char*)record->servName, (const char*)s );

						const uint8_t* srv_type = this->_postfixForProtocol(proto);
						if (srv_type)
							strcat( (char*)record->servName, (const char*)srv_type );
					}

					this->_serviceRecords[i] = record;

					status = ( MDNSSuccess ==
						   this->_sendMDNSMessage(0, 0, (int)MDNSPacketTypeServiceRecord, i) );

					break;
				}
			}
		}
	}

	return status;

errorReturn:
	if (NULL != record) {
		if (NULL != record->name)
			my_free(record->name);
		if (NULL != record->servName)
			my_free(record->servName);
		if (NULL != record->textContent)
			my_free(record->textContent);

		my_free(record);
	}

	return 0;
}

void EthernetBonjourClass::_removeServiceRecord(int idx)
{
	if (NULL != this->_serviceRecords[idx]) {
		(void)this->_sendMDNSMessage(0, 0, (int)MDNSPacketTypeServiceRecordRelease, idx);

		if (NULL != this->_serviceRecords[idx]->textContent)
			my_free(this->_serviceRecords[idx]->textContent);

		if (NULL != this->_serviceRecords[idx]->servName)
			my_free(this->_serviceRecords[idx]->servName);

		my_free(this->_serviceRecords[idx]->name);
		my_free(this->_serviceRecords[idx]);

		this->_serviceRecords[idx] = NULL;
	}
}

void EthernetBonjourClass::removeServiceRecord(uint16_t port, MDNSServiceProtocol_t proto)
{
	this->removeServiceRecord(NULL, port, proto);
}

void EthernetBonjourClass::removeServiceRecord(const char* name, uint16_t port,
					       MDNSServiceProtocol_t proto)
{
	int i;
	for (i = 0; i < NumMDNSServiceRecords; i++)
		if ( port == this->_serviceRecords[i]->port &&
		     proto == this->_serviceRecords[i]->proto &&
		     ( NULL == name || 0 == strcmp( (char*)this->_serviceRecords[i]->name, name ) ) ) {
			this->_removeServiceRecord(i);
			break;
		}
}

void EthernetBonjourClass::removeAllServiceRecords()
{
	int i;
	for (i = 0; i < NumMDNSServiceRecords; i++)
		this->_removeServiceRecord(i);
}

void EthernetBonjourClass::_writeDNSName(const uint8_t* name, uint16_t* pPtr,
					 uint8_t* buf, int bufSize, int zeroTerminate)
{
	uint16_t ptr = *pPtr;
	uint8_t* p1 = (uint8_t*)name, *p2, *p3;
	int i, c, len;

	while(*p1) {
		c = 1;
		p2 = p1;
		while (0 != *p2 && '.' != *p2) { p2++; c++; };

		p3 = buf;
		i = c;
		len = bufSize - 1;
		*p3++ = (uint8_t)-- i;
		while (i-- > 0) {
			*p3++ = *p1++;

			if (--len <= 0) {
				this->write( (uint8_t*)buf, bufSize );
				ptr += bufSize;
				len = bufSize;
				p3 = buf;
			}
		}

		while ('.' == *p1)
			++p1;

		if (len != bufSize) {
			this->write( (uint8_t*)buf, bufSize - len );
			ptr += bufSize - len;
		}
	}

	if (zeroTerminate) {
		buf[0] = 0;
		this->write( (uint8_t*)buf, 1 );
		ptr += 1;
	}

	*pPtr = ptr;
}

void EthernetBonjourClass::_writeMyIPAnswerRecord(uint16_t* pPtr, uint8_t* buf, int bufSize, uint8_t* hostName)
{
	uint16_t ptr = *pPtr;

	this->_writeDNSName(hostName, &ptr, buf, bufSize, 1);

	buf[0] = 0x00;
	buf[1] = 0x01;
	buf[2] = 0x80;	// cache flush: true
	buf[3] = 0x01;
	this->write( (uint8_t*)buf, 4 );
	ptr += 4;

	*( (uint32_t*)buf ) = ethutil_htonl(MDNS_RESPONSE_TTL);
	*( (uint16_t*)&buf[4] ) = ethutil_htons(4);	// data length

	uint8_t myIp[4];
	IPAddress myIpBuf;
	myIpBuf = Ethernet.localIP();
	myIp[0] = myIpBuf [0];
	myIp[1] = myIpBuf [1];
	myIp[2] = myIpBuf [2];
	myIp[3] = myIpBuf [3];

	memcpy(&buf[6], &myIp, 4);		// our IP address

	this->write( (uint8_t*)buf, 10 );
	ptr += 10;

	*pPtr = ptr;
}

void EthernetBonjourClass::_writeServiceRecordName(int recordIndex, uint16_t* pPtr, uint8_t* buf,
						   int bufSize, int tld)
{
	uint16_t ptr = *pPtr;

	uint8_t* name = tld ? this->_serviceRecords[recordIndex]->servName :
			this->_serviceRecords[recordIndex]->name;

	this->_writeDNSName(name, &ptr, buf, bufSize, tld);

	if (0 == tld) {
		const uint8_t* srv_type =
			this->_postfixForProtocol(this->_serviceRecords[recordIndex]->proto);

		if (NULL != srv_type) {
			srv_type++;	// eat the dot at the beginning
			this->_writeDNSName(srv_type, &ptr, buf, bufSize, 1);
		}
	}

	*pPtr = ptr;
}

void EthernetBonjourClass::_writeServiceRecordPTR(int recordIndex, uint16_t* pPtr, uint8_t* buf,
						  int bufSize, uint32_t ttl)
{
	uint16_t ptr = *pPtr;

	this->_writeServiceRecordName(recordIndex, &ptr, buf, bufSize, 1);

	buf[0] = 0x00;
	buf[1] = 0x0c;	// PTR record
	buf[2] = 0x00;	// no cache flush
	buf[3] = 0x01;	// class IN

	// ttl
	*( (uint32_t*)&buf[4] ) = ethutil_htonl(ttl);

	// data length (+13 = "._tcp.local" or "._udp.local" + 1  byte zero termination)
	*( (uint16_t*)&buf[8] ) =
		ethutil_htons(strlen( (char*)this->_serviceRecords[recordIndex]->name ) + 13);

	this->write( (uint8_t*)buf, 10 );
	ptr += 10;

	this->_writeServiceRecordName(recordIndex, &ptr, buf, bufSize, 0);

	*pPtr = ptr;
}

uint8_t* EthernetBonjourClass::_findFirstDotFromRight(const uint8_t* str)
{
	const uint8_t* p = str + strlen( (char*)str );
	while (p > str && '.' != *p--) ;
	return (uint8_t*)&p[2];
}

int EthernetBonjourClass::_matchStringPart(const uint8_t** pCmpStr, int* pCmpLen, const uint8_t* buf,
					   int dataLen)
{
	int matches = 1;

	if (*pCmpLen >= dataLen)
		matches &= ( 0 == memcmp(*pCmpStr, buf, dataLen) );
	else
		matches = 0;

	*pCmpStr += dataLen;
	*pCmpLen -= dataLen;
	if ('.' == **pCmpStr)
		(*pCmpStr)++, (*pCmpLen)--;

	return matches;
}

const uint8_t* EthernetBonjourClass::_postfixForProtocol(MDNSServiceProtocol_t proto)
{
	const uint8_t* srv_type = NULL;
	switch(proto) {
		case MDNSServiceTCP:
			srv_type = (uint8_t*)"._tcp" MDNS_TLD;
			break;
		case MDNSServiceUDP:
			srv_type = (uint8_t*)"._udp" MDNS_TLD;
			break;
	}

	return srv_type;
}

void EthernetBonjourClass::_finishedResolvingName(char* name, const byte ipAddr[4])
{
	if (NULL != this->_nameFoundCallback) {
		if (NULL != name) {
			uint8_t* n = this->_findFirstDotFromRight( (const uint8_t*)name );
			*(n - 1) = '\0';
		}

		this->_nameFoundCallback( (const char*)name, ipAddr );
	}

	my_free(this->_resolveNames[0]);
	this->_resolveNames[0] = NULL;
}

EthernetBonjourClass EthernetBonjour;
