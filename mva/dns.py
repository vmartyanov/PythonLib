import sys
if (sys.version_info[0] != 3):
	print("This script requires Python version 3.x")
	exit(1)

import random
import socket
import struct

#TYPES
A		= 1
NS		= 2
MD		= 3		#obsolete
MF		= 4		#obsolete
CNAME	= 5
SOA		= 6
MB		= 7		#experimental
MG		= 8		#experimental
MR		= 9		#experimental
NULL	= 10	#experimental
WKS		= 11
PTR		= 12
HINFO	= 13
MINFO	= 14
MX		= 15
TXT		= 16
RP		= 17
AAAA	= 28
SRV		= 33
NAPTR	= 35
DS			= 43
RRSIG		= 46
NSEC		= 47
DNSKEY		= 48
NSEC3		= 50
NSEC3PARAM	= 51
TLSA		= 52
OPENPGPKEY	= 61
SPF			= 99
AXFR		= 252
CAA			= 257
TYPES = {0: "UNKNOWN", 1: "A", 2: "NS", 3: "MD", 4: "MF", 5: "CNAME", 6: "SOA", 7: "MB", 8 : "MG", 9 : "MR",
		10 : "NULL", 11 : "WKS", 12 : "PTR", 13 : "HINFO", 14 : "MINFO", 15 : "MX", 16 : "TXT", 17: "RP",
		28: "AAAA",
		33: "SRV", 35: "NAPTR",
		43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY",
		50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA",
		61: "OPENPGPKEY",
		99: "SPF",
		252: "AXFR", 257: "CAA"
		}

#OPCODES
QUERY	= 0
IQUERY	= 1
STATUS	= 2
OPCODES = {0: "QUERY", 1: "IQUERY", 2: "STATUS"}

#CLASSES
IN		= 1
CS		= 2
CH		= 3
HS		= 4
CLASSES = {0: "UNKNWON", 1: "IN", 2: "CS", 3: "CH", 4: "HS"}

#RCODES
R_OK			= 0
R_FORMATERR		= 1
R_SERVFAIL		= 2
R_NAMEERR		= 3
R_NOTIMPL		= 4
R_REFUSED		= 5
RCODES = {0: "No error", 1: "Format error", 2: "Server failure", 3: "Name error", 4: "Not Implemented",
			5: "Refused"}
	
def ReadName(data, startOffset):
	retLen = 0
	retStr = ""
	while(1):
		l = data[startOffset + retLen]
		if (l >= 0xC0):		#offset
			offset = struct.unpack("!H", data[startOffset + retLen:startOffset + retLen+2])[0]
			offset = offset & 0x3FFF
			
			s, foo = ReadName(data, offset)
			
			retStr = retStr + s
			retLen = retLen + 2
			break		#because pointer is ALWAYS the last element
		else:
			retLen = retLen + 1
			if (l == 0):
				break
			retStr = retStr + data[startOffset + retLen: startOffset + retLen + l].decode() + "."
			retLen = retLen + l
	
	if (len(retStr) == 0):
		return "<ROOT>", retLen
	if (retStr[-1] == "."):
		retStr = retStr[:-1]
	return (retStr, retLen)

class DNSheader:
	def __init__(self):
		self.ID = random.randrange(0, 16384)
		self.QR = 0
		self.OPCODE = 0
		self.AA = 0
		self.TC = 0
		self.RD = 0
		self.RA = 0
		self.Z = 0
		self.RCODE = 0
		
		self.QDCOUNT = 0
		self.ANCOUNT = 0
		self.NSCOUNT = 0
		self.ARCOUNT = 0

	def __len__(self):
		return 6 * 2				#6 words
		
	def __str__(self):
		if (self.QR == 0):
			s = "QUERY"
		else:
			s = "RESPONSE"
		s = s + ": ID = " + hex(self.ID)
		s = s + ", OPCODE = " + OPCODES[self.OPCODE]
		s = s + ", AA = " + hex(self.AA)
		s = s + ", TC = " + hex(self.TC)
		s = s + ", RD = " + hex(self.RD)
		s = s + ", RA = " + hex(self.RA)
		s = s + ", Z = " + hex(self.Z)
		s = s + ", RCODE = " + RCODES[self.RCODE]
		s = s + ", QDCOUNT = " + hex(self.QDCOUNT)
		s = s + ", ANCOUNT = " + hex(self.ANCOUNT)
		s = s + ", NSCOUNT = " + hex(self.NSCOUNT)
		s = s + ", ARCOUNT = " + hex(self.ARCOUNT)
		return s

	def ToBytes(self):
		out = struct.pack("!H", self.ID)		#ID
		
		i = (self.QR & 0x01) << 15
		i = i + ((self.OPCODE& 0x0F) << 14)
		i = i + ((self.AA & 0x01) << 10)
		i = i + ((self.TC & 0x01) << 9)
		i = i + ((self.RD & 0x01) << 8)
		
		i = i + ((self.RA & 0x01) << 7)
		i = i + ((self.Z & 0x07) << 6)
		i = i + (self.RCODE & 0x0F)
		out = out + struct.pack("!H", i)							#QR, Opcode, AA, TC, RD, RA, Z, RCODE

		out = out + struct.pack("!H", self.QDCOUNT)
		out = out + struct.pack("!H", self.ANCOUNT)
		out = out + struct.pack("!H", self.NSCOUNT)
		out = out + struct.pack("!H", self.ARCOUNT)
		return out

	def FromBytes(self, data, startOffset):
		self.ID, i, self.QDCOUNT, self.ANCOUNT, self.NSCOUNT, self.ARCOUNT = struct.unpack("!HHHHHH", data[startOffset:startOffset + len(self)])
		
		self.QR = (i >> 15) & 0x01
		self.OPCODE = (i >> 11) & 0x0F
		self.AA = (i >> 10) & 0x01
		self.TC = (i >> 9) & 0x01
		self.RD = (i >> 8) & 0x01
		self.RA = (i >> 7) & 0x01
		self.Z = (i >> 4) & 0x07
		self.RCODE = i & 0x0F
		
		return self

class DNSQuestion:
	def __init__(self):
		self.NAME = ""
		self.QTYPE = 0
		self.QCLASS = 0
		
	def __len__(self):
		return len(self.ToBytes())
		
	def __str__(self):
		s = "NAME = " + self.NAME
		s = s + ", QTYPE = " + TYPES[self.QTYPE]
		s = s + ", CLASS = " + CLASSES[self.QCLASS]
		return s
	
	def ToBytes(self):
		out = b''
		parts = self.NAME.split('.')
		for part in parts:
			partLen = len(part)
			if (partLen > 63):
				raise
			out = out + struct.pack("B", partLen)
			out = out + part.encode()

		out = out + b'\x00'
		out = out + struct.pack("!H", self.QTYPE)
		out = out + struct.pack("!H", self.QCLASS)
		return out

	def FromBytes(self, data, startOffset):
		self.NAME, l = ReadName(data, startOffset)
			
		self.QTYPE, self.QCLASS = struct.unpack("!HH", data[startOffset + l: startOffset + l + 4])
		return self

class RDATA:
	def __init__(self, data, startOffset):
		self.NAME = ""
		raise
	def __str__(self):
		return self.NAME
	def toText(self):
		return str(self)

class JustName_RDATA(RDATA):
	def __init__(self, data, startOffset):
		self.NAME, l = ReadName(data, startOffset)

class A_RDATA(RDATA):
	def __init__(self, data, startOffset):
		ip1, ip2, ip3, ip4 = struct.unpack("BBBB", data[startOffset: startOffset + 4])
		self.NAME = str(ip1) + "." + str(ip2) + "." + str(ip3) + "." + str(ip4)

class MX_RDATA(RDATA):
	def __init__(self, data, startOffset):
		self.PREFERENCE = struct.unpack("!H", data[startOffset: startOffset + 2])[0]
		self.NAME, l = ReadName(data, startOffset + 2)
	def toText(self):
		return str(self.PREFERENCE) + " " + self.NAME

class TXT_RDATA(RDATA):
	def __init__(self, data, startOffset):
		l = data[startOffset]
		self.NAME = data[startOffset + 1 : startOffset + 1 + l].decode()

class SOA_RDATA(RDATA):
	def __init__(self, data, startOffset):
		self.NAME, l = ReadName(data, startOffset)
		pos = l
		
		self.RNAME, l = ReadName(data, startOffset + pos)
		pos = pos + l
		
		self.SERIAL, self.REFRESH, self.RETRY, self.EXPIRE, self.MINIMUM = 	struct.unpack("!LLLLL", data[startOffset + pos:startOffset + pos + 20])
		
	def toText(self):
		s = self.NAME + "\t" + self.RNAME
		s = s + "\t" + str(self.SERIAL)
		s = s + "\t" + str(self.REFRESH)
		s = s + "\t" + str(self.RETRY)
		s = s + "\t" + str(self.EXPIRE)
		s = s + "\t" + str(self.MINIMUM)
		return s

class TODO_RDATA (RDATA):
	def __init__(self, data, startOffset):
		self.NAME = "UNIMPLEMENTED"

	
#it's a resource record BTW
class DNSAnswer:
	def __init__(self, data, startOffset):
		pos = 0
		
		self.NAME, l = ReadName(data, startOffset)
		self.nameLen = l
		pos = pos + self.nameLen
		
		self.TYPE, self.CLASS, self.TTL, self.RDLENGTH = struct.unpack("!HHLH", data[startOffset + pos: startOffset + pos + 10])
		self.RDATAoffset = startOffset + pos + 10
		
		if (self.CLASS != IN):
			return

		if (self.TYPE == A):		#1
			self.RDATA = A_RDATA(data, self.RDATAoffset)
		elif (self.TYPE == NS):		#2
			self.RDATA = JustName_RDATA(data, self.RDATAoffset)
		elif (self.TYPE == CNAME):	#5
			self.RDATA = JustName_RDATA(data, self.RDATAoffset)
		elif (self.TYPE == SOA):		#6
			self.RDATA = SOA_RDATA(data, self.RDATAoffset)
		elif (self.TYPE == PTR):		#12
			self.RDATA = JustName_RDATA(data, self.RDATAoffset)
		elif (self.TYPE == MX):		#15
			self.RDATA = MX_RDATA(data, self.RDATAoffset)
		elif (self.TYPE == TXT):		#16
			self.RDATA = TXT_RDATA(data, self.RDATAoffset)
		elif (self.TYPE == SPF):		#99
			self.RDATA = TXT_RDATA(data, self.RDATAoffset)
		else:
			self.RDATA = TODO_RDATA(data, self.RDATAoffset)
		
	
	def __len__(self):
		return self.nameLen + 10 + self.RDLENGTH
	
	def __str__(self):
		s = self.NAME
		s = s + "\t" + CLASSES[self.CLASS]
		s = s + "\t" + TYPES[self.TYPE]
		s = s + "\t" + str(self.TTL)
		s = s + "\t" + self.RDATA.toText()
		
		return s
		

def UDPQuery(server, port, timeout, data):
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.settimeout(timeout)
	sock.sendto(data, (server, port))
	out = sock.recv(512)
	return out

def TCPAXFRQueryBegin(server, port, timeout, data):
	data = struct.pack("!H", len(data)) + data
	
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(timeout)
	try:
		sock.connect((server, port))
		sock.sendall(data)
	except:
		return None
	
	return sock

def TCPAXFRQueryNext(sock):
	ret = b""
	try:
		messageLen = sock.recv(2)
		ret = ret + messageLen
		expectedLen = 2 + struct.unpack("!H", messageLen)[0]
		while (1):
			portionLen = expectedLen - len(ret)		#How many bytes left
			if (portionLen == 0):
				break
			if (portionLen > 1024):
				portionLen = 1024
			
			data = sock.recv(portionLen)
			ret = ret + data
	except:
		pass
	return ret

def Query(domain, type, server = "8.8.8.8", port = 53, timeout = 2, recursive = True):
	answers = []
	
	header = DNSheader()
	header.OPCODE = QUERY
	header.QDCOUNT = 1
	if (recursive == True):
		header.RD = 1
	
	question = DNSQuestion()
	question.NAME = domain
	question.QTYPE = type
	question.QCLASS = IN
	
	rawAnswer = UDPQuery(server, port, timeout, header.ToBytes() + question.ToBytes())
	
	answerHeader = DNSheader().FromBytes(rawAnswer, 0)
	pos = len(answerHeader)

	for i in range(answerHeader.QDCOUNT):
		rq = DNSQuestion().FromBytes(rawAnswer, pos)
		pos = pos + len(rq)
		
	for i in range(answerHeader.ANCOUNT):
		foo = DNSAnswer(rawAnswer, pos)
		pos = pos + len(foo)
		if (foo.TYPE != type):			#Yes, we can receive some extra records with other types
			continue
		answers.append(foo.RDATA)
		
	return answers
	
def AXFRquery(domain, server, port = 53, timeout = 2, recursive = True):
	answers = []
	
	header = DNSheader()
	header.OPCODE = QUERY
	header.QDCOUNT = 1
	if (recursive == True):
		header.RD = 1
	
	question = DNSQuestion()
	question.NAME = domain
	question.QTYPE = AXFR
	question.QCLASS = IN
	
	#RFC 5936
	sock = TCPAXFRQueryBegin(server, port, timeout, header.ToBytes() + question.ToBytes())
	if (sock == None):
		return answers
	
	while(1):
		rawMessage = TCPAXFRQueryNext(sock)
		if (len(rawMessage) <= 2):
			break
		rawMessage = rawMessage [2:]			#remove len prefix
		
		answerHeader = DNSheader().FromBytes(rawMessage, 0)
		pos = len(answerHeader)
		if (answerHeader.RCODE != R_OK):
			break
		
		for i in range(answerHeader.QDCOUNT):
			rq = DNSQuestion().FromBytes(rawMessage, pos)
			pos = pos + len(rq)
		
		for i in range(answerHeader.ANCOUNT):
			foo = DNSAnswer(rawMessage, pos)
			pos = pos + len(foo)
			answers.append(foo)
		
		if (answers[-1].TYPE == SOA):
			break
	
	sock.close()
	return answers