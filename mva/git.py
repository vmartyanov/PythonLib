import sys
import struct

if (sys.version_info[0] != 3):
	print("This script requires Python version 3.x")
	exit(1)


def CheckIndexSignature(indexData):
	signature = struct.unpack(">L", indexData[0:4])[0]
	if (signature != 0x44495243):
		return False
	return True

def GetIndexVersion(indexData):
	return struct.unpack(">L", indexData[4:8])[0]

def GetIndexElementsCount(indexData):
	return struct.unpack(">L", indexData[0x8:0xC])[0]

def GetIndexElements(indexData):
	currentPos = 0x0C
	ret = []
	
	indexEntriesCount = GetIndexElementsCount(indexData)
	while (indexEntriesCount > 0):
		entrieSize = 40						#10 DWORDS
		
		hash = indexData[currentPos + entrieSize:currentPos + entrieSize + 20].hex()
		entrieSize = entrieSize + 20		#SHA1
		
		nameLen = indexData[currentPos + entrieSize] * 256 + indexData[currentPos + entrieSize + 1]
		nameLen = nameLen & 0xFFF
		entrieSize = entrieSize + 2

		name = indexData[currentPos + entrieSize:currentPos + entrieSize + nameLen]
		name = name.decode(errors = "replace")

		ret.append((hash, name, "file"))
		
		entrieSize = entrieSize + nameLen + 1 		#len + name + terminating zero
		
		if ((entrieSize % 8) != 0):
			entrieSize = entrieSize + (8 - (entrieSize % 8))

		currentPos = currentPos + entrieSize
		indexEntriesCount = indexEntriesCount - 1
	return ret
	
def GetTreeElements(treeData):
	ret = []
	while(1):
		if (len(treeData) == 0):
			return ret
		if (treeData[0] == 0x31):
			type = "file"
		else:
			type = "dir"
		startPos = treeData.find(0x20)
		endPos = treeData.find(0x00)
		
		name = treeData[startPos+1:endPos].decode(errors = "replace")
		hash = treeData[endPos+1:endPos+21].hex()
		ret.append((hash, name, type))
		
		treeData = treeData[endPos+21:]

def GetObjectType(objData):
	pos = objData.find(0x20)
	if (pos == -1):
		return None
	return objData[:pos].decode()
