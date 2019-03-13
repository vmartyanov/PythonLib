import sys
import struct

from typing import List, Tuple, Set

if (sys.version_info[0] != 3):
	print("This script requires Python version 3.x")
	exit(1)

class GitFile:
	def __init__(self, hash: bytes, name: str, type: str) -> None:
		self.hash = hash
		self.name = name
		self.type = type
		self.childs = []
	def __str__(self) -> str:
		return self.path + " (" + self.type + ") " + self.hash

class GitTree:
	def __init__(self) -> None:
		self.findMap = {}
		self.root = GitFile("root", "", "dir")

	def Add(self, gitFile, parent: bytes) -> None:
		if (parent == None):
			parent = self.root
		else:
			parent = self.findMap[parent]

		if (gitFile.type == "dir"):
			if (not gitFile.hash in self.findMap):		#new dir
				self.findMap[gitFile.hash] = gitFile		#add to map

		parent.childs.append(gitFile)				#it's a dir - check for existence in map and add a ref.
													#A file - just add
	def GetFiles(self, hash: bytes = None, basePath: str = "") -> List[Tuple[bytes, str]]:
		ret = []
		if (hash == None):
			node = self.root
		else:
			node = self.findMap[hash]

		for i in node.childs:
			name = i.name
			if (basePath != ""):
				name = basePath + "/" + name
			if (i.type == "dir"):
				ret = ret + self.GetFiles(i.hash, name)
			else:
				ret.append((i.hash, name))
		return ret

def CheckIndexSignature(indexData: bytes) -> bool:
	if (len(indexData) < 4):
		return False
	signature = struct.unpack(">L", indexData[0:4])[0]
	if (signature != 0x44495243):
		return False
	return True

def GetIndexVersion(indexData: bytes) -> int:
	if (len(indexData) < 4):
		return False
	return struct.unpack(">L", indexData[4:8])[0]

def GetIndexElementsCount(indexData: bytes) -> int:
	if (len(indexData) < 4):
		return False
	return struct.unpack(">L", indexData[0x8:0xC])[0]

def GetIndexFileObjs(indexData: bytes) -> List[GitFile]:
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

		ret.append(GitFile(hash, name, "file"))
		
		entrieSize = entrieSize + nameLen + 1 		#len + name + terminating zero
		
		if ((entrieSize % 8) != 0):
			entrieSize = entrieSize + (8 - (entrieSize % 8))

		currentPos = currentPos + entrieSize
		indexEntriesCount = indexEntriesCount - 1
	return ret
	
def GetTreeFileObjs(treeData: bytes) -> List[GitFile]:
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
		ret.append(GitFile(hash, name, type))
		
		treeData = treeData[endPos+21:]

def GetObjectType(objData: str) -> str:
	pos = objData.find(0x20)
	if (pos == -1):
		return None
	return objData[:pos].decode()
