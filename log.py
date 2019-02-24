import sys
if (sys.version_info[0] != 3):
	print("This script requires Python version 3.x")
	exit(1)

import os

fileName = ""

if (os.name == "nt"):
	try:
		import ctypes
		haveCTYPES = True
	except ImportError:
		haveCTYPES = False
else:
	haveCTYPES = False

import datetime

def TimeString():
	return datetime.datetime.now().strftime("[%H:%M:%S]")
	
def Info(string, logToFile = True):
	Output(string, "[INFO]", 0x02, logToFile)

def Warning(string, logToFile = True):
	Output(string, "[WARNING]", 0x06, logToFile)

def Error(string, logToFile = True):
	Output(string, "[ERROR]", 0x04, logToFile)

def Result(string, logToFile = True):
	Output(string, "[RESULT]", 0x03, logToFile)

def Output(string, marker, colorCode, logToFile):
	tmpString = TimeString() + " " + marker + " " + string
	
	if (fileName != "" and logToFile == True):
		file = open(fileName, "a", errors = "replace")
		file.write(tmpString + "\n")
		file.close()
	
	if (haveCTYPES == False):
		if (os.name != "nt"):
			if (colorCode == 0x02):
				tmpString = "\033[32m" + tmpString
			elif (colorCode == 0x06):
				tmpString = "\033[33m" + tmpString
			elif (colorCode == 0x04):
				tmpString = "\033[31m" + tmpString
			elif (colorCode == 0x03):
				tmpString = "\033[36m" + tmpString
		print (tmpString)
		return
	
	cHandle = ctypes.windll.kernel32.GetStdHandle(-11)
	if (cHandle == None):
		print (tmpString)
		return
	
	ctypes.windll.kernel32.SetConsoleTextAttribute(cHandle, colorCode)
	print (tmpString)
	ctypes.windll.kernel32.SetConsoleTextAttribute(cHandle, 0x07)