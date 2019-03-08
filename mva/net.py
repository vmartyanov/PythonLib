import sys
if (sys.version_info[0] != 3):
	print("This script requires Python version 3.x")
	exit(1)

try:
	import requests
except ImportError:
	print ("You need \"requests\" module installed. Try to run pip install requests")
	exit(1)
	
#Need it to use TOR
try:
	import socks
except ImportError:
	print ("You need \"socks\" module installed. Try to run pip install requests[socks]")
	exit(1)
	
#Disable InsecureRequestWarning in GET (got this warning because of verify=False)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {}

def GET(url, timeout = None, redirects = True):
	global proxies
	return requests.get(url, proxies=proxies, timeout = timeout, verify = False, allow_redirects = redirects)

def SetProxy(proxyType, proxyHost, proxyPort):
	global proxies
	
	proxy = proxyType + "://" + proxyHost+ ":" + str(proxyPort)
	proxies["http"] = proxy
	proxies["https"] = proxy

def CheckTor():
	global proxies
	r = GET("http://check.torproject.org/")

	if (r.content.find(b"Congratulations. This browser is configured to use Tor.") != -1):
		return True

	return False
