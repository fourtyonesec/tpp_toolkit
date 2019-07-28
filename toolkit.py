#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import time
import requests
import json
import urllib3
import platform
from lxml.html import fromstring
import random
from datetime import datetime
now = datetime.now()

urllib3.disable_warnings()

__date__ = time.ctime()
__useragent__ = "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:68.0) Gecko/20100101 Firefox/68.0"
try:
	print("[*] Checking your connection! Please waiting a moments.")
	r = requests.get("https://www.google.com/")
	if (r.status_code == 200):
		print("[*] Successfully check your connection.")
		pass
	else:
		print("[!] Your connection error!")
		sys.exit(1)
		pass
	# print(r.status_code)
	pass
except urllib3.exceptions.NewConnectionError:
	print("[!] | NewConnectionError | Failed to establish a new connection: Temporary failure in name resolution ")
	pass
except urllib3.exceptions.MaxRetryError:
	print("[!] | MaxRetryError | Failed to establish a new connection: Temporary failure in name resolution")
	pass
except requests.exceptions.ConnectionError:
	print("[!] | ConnectionError | Failed to establish a new connection: Temporary failure in name resolution")
	pass
except KeyboardInterrupt:
	print("\n[!] Keyboard CTRL + C Detected. ")
	sys.exit(1)
	pass
pass


# Your IP Stack
r = requests.get("https://api.ipify.org?format=json", verify=False)
data = json.loads(r.text)
__ip__ = data["ip"]
r = requests.get("http://ip-api.com/json/"+__ip__, verify=False)
data = json.loads(r.text)
__isp__ = data["isp"]
__sizefile__ = os.stat("toolkit.py")
__version__ = """
>> Result in 'python3 {} --version': .:: Team Pencari Proxy [Version 1.26072019] ::. 
""".format(__file__)
__file__ = "toolkit.py"
__help__ = """
     Syntax Line                Description Syntax Line    
   ---------------            ---------------------------
 --version                  Check Version Team Pencari Proxy Toolkit
 --license                  Check Your license in Team Pencari Proxy Toolkit
 --help                     Check Syntax Line in Team Pencari Proxy Toolkit
"""
__copyright__ = """
     Copyright (c) 2019
   ----------------------
 Copyright sangat berharga bagi kami untuk berkreasi didunia pemprograman,
 Jadi tidak ada salahnya bagi kami untuk menbatasi atau membuat copyright di
 toolkit ini. -fourtyonesec

     Admin Group
   ---------------
 - Irvan Noor Soleh (admin)
 - Brilyan Okta Firmansyah A.K.A ./fourtyonesec (admin)
 - Aruji Hermantyar (admin)
 - Ahmad Nur Zakir (admin)
 - Akbar Rifai A.K.A Aztec Rabbit (admin)
 - M.Farisal (admin)
 - Heleh (admin)
 - Maxs Wopy (admin)
 - Mestur (admin)
 - Azizul Hakim (admin)
 - Renata Aldi Cakra (admin)
 - Eko Lesmana (admin)
 - (Sorry!) (admin)

     Peraturan Remake / Remode
   -----------------------------
 * Bagi anda yang ingin remake / remode di toolkit ini mohon untuk chat
 admin via Whatsapp. bisa menghubungi admin yang ada diatas!
 Terimakasih - ./fourtyonesec


 Slogan Group: Created - Development - Share to public
"""
__data_table__ = """
     Datatable                         Description
   -------------                     ---------------
     ip_tool                Internet Protocol Checker Online Tools.
      quit                  Quit for tool
"""
__parameters__ = """
   Parameters                      Value
 --------------                  ---------
 type (required)         http, https, socks4, socks5
 anon (optional)         transparent, anonymous, elite
 country (optional)       ID, US, or Country ISO code 


   Country ISO Code
 --------------------
 https://www.nationsonline.org/oneworld/country_code_list.htm
"""

session = requests.Session()

__banner__ = """  
       _     _
       \`\ /`/    Team Pencari Proxy [Version 1.26072019]
        \ V /     Copyright (c) 2019. Team Pencari Proxy        
        /. .\     Date: """+__date__+"""
       =\ T /=    User-Agent (default): """+__useragent__+"""               
        / ^ \\     Usage: 'python3 {}' """.format(__file__)+ """
       /\\\ //\\    Your IP: """+__ip__+""" ("""+__isp__+""")
     __\\ " " /__  Size: """+str(__sizefile__.st_size)+""" KB       
    (____/^\____)

* Information: Team Pencari Proxy Toolkit was here! Created, Development, Shared to public!
               this tool for created in my friends and my member group!"""

def license_code():
	try:
		file_write = open("src/license.txt", "r")
		sys.exit(1)
		pass
	except FileNotFoundError:
		pass
	try:
		license = str(input("\n[*] License: "))
		if (license == ""):
			print("[!] Your input license invalid. Please try again!")
			sys.exit(1)
			pass
		else:
			pass
		print("[*] Processing data license, Please waiting a moments !")
		try:
			r = session.get("https://fourtyonesec.000webhostapp.com/" + license +".json") 
			data = json.loads(r.text)
			try:
				os.mkdir("src")
			except FileExistsError:
				pass
			file_write = open("src/license.txt", "w")
			file_write.write(license)
			pass
		except json.decoder.JSONDecodeError:
			print("[!] Your license invalid or not found! Please try again.")
			sys.exit(1)
			pass
		except urllib3.exceptions.NewConnectionError:
			print("[!] Failed to establish a new connection: Temporary failure in name resolution") 
			pass
		except requests.exceptions.ConnectionError:
			print("[!] Failed to establish a new connection: Temporary failure in name resolution") 
			pass
		time.sleep(2)
		print("[*] Successfully find your license.")
		time.sleep(2)
		pass
	except KeyboardInterrupt:
		print("\n[!] Keyboard CTRL + C Detected. ")
		sys.exit(1)
		pass
	except urllib3.exceptions.NewConnectionError:
		print("[!] Failed to establish a new connection: Temporary failure in name resolution") 
		pass
	except requests.exceptions.ConnectionError:
		print("[!] Failed to establish a new connection: Temporary failure in name resolution") 
		pass
	pass

def main():
	try:
		print(__banner__)
		data_table()
		pass
	except KeyboardInterrupt:
		print("\n[!] Keyboard CTRL + C Detected. ")
		sys.exit(1)
		pass
	except urllib3.exceptions.NewConnectionError:
		print("[!] Failed to establish a new connection: Temporary failure in name resolution") 
		pass
	except requests.exceptions.ConnectionError:
		print("[!] Failed to establish a new connection: Temporary failure in name resolution") 
		pass
	pass


def data_table():
	file_write = open("src/license.txt", "r")
	license = file_write.read()
	r = session.get("https://fourtyonesec.000webhostapp.com/" + license +".json") 
	data = json.loads(r.text)
	try:
		print(__data_table__)
		username = data["username"]
		choice = str(input("[./"+username+"] >> "))
		if (choice == "ip_tool"):
			ip_tool()
			pass
		elif (choice == "quit"):
			sys.exit(1)
			pass
		else:
			print("\n[!] Your menu invalid. Please try again.")
			data_table()
			pass
		pass
	except KeyboardInterrupt:
		print("\n[!] Keyboard CTRL + C Detected. ")
		sys.exit(1)
		pass
	except urllib3.exceptions.NewConnectionError:
		print("[!] Failed to establish a new connection: Temporary failure in name resolution") 
		pass
	except requests.exceptions.ConnectionError:
		print("[!] Failed to establish a new connection: Temporary failure in name resolution") 
		pass
	pass


# check_proxy                Check Proxy using requests with this quick check.
__data_menu__ = """
     Datatable                         Description
   -------------                     ---------------
    http_header                Review the HTTP Headers from a web server with this quick check.
      ip_info                  IP Geolocation from query - JSON endpoint with this quick check.
     get_proxy                 Get Proxy Free! with website 'https://free-proxy-list.net/'.
    proxy_text                 Get Proxy save to file with website 'https://www.proxy-list.download/'

       quit                    Quit for tools
"""

def ip_tool():
	file_write = open("src/license.txt", "r")
	license = file_write.read()
	r = session.get("https://fourtyonesec.000webhostapp.com/" + license +".json") 
	data = json.loads(r.text)
	try:
		print(__data_menu__)
		username = data["username"]
		while True:
			choice = str(input("[./"+username+"] >> "))
			if (choice == "http_header"):
				http_header()
				pass
			elif (choice == "ip_info"):
				ip_info()
				pass
			elif (choice == "get_proxy"):
				get_proxy()
				pass
			elif (choice == "proxy_text"):
				proxy_text()
				pass
			elif (choice == "quit"):
				data_table()
				pass
			else:
				print("\n[!] Your menu invalid. Please try again.")
				ip_tool()
				pass
			pass
	except KeyboardInterrupt:
		print("\n[!] Keyboard CTRL + C Detected. ")
		sys.exit(1)
		pass
	except urllib3.exceptions.NewConnectionError:
		print("[!] Failed to establish a new connection: Temporary failure in name resolution") 
		pass
	except requests.exceptions.ConnectionError:
		print("[!] Failed to establish a new connection: Temporary failure in name resolution") 
		pass
	pass

def http_header():
	try:
		while True:
			url = str(input("[./url_access] >> "))
			if (url == "quit"):
				print("[*] Quit! ")
				ip_tool()
				pass
			elif (url == ""):
				print("[!] Your url invalid. Please try again.")
				http_header()
				pass
			else:
				# r = requests.get("https://api.hackertarget.com/httpheaders/?q=" + url)
				# print(r.text)
				# r = requests.get(url)
				# json_response = r.json()
				# repository = json_response['items'][0]
				# print(f'Text matches: {repository["text_matches"]}')
				print("[*] HTTP Header using package to 'wget' ... \n")
				time.sleep(2)
				os.system("wget --server-response --spider -q " + url + " > /dev/null")
				time.sleep(2)
				print("\n[*] Successfully check HTTP Header for url '"+url+"'")
				print("[*] If you want to exit this menu you can type 'quit' to exit\n")
				pass
			pass
	except requests.exceptions.InvalidURL:
		print("[!] Invalid URL '"+url+"': No host supplied")
		print("[*] Fixed url example: http://www.google.com/ or https://www.google.com/")
		sys.exit(1)
		pass
	except KeyboardInterrupt:
		print("\n[!] Keyboard CTRL + C Detected. ")
		sys.exit(1)
		pass
	pass

def ip_info():
	try:
		while True:
			ip = str(input("[./ip_info] >> "))
			if (ip == ""):
				print("[!] Your IP invalid. PLease try again!")
				ip_info()
				pass
			elif (ip == "quit"):
				print("[*] Quit! ")
				ip_tool()
				pass
			else:
				print("\n[*] IP Info using website to 'https://ip-api.com/' ... \n")
				time.sleep(2)
				fields = "status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,currency,isp,org,as,asname,reverse,mobile,proxy,query"
				url_path = "http://ip-api.com/json/"+ip+"?fields="+fields
				r = requests.get(url_path, verify=False)
				data = json.loads(r.text)
				# print(data)
				print("[*] AS: " +str(data["as"]))
				print("[*] ASNAME: " +str(data["asname"]))
				print("[*] City: " + str(data["city"]))
				print("[*] Continent: " + str(data["continent"]))
				print("[*] continentCode: " + str(data["continentCode"]))
				print("[*] Country: " + str(data["country"]))
				print("[*] countryCode: " + str(data["countryCode"]))
				print("[*] Currency: " + str(data["currency"]))
				print("[*] District: " + str(data["district"]))
				print("[*] ISP: " + str(data["isp"]))
				print("[*] Latitude: " + str(data["lat"]))
				print("[*] Longitude: " + str(data["lon"]))
				print("[*] Mobile: " + str(data["mobile"]))
				print("[*] Organization: " + str(data["org"]))
				print("[*] Proxy: " + str(data["proxy"]))
				print("[*] Region: " + str(data["region"]))
				print("[*] regionName: " + str(data["regionName"]))
				print("[*] ReverseHost: " + str(data["reverse"]))
				print("[*] Timezone: " + str(data["timezone"]))
				print("[*] ZipCode: " + str(data["zip"]))
				time.sleep(2)
				print("\n[*] Successfully check IP Info for ip '"+ip+"'")
				print("[*] If you want to exit this menu you can type 'quit' to exit\n")
				pass
			pass
	except KeyboardInterrupt:
		print("[!] Keyboard CTRL + C Detected. ")
		sys.exit(1)
		pass
	pass

def proxy_text():
	try:
		print(__parameters__)
		while True:
			type = str(input("[*] Type Proxy: "))
			if (type == ""):
				print("[!] Your 'type proxy' invalid. Please try again!")
				proxy_text()
				pass
			else:
				pass
			anon = str(input("[*] Anonymity Proxy: "))
			if (anon == ""):
				print("[!] Your 'anonymity proxy' invalid. Please try again!")
				proxy_text()
				pass
			else:
				pass
			country = str(input("[*] Country Proxy: "))
			if (country == ""):
				print("[!] Your 'country proxy' invalid. Please try again!")
				proxy_text()
				pass
			else:
				pass
			url = "https://www.proxy-list.download/api/v1/get?type="+type+"&anon="+anon+"&country="+country
			r = session.get(url, verify=False)
			# print(r.text)
			try:
				os.mkdir("result")
				pass
			except FileExistsError:
				pass
			date_time = now.strftime("%m/%d/%Y_%H:%M:%S")
			save = open("result/result.txt", "w+")
			save.write("# Result Time: " + str(date_time) + "\n\n" + str(r.text))
			save.close()
			print("\n[*] Successfully Generate Proxy Free! ")
			print("[*] Adding file 'result/result.txt'\n")
			print("[*] If you want to exit this menu you can type 'quit' to exit")
			print("[*] If you want to repeat you can type 'while' to repeat the system\n")
			choice = str(input("[./proxy_text] >> "))
			if (choice == ""):
				print("[!] Your input invalid. PLease try again!")
				proxy_text()
				pass
			elif (choice == "quit"):
				print("[*] Quit! ")
				ip_tool()
				pass
			elif (choice == "while"):
				proxy_text()
				pass
			else:
				print("[!] Your input invalid. PLease try again!")
				proxy_text()
				pass
			pass
		pass
	except KeyboardInterrupt:
		print("[!] Keyboard CTRL + C Detected. ")
		sys.exit(1)
		pass
	pass


def get_proxy():
	try:
		while True:
			count = str(input("[+] Proxy Count (1-100): "))
			if (count == ""):
				print("[!] Your Proxy Count invalid. PLease try again!")
				get_proxy()
				pass
			elif (count == "quit"):
				print("[*] Quit! ")
				ip_tool()
				pass
			else:
				pass
			print("[*] Generate Proxy Free! Limit for 10 Proxy")
			for x in range(int(count)):
				url = "https://api.getproxylist.com/proxy"
				ip_backend = str(random.randint(1, 200))
				ip_static = "114.124.197."+str(ip_backend)
				headers = {
					"x-forwarded-for": str(ip_static),
					"Connection": "keep-alive",
					"User-Agent": __useragent__
				}
				session = requests.Session()
				r = session.get(url, headers=headers, verify=False)
				data = json.loads(r.text)
				# print(data)
				try:
					live = "\033[32;1m"
					c = "\033[0m"
					print("\n[*] Proxy is " + live + str(data["ip"] + c))
					print("[*] Port: " + str(data["port"]))
					print("[*] Protocol: " + str(data["protocol"]))
					print("[*] Anonymity: " + str(data["anonymity"]))
					print("[*] Last Tested: " + str(data["lastTested"]))
					print("[*] [INFORMATION] >> ")
					print("""
  - AllowRefererHeader: """+ str(data["allowsRefererHeader"]) + """
  - AllowUserAgentHeader: """+ str(data["allowsUserAgentHeader"]) + """
  - AllowsCustomHeaders: """+ str(data["allowsCustomHeaders"]) + """
  - AllowsCookies: """+ str(data["allowsCookies"]) + """
  - AllowsPost: """+ str(data["allowsPost"]) + """
  - AllowsHttps: """+ str(data["allowsHttps"]) + """
						""")
					print("[*] Country: " + str(data["country"]))
					print("[*] ConnectTime: " + str(data["country"]))
					print("[*] DownloadSpeed: " + str(data["downloadSpeed"]))
					print("[*] SecondsToFirstByte: " + str(data["secondsToFirstByte"]))
					print("[*] Uptime: " + str(data["uptime"] + "\n"))
					pass
				except KeyError:
					print("\n[!] " + data["error"])
				pass
			print("\n[*] Successfully Generate Proxy Free! ")
			print("[*] If you want to exit this menu you can type 'quit' to exit\n")
			pass
	except KeyboardInterrupt:
		print("[!] Keyboard CTRL + C Detected. ")
		sys.exit(1)
		pass
	pass


def menu_item():
	try:
		pass
	except KeyboardInterrupt:
		print("\n[!] Keyboard CTRL + C Detected. ")
		sys.exit(1)
		pass
	except urllib3.exceptions.NewConnectionError:
		print("[!] Failed to establish a new connection: Temporary failure in name resolution") 
		pass
	except requests.exceptions.ConnectionError:
		print("[!] Failed to establish a new connection: Temporary failure in name resolution") 
		pass
	pass


try:
	if (sys.argv[1] == "--help"):
		os.system("clear")
		print(__banner__)
		print(__help__)
		sys.exit(1)
		pass
	elif (sys.argv[1] == "--version"):
		os.system("clear")
		print(__banner__)
		print(__version__)
		sys.exit(1)
		pass
	elif (sys.argv[1] == "--copyright"):
		os.system("clear")
		print(__banner__)
		print(__copyright__)
		sys.exit(1)
		pass
	elif (sys.argv[1] == "--license"):
		os.system("clear")
		print(__banner__)
		print("\n>> Result in 'python3 {} --license': ".format(__file__))
		try:
			file_write = open("src/license.txt", "r")
			license = file_write.read()
			r = session.get("https://fourtyonesec.000webhostapp.com/" + license +".json") 
			data = json.loads(r.text)
			print("\n[*] Name: " + str(data["name"]))
			print("[*] License: " + str(data["license"]))
			print("[*] Expired: " + str(data["expired"] + "\n"))
		except json.decoder.JSONDecodeError:
			print("\n[!] Your license invalid or not found! Please try again.\n")
			sys.exit(1)
			pass
		except FileNotFoundError:
			print("\n[!] Your license invalid or not found! Please try again.")
			sys.exit(1)
			pass
		except urllib3.exceptions.NewConnectionError:
			print("[!] Failed to establish a new connection: Temporary failure in name resolution") 
			pass
		except requests.exceptions.ConnectionError:
			print("[!] Failed to establish a new connection: Temporary failure in name resolution") 
			pass	
		sys.exit(1)
		pass
	else:
		main()
		pass
except IndexError:
	pass

if __name__ == "__main__":
	try:
		os.system("clear")
		main()
		license_code()
		pass
	except urllib3.exceptions.NewConnectionError:
		print("[!] Failed to establish a new connection: Temporary failure in name resolution") 
		pass
	except requests.exceptions.ConnectionError:
		print("[!] Failed to establish a new connection: Temporary failure in name resolution") 
		pass
	pass