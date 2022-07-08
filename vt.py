import requests as req
import json,os,sys
import hashlib as hb
import threading as tr
vtkey= "b29817abfaf1a707729dbb72096d20497f22e9941df5be42c35457bb9ab8f2cf"
headers = {
    
    "x-apikey":vtkey
    
     }   
sayac = 1
ara = input("# ").strip()
list(ara)
while sayac:
    path_ = "/data/data/com.termux/files/home/"
    if os.path.exists(path_):
      sayac = 0
    else:
        break
for roots, dirs, files in os.walk(path_):
   for each_file in files:
       if ara in str(each_file): 
           dos = roots.replace("\\","/") +"/"+str(each_file)
      
f = open(dos,'rb') 
file_bin = f.read()
upload = {"file":(file_bin)}
dowland = req.post("https://www.virustotal.com/api/v3/files" ,headers=headers,  files=upload)
file_id = dowland.json().get('data').get('id')
api_url= f"https://www.virustotal.com/api/v3/analyses/{file_id}"
istek1 = req.get(api_url, headers=headers)
sha256 = istek1.json().get('meta').get('file_info').get('sha256')
istek2 = f'https://www.virustotal.com/api/v3/files/{sha256}'
api = req.get(istek2,headers=headers)
resep = api.json().get("data").get("attributes").get('last_analysis_results')
for key, value in resep.items():
   print(f"""
        Anti-virus name: {key}
        Anti-virus resepsone;
        {value}
    """)
 
