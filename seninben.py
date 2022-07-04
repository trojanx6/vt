import requests as req
import json,os
import threading as tr
vtkey= "b29817abfaf1a707729dbb72096d20497f22e9941df5be42c35457bb9ab8f2cf"

heckir= 1 
ara = input("# ").strip()
#ara = "Virüs.exe"
list(ara)
while heckir:
    path_ = "/storage/emulated/0/"
    if os.path.exists(path_):
        heckir  = 0
for roots, dirs, files in os.walk(path_):
    for each_file in files:
        if ara[0] in str(each_file):
            filli_boya  = roots.replace("\\","/") +"/"+str(each_file)
with open(filli_boya, 'rb') as f:
         file_bin = f.read()
def vin_basgaza():
    haldir_saldir = {
    
    "x-apikey":vtkey
    
    }    
   
    upload = {"file":(file_bin)}
    postala = req.post("https://www.virustotal.com/api/v3/files" ,headers=haldir_saldir, files=upload)
    gitti_o = postala.json().get('data').get('id')
    apiu = f"https://www.virustotal.com/api/v3/analyses/{gitti_o}"
    sipa = req.get(apiu, headers=haldir_saldir)
    sha = sipa.json().get('meta').get('file_info').get('sha256')
    pembe_mezarlik = f'https://www.virustotal.com/api/v3/files/{sha}'
    istek = req.get(pembe_mezarlik, headers=haldir_saldir)
    dark = istek.json().get("data").get("attributes").get('last_analysis_results')
    
 
    for key, value in dark.items():
        print(f"""
        Anti-virus name: {key}
        Anti-virus resepsone;
        {value}
 
        """)
 
 
 

hizli_ve_ofkeli_8_adana = tr.Thread(target=vin_basgaza)
hizli_ve_ofkeli_8_adana.start()