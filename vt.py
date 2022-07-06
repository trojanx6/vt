import requests as req
import json,os,sys
import threading as tr
vtkey= "b29817abfaf1a707729dbb72096d20497f22e9941df5be42c35457bb9ab8f2cf"
headers = {
    
    "x-apikey":vtkey
    
     }   
sayac = 1
ara = input("# ").strip()
#ara = "Virüs.exe"
list(ara)
while sayac:
    
    path_ = "/storage/emulated/0/"
    if os.path.exists(path_): # dosyanin olup olmadigini kontrol ediyor 
       sayac  = 0
for roots, dirs, files in os.walk(path_):
   for each_file in files:
       if ara in str(each_file): # liste hakine getirip ilk indexdeki sonucu aliyoruz
           dos = roots.replace("\\","/") +"/"+str(each_file)
                
                
                
f = open(dos,'rb')
file_bin = f.read() 
f.close()
upload = {"file":(file_bin)}
dowland = req.post("https://www.virustotal.com/api/v3/files" ,headers=headers,  files=upload) 
if dowland.status_code  == "204":
        print("Günlük kotaya Ulaşıldı 00.00 Günlük kota yenilenecek")
        sys.exit()
elif dowland.status_code == "400":
        print("yanlış değerlere sahip arguman girdiniz Tekrar deneyiniz")
        sys.exit()
file_id = dowland.json().get('data').get('id') 
api_url= f"https://www.virustotal.com/api/v3/analyses/{file_id}" 
istek1 = req.get(api_url, headers=headers) 
sha256 = istek1.json().get('meta').get('file_info').get('sha256') 
istek2 = f'https://www.virustotal.com/api/v3/files/{sha256}' 
api2 = req.get(istek2,headers=headers) 
resep = api2.json().get("data").get("attributes").get('last_analysis_results') 
for key, value in resep.items():     
    print(f"""
    Anti-virus name: {key}
    Anti-virus resepsone;
     {value}
            """)
 
 
 
#hizlandirma = tr.Thread(target=main) #hizlandirma komutu
#hizlandirma.start() # start komutu ilede baslatiyoruz