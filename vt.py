import requests as req
import json,os,sys
import threading as tr
vtkey= "b29817abfaf1a707729dbb72096d20497f22e9941df5be42c35457bb9ab8f2cf"

sayac = 1
ara = input("# ").strip()
#ara = "Virüs.exe"
list(ara)
while sayac:
    path_ = "/storage/emulated/0/"
    if os.path.exists(path_): # dosyanin olup olmadigini kontrol ediyor 
        sayac  = 0
for roots, dirs, files in os.walk(path_): # walk fonksiyonu 3 sonuc verir dosya alt dizi dosya bizde dosyayi aliyoruz
    for each_file in files:
        if ara[0] in str(each_file): # liste hakine getirip ilk indexdeki sonucu aliyoruz
            dos = roots.replace("\\","/") +"/"+str(each_file)
with open(dos,'rb') as f: 
         file_bin = f.read() 
def main():
    global file_bin
    headers = {
    
    "x-apikey":vtkey
    
    }    
   
    upload = {"file":(file_bin)}
    dowland = req.post("https://www.virustotal.com/api/v3/files" ,headers=headers, files=upload) # file upload virustotal 
    if dowland.status_code  == "204":
        print("Günlük kotaya Ulaşıldı 00.00 Günlük kota yenilenecek")
        sys.exit()
    elif dowland.status_code == "400":
        print("yanlış değerlere sahip arguman girdiniz Tekrar deneyiniz")
        sys.exit()

    
    file_id = dowland.json().get('data').get('id') # dosya id aliyoruz jsonla
    
    api_url= f"https://www.virustotal.com/api/v3/analyses/{file_id}" # dosya idsini baska vt analiz apisine gonderiyor
    istek1 = req.get(api_url, headers=headers) # requests 
    sha256 = istek1.json().get('meta').get('file_info').get('sha256') #jsonlu verideki sha256 cekiyoruz get komutu ile
    
    istek2 = f'https://www.virustotal.com/api/v3/files/{sha256}' #bu seferde bu vt apidine sha256 gondererek yanit bekliyoruz
    api2 = req.get(istek2,headers=headers) 
    
    resep = api2.json().get("data").get("attributes").get('last_analysis_results') #gelen yanit last analsys icinde ona get komutu ile istei gonderiyoruz 
    
 
    for key, value in resep.items():# for ile hem anahtari aliyoz hemde degeri aliyoruz
        
        print(f"""
        Anti-virus name: {key}
        Anti-virus resepsone;
        {value}
 :
        """)
 
 
 

hizlandirma = tr.Thread(target=main) #hizlandirma komutu
hizlandirma.start() # start komutu ilede baslatiyoruz