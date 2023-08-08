import re
import time
import whois
import openai
import requests
from bs4 import BeautifulSoup
from unidecode import unidecode
from urllib.parse import urlparse
#from api import get_decrypted_api_key


# enkripsi api key
#json_file = 'encrypted_api_key.json'
#keyword = 'KUNCI_API_KEY'
#decrypted_api_key = get_decrypted_api_key(json_file, keyword)


# Normalisasi ssl(http/https)
def normalize_protocol_url(url):
    if url.startswith('http://'):
        url = url[7:]
    elif url.startswith('https://'):
        url = url[8:]

    try:
        response = requests.get('https://' + url)
        if response.status_code == 200:
            return 'https://' + url
    except (requests.exceptions.SSLError, requests.exceptions.RequestException):
        pass

    return 'http://' + url

# Normalisasi Url Asli
def normalize_url_actual(normalisasi_protokol):
    original_url = normalisasi_protokol

    try:
        response = requests.head(normalisasi_protokol, allow_redirects=True)
        normalisasi_protokol = response.url
    except requests.exceptions.RequestException:
        normalisasi_protokol = original_url

    return normalisasi_protokol
    
# menghitung panjang domain
def length_domain(url_asli):
    parsed_url = urlparse(url_asli)
    domain_parts = parsed_url.netloc.split('.')

    if parsed_url.netloc.replace('.', '').isnumeric():
        return -1

    if len(domain_parts) >= 2:
        last_part = domain_parts[-1]
        second_last_part = domain_parts[-2]
        if len(last_part) <= 3 and len(second_last_part) <= 3:
            domain_parts = domain_parts[:-2]
        elif len(last_part) <= 3:
            domain_parts = domain_parts[:-1]

    main_domain = domain_parts[-1] if len(domain_parts) >= 1 else ''

    domain_length = len(main_domain)
    if domain_length > 10:
        result_length = -1
    else:
        result_length = 1

    return result_length

# Memeriksa apakah domain memiliki tanda hubung (-)
def dashes(url_asli):
    parsed_url = urlparse(url_asli)
    domain_parts = parsed_url.netloc.split('.')

    if parsed_url.netloc.replace('.', '').isnumeric():
        return -1

    if len(domain_parts) >= 2:
        last_part = domain_parts[-1]
        second_last_part = domain_parts[-2]
        if len(last_part) <= 3 and len(second_last_part) <= 3:
            domain_parts = domain_parts[:-2]
        elif len(last_part) <= 3:
            domain_parts = domain_parts[:-1]

    main_domain = domain_parts[-1] if len(domain_parts) >= 1 else ''

    if '-' in main_domain:
        return -1
    return 1


# Memeriksa apakah url memiliki protocol http atau https
def check_ssl(url_asli):
    parsed_url = urlparse(url_asli)
    scheme = parsed_url.scheme

    if parsed_url.netloc.replace('.', '').isnumeric():
        return -1

    if scheme == 'https':
        return 1
    else:
        return -1


# Memeriksa penggunaan tld (top level domain) yang di perbolehkan
def tld(url_asli):
    parsed_url = urlparse(url_asli)

    if parsed_url.netloc.replace('.', '').isnumeric():
        return -1

    match = re.search(r'(?<=://)[\w\.-]+', url_asli)
    if match:
        domain = match.group(0)
        has_number = any(char.isdigit() for char in domain)
        if has_number:
            return -1

    valid_domains = ["com", "io", "gov", "org", "net", "ac.id", "edu", "co.id", "id",
                     "go.id", "mil.id", "sch.id", "or.id", "net.id"]

    domain = parsed_url.netloc.split('.')[-1]
    if domain in valid_domains:
        return 1
    else:
        return -1

# Memeriksa penggunaan karakter yang dilarang
def check_prohibited_characters(url_asli):

    parsed_url = urlparse(url_asli)
    if parsed_url.netloc.replace('.', '').isnumeric():
        return -1

    if '@' in url_asli or '!' in url_asli or ';'  in url_asli or '*' in url_asli:
        return -1
    else:
        return 1

# Memeriksa panjang karakter spesial yang diperbolehkan
def length_special_characters(url_asli):

    parsed_url = urlparse(url_asli)
    if parsed_url.netloc.replace('.', '').isnumeric():
        return -1

    path = url_asli.split('/', 3)[-1]
    special_chars = {'#', '+', '?', '-', '_', '=', '$', '%', '&'}

    count = sum(1 for char in path if char in special_chars)
    if count < 15 :
        return 1
    else:
        return -1

# memeriksa banyak path yang digunakan
def check_path(url_asli):

    parsed_url = urlparse(url_asli)
    path = parsed_url.path

    if parsed_url.netloc.replace('.', '').isnumeric():
        return -1

    jumlah_path = path.count('/')

    if jumlah_path <= 3:
        return 1
    else:
        return -1

# Memeriksa banyak single slash yang digunakan
def count_single_slash(url_asli):

    parsed_url = urlparse(url_asli)
    if parsed_url.netloc.replace('.', '').isnumeric():
        return -1

    single_slash_count = url_asli.count('/') - url_asli.count('//')
    if single_slash_count > 4:
        return -1
    else:
        return 1

# Memeriksa banyak titik yang digunakan dengen batas maksimal 5
def count_dots(url_asli):

    parsed_url = urlparse(url_asli)
    if parsed_url.netloc.replace('.', '').isnumeric():
        return -1

    dot_count = url_asli.count('.')
    if dot_count > 5:
        return -1
    else:
        return 1

# memeriksa panjang url yang digunakan dengan batas maksimal 80 karakter
def length_url(url_asli):

    parsed_url = urlparse(url_asli)
    if parsed_url.netloc.replace('.', '').isnumeric():
        return -1

    if len(url_asli) > 80:
        return -1
    else:
        return 1

# memeriksa sumbers daya konten yang digunakan mengandung kata yang mencurigakan
def sumber_daya_konten(url_asli):
    try:
        response = requests.get(url_asli)

        soup = BeautifulSoup(response.text, 'html.parser')

        text = ' '.join(soup.stripped_strings).lower()

        normalized_text = unidecode(text)

        if re.search(r'\b(claim|reward|ambil|hadiahmu|kepo|kepoin|melihat|stalking|ngepoin|fb|ig|tarif|dana|facebookkepo)\b', normalized_text):
            return -1
        else:
            return 1
    except requests.exceptions.RequestException as e:
        return 1

# memeriksa keberadaan favicon
def keberadaan_favicon(url_asli):
    try:
        response = requests.get(url_asli)
        soup = BeautifulSoup(response.content, 'html.parser')
        head = soup.find('head')
        if head:
            favicon_links = head.find_all('link', rel='icon')
            for favicon_link in favicon_links:
                href = favicon_link.get('href')
                if href.endswith('.ico') or href.endswith('.png'):
                    return 1
        return -1
    except requests.exceptions.RequestException as e:
        return -1

# Memeriksa whois domain yang digunakan apakah memiliki status atau tidak
def check_whois(url_asli):
    parsed_url = urlparse(url_asli)

    try:
        domain = whois.whois(parsed_url.netloc)
        if domain.status:
            return 1
        else:
            return -1
    except Exception as e:
        print("Error saat memeriksa whois, Nilai dikembalikan menjadi -1:", e)
        return -1

# mengggunakan model openai untuk memeriksa url yang digunakan apakah phishing atau tidak
#def openai_model_text_davinci_003(url_asli):
#    counter = 0
#   while True:
#        counter += 1
#       try:
#            openai.api_key = decrypted_api_key
#            command = f"Periksa URL ini merupakan phishing atau tidak. Jika phishing berikan nilai output -1, dan jika tidak phishing berikan nilai 1. result hanya berupa angka 1 dan -1 tidak perlu memiliki penjelasan deskripsi. '{url_asli}'"

#            response = openai.Completion.create(
#                model="text-davinci-003",
#                prompt=command,
#                temperature=1,
#                max_tokens=5,
#                top_p=1,
#                frequency_penalty=0,
#                presence_penalty=0
#            )
#           result = response.choices[0].text.strip()


#            if result == "1":
#                return 1
#            elif result == "-1":
#                return -1

#            print(f"Hasil model text-davinci-003 tidak valid pada percobaan ke-{counter}, mencoba kembali...")
#        except Exception as e:
#            print(f"Terjadi kesalahan pada model text-davinci-003 pada percobaan ke-{counter}:", str(e))
#            print("Akan mencoba kembali setelah 5 detik...")
#            time.sleep(5)


def extract_features(url):
    # Normalisasi protokol URL
    normalized_protocol_url = normalize_protocol_url(url)

    # Dapatkan URL asli setelah normalisasi
    url_asli = normalize_url_actual(normalized_protocol_url)

    features = []
    features.append(length_domain(url_asli))
    features.append(dashes(url_asli))
    features.append(check_ssl(url_asli))
    features.append(check_prohibited_characters(url_asli))
    features.append(length_special_characters(url_asli))
    features.append(check_path(url_asli))
    features.append(tld(url_asli))
    features.append(count_single_slash(url_asli))
    features.append(count_dots(url_asli))
    features.append(length_url(url_asli))
    features.append(sumber_daya_konten(url_asli))
    features.append(keberadaan_favicon(url_asli))
    features.append(check_whois(url_asli))
#  features.append(openai_model_text_davinci_003(url_asli))
    return features