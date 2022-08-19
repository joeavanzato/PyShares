# Requires pythonnet, Python <=3.8, .NET Framework, pywin32
# pyinstaller --hidden-import=pythonnet --onefile .\pyshares.py
# "C:\Program Files\Python38\Scripts\pyinstaller.exe" --hidden-import=pythonnet --onefile PyShares.py
import argparse, socket, traceback, sys, clr, win32net, os, re, platform
from concurrent.futures import ThreadPoolExecutor
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

parser = argparse.ArgumentParser(
    usage='\n Share Scanning, now in Python!\n -l -- [Target Host/IP List]\n -u --users Dump out Domain Users, Skip Shares ')
parser.add_argument("-l", "--list",
                    help='Specify Target Host/IP List (Newline Separated List of Computers or IP Addresses)',
                    required=False, action='store_true')
parser.add_argument("-u", "--users",
                    help='Dump Domain Users',
                    required=False, action='store_true')
parser.add_argument("-f", "--files",
                    help='Scan Detected Shares for Interesting Files',
                    required=False, action='store_true')
parser.add_argument("-re", "--regex",
                    help='Pass Interesting Files through Regex Scanning',
                    required=False, action='store_true')
parser.add_argument("-ss", "--sharpshares",
                    help='Specify SharpShares Output File, Pass SharpShares Output Into PyShares, Bypassing Share Enumeration and initiating interesting file scan.',
                    required=False,
                    type=str,
                    nargs=1)
parser.add_argument("-mt", "--maxthreads",
                    help='Specify Max Threads for Operations',
                    required=False,
                    type=int,
                    nargs=1)
args = parser.parse_args()

logo = """
 ██▓███ ▓██   ██▓  ██████  ██░ ██  ▄▄▄       ██▀███  ▓█████   ██████ 
▓██░  ██▒▒██  ██▒▒██    ▒ ▓██░ ██▒▒████▄    ▓██ ▒ ██▒▓█   ▀ ▒██    ▒ 
▓██░ ██▓▒ ▒██ ██░░ ▓██▄   ▒██▀▀██░▒██  ▀█▄  ▓██ ░▄█ ▒▒███   ░ ▓██▄   
▒██▄█▓▒ ▒ ░ ▐██▓░  ▒   ██▒░▓█ ░██ ░██▄▄▄▄██ ▒██▀▀█▄  ▒▓█  ▄   ▒   ██▒
▒██▒ ░  ░ ░ ██▒▓░▒██████▒▒░▓█▒░██▓ ▓█   ▓██▒░██▓ ▒██▒░▒████▒▒██████▒▒
▒▓▒░ ░  ░  ██▒▒▒ ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▒▓ ░▒▓░░░ ▒░ ░▒ ▒▓▒ ▒ ░
░▒ ░     ▓██ ░▒░ ░ ░▒  ░ ░ ▒ ░▒░ ░  ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ░  ░░ ░▒  ░ ░
░░       ▒ ▒ ░░  ░  ░  ░   ░  ░░ ░  ░   ▒     ░░   ░    ░   ░  ░  ░  
         ░ ░           ░   ░  ░  ░      ░  ░   ░        ░  ░      ░  
         ░ ░                                                         
                       """
print(logo)
print("[-] Joe Avanzato, @panscan")
print("[-] github.com/joeavanzato\n")

if args.maxthreads is not None:
    MAX_THREADS = args.maxthreads[0]
else:
    MAX_THREADS = 10

re_dict = {}
# Some stolen from https://github.com/sdushantha/dora/blob/main/dora/db/data.json
re_dict["SSN"] = '\d{3}-\d{2}-\d{4}'
re_dict["SSN_Proximity"] = '(SSN|ssn)[\w\W]{1,200}?(\d{9}|\d{3}-\d{2}-\d{4})'
re_dict['Google_API'] = "AIza[0-9A-Za-z-_]{35}"
re_dict['MailGun_API'] = "key-[0-9a-zA-Z]{32}"
re_dict[
    'Heroku_API'] = "[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"
re_dict['Slack_API'] = "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})"
re_dict['Slack_Webhook'] = "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"
re_dict['MailChimp_API'] = "[0-9a-f]{32}-us[0-9]{1,2}"
re_dict['Facebook_Access_Token'] = "EAACEdEose0cBA[0-9A-Za-z]+"
re_dict['Facebook_Secret_Key'] = "(?i)(facebook|fb)(.{0,20})?['\"][0-9a-f]{32}['\"]"
re_dict['Facebook_Client_ID'] = "(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}['\"]"
re_dict['Twitter_Secret_Key'] = "(?i)twitter(.{0,20})?['\"][0-9a-z]{35,44}['\"]"
re_dict['Twitter_Client_ID'] = "(?i)twitter(.{0,20})?['\"][0-9a-z]{18,25}['\"]"
re_dict['GitHub_Personal_Access_Token'] = "ghp_[0-9a-zA-Z]{36}"
re_dict['GitHub_OAuth_Access_Token'] = "gho_[0-9a-zA-Z]{36}"
re_dict['GitHub_App_Token'] = "(ghu|ghs)_[0-9a-zA-Z]{36}"
re_dict['GitHub_Refresh_Token'] = "ghr_[0-9a-zA-Z]{76}"
re_dict['LinkedIn_Secret_Key'] = "(?i)linkedin(.{0,20})?[0-9a-z]{16}"
re_dict['GitHub_Access_Token'] = "[a-zA-Z0-9_-]*:[a-zA-Z0-9_-]+@github\.com*"
re_dict['Stripe_Restricted_API_Token'] = "rk_live_[0-9a-zA-Z]{24}"
re_dict['Stripe_Standard_API_Token'] = "sk_live_[0-9a-zA-Z]{24}"
re_dict['Square_Access_Token'] = "sqOatp-[0-9A-Za-z\-_]{22}"
re_dict['Square_Application_Secret'] = "sandbox-?sq0csp-[0-9A-Za-z-_]{43}|sq0[a-z]{3}-[0-9A-Za-z-_]{22,43}"
re_dict['PayPal_Braintree_Access_Token'] = "access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"
re_dict['Amazon_MWS_Auth_Token'] = "amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
re_dict['Picatic_API_Key'] = "sk_[live|test]_[0-9a-z]{32}"
re_dict['Google_OAuth_Access_Key'] = "ya29\.[0-9A-Za-z\-_]+"
re_dict['Google_OAuth_ID'] = "[0-9(+-[0-9A-Za-z_]{32}.apps.googleusercontent.com"
re_dict['StackHAwk_API_Key'] = "hawk\.[0-9A-Za-z\-_]{20}\.[0-9A-Za-z\-_]{20}"
re_dict['NuGet_API_Key'] = "oy2[a-z0-9]{43}"
re_dict['SendGrid_Token'] = "SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z-_]{43}"
re_dict['AWS_Access_Key'] = "(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
re_dict['AWS_Secret_Key'] = "(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"
re_dict['Google_Cloud_Platform_API_Key'] = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
re_dict['ZoHo_Webhook_Token'] = "https://creator\.zoho\.com/api/[A-Za-z0-9/\-_\.]+\?authtoken=[A-Za-z0-9]+"
re_dict['Zapier_Webhook'] = "hooks\.zapier\.com/hooks/catch/[A-Za-z0-9]+/[A-Za-z0-9]+/"
re_dict['New_Relic_Admin_API_Key'] = "NRAA-[a-f0-9]{27}"
re_dict['New_Relic_Insights_Key'] = "NRI(?:I|Q)-[A-Za-z0-9\-_]{32}"
re_dict['New_Relic_REST_API_Key'] = "NRRA-[a-f0-9]{42}"
re_dict['Microsoft_Teams_Webhook'] = "https://outlook\.office\.com/webhook/[A-Za-z0-9\-@]+/IncomingWebhook/[A-Za-z0-9\-]+/[A-Za-z0-9\-]+"
re_dict['Google_FCM_Server_Key'] = "AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}"
re_dict['Google_Calendar_URI'] = "https://www\.google\.com/calendar/embed\?src=[A-Za-z0-9%@&;=\-_\./]+"
re_dict['Discord_Webhook'] = "https://discordapp\.com/api/webhooks/[0-9]+/[A-Za-z0-9-_]+"
re_dict['Cloudinary_Credentials'] = "cloudinary://[0-9]+:[A-Za-z0-9-_.]+@[A-Za-z0-9-_.]+"
re_dict['Bitly_Secret'] = "R_[0-9a-f]{32}"
re_dict['Amazon_SNS_Topic'] = "arn:aws:sns:[a-z0-9-]+:[0-9]+:[A-Za-z0-9-_]+"
re_dict['PyPI_Upload_Token'] = "pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,1000}"
re_dict['Shopify_Private_App_Token'] = "shppa_[a-fA-F0-9]{32}"
re_dict['Shopify_Custom_App_Token'] = "shpca_[a-fA-F0-9]{32}"
re_dict['Shopify_Access_Token'] = "shpat_[a-fA-F0-9]{32}"
re_dict['Shopify_Shared_Secret'] = "shpss_[a-fA-F0-9]{32}"
re_dict['Dynatrace_Token'] = "dt0[a-zA-Z]{1}[0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}"
re_dict['Twilio_API_Key'] = "(?i)twilio(.{0,20})?SK[0-9a-f]{32}"
re_dict['MongoDB_Cloud_Connection_String'] = "mongodb\+srv://(.*)"
re_dict['AWS_S3_URL'] = "[https://]*s3\.amazonaws.com[/]+.*|[a-zA-Z0-9_-]*\.s3\.am"
re_dict['Notion_Integration_Token'] = "(secret_)([a-zA-Z0-9]{43})"
re_dict['Secrets_Generic_1'] = "(pass|password|secret|key|token)[:=-][\w!?=!@#$%^&*<>{}]{5,32}"
re_dict['Mastercard_Num'] = "(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}$"
re_dict['Visa_Num'] = "\\b([4]\d{3}[\s]\d{4}[\s]\d{4}[\s]\d{4}|[4]\d{3}[-]\d{4}[-]\d{4}[-]\d{4}|[4]\d{3}[.]\d{4}[.]\d{4}[.]\d{4}|[4]\d{3}\d{4}\d{4}\d{4})\\b"
re_dict['American_Express_Num'] = "^3[47][0-9]{13}$"

re_string = ""
i = 0
total_keys = len(re_dict)
for k, v in re_dict.items():
    i = i + 1
    # new = re.escape(str(v))
    new = str(v).replace('/', '\/')
    if i < total_keys:
        re_string += f"(?P<{k}>{new})|"
    else:
        re_string += f"(?P<{k}>{new})"
all_regex_compiled = re.compile(re_string)


def getCurrentDomain():
    global CURRENT_DOMAIN
    try:
        CURRENT_DOMAIN=socket.getfqdn().split('.',1)[1]
        print("[+] Active Domain: "+CURRENT_DOMAIN)
    except:
        print("[!] Oops!")
        print(traceback.format_exc())
        sys.exit(1)

def getDC():
    global DC_ADDRESS
    try:
        DC_ADDRESS = socket.gethostbyname(CURRENT_DOMAIN)
        print("[+] Active DC: "+DC_ADDRESS)
    except:
        print("[!] Oops!")
        print(traceback.format_exc())
        sys.exit(1)

def getUsersNET():
    clr.FindAssembly("System.DirectoryServices.DirectorySearcher")
    from System.DirectoryServices import DirectorySearcher
    global USER_LIST
    USER_LIST = []
    print("\n[*] User Object List;")
    try:
        searcher = DirectorySearcher()
        searcher.Filter = "(objectCategory=user)"
        searcher.PropertiesToLoad.Add("name")
        data = searcher.FindAll()
        for item in data:
            for name in item.Properties['name']:
                USER_LIST.append(name)
                print(name)
    except:
        print("[!] Oops!")
        print(traceback.format_exc())
        sys.exit(1)

def getComputersNET():
    clr.FindAssembly("System.DirectoryServices.DirectorySearcher")
    from System.DirectoryServices import DirectorySearcher
    COMPUTER_LIST = []
    print("\n[*] Gathering Computer Objects..")
    try:
        searcher = DirectorySearcher()
        searcher.Filter = "(objectCategory=computer)"
        searcher.PropertiesToLoad.Add("name")
        data = searcher.FindAll()
        with open("DOMAIN_COMPUTER_LIST.txt", mode="w") as f:
            for item in data:
                for name in item.Properties['name']:
                    COMPUTER_LIST.append(name)
                    f.write(name+"\n")
                    #print(name)
        print(f"[*] Discovered: {len(COMPUTER_LIST)} Computer Accounts")
        return COMPUTER_LIST
    except:
        print("[!] Oops!")
        print(traceback.format_exc())
        sys.exit(1)


def getShares(target, current, total):
    SHARE_LIST = []
    #getComputersNET()
    #for target in COMPUTER_LIST:
    print(f"[+] ({current}/{total}) Scanning : "+target)
    #ip = socket.gethostbyname(str(target))
    #print(target+" : "+ip)
    try:
        shares, _, _ = win32net.NetShareEnum(target, 0)  # 0 is Names, 1 is Names/Types/Comments, 2 is Names/Types/Permissions/Password/NumberofConnections, 502 is Blah, 503 is Blah
        for share in shares:
            for key in share:
                value = target+"\\\\"+share[key]
                #SHARE_LIST.append(value)
                #print(value)
                checkShare(value)
    except e:
        if e == "pywintypes.error: (53, 'NetShareEnum', 'The network path was not found.')":
            print("[!] Failed to Resolve Or Lacking Privileges: " + target)
        else:
            print(traceback.format_exc())

def checkShare(path):
    global READABLE_SHARES
    try:
        path = path.replace("\\\\", "\\")
        path = "\\\\"+path
        print(f"[+] Checking: {path}")
        name = str(platform.node())
        if os.access(path, os.R_OK) and not name.lower() in path.lower(): #This works for checking read access. (Skipping Local Host)
            READABLE_SHARES.append(path)
        #if os.access(path, os.W_OK): #This returns ok even when we don't have write access to the base directory.
        #    print("WRITE OK")
    except:
        print(f"[!] Error Checking Share: {path}")

def processShares(READABLE_SHARES):
    global INTERESTING_FILES
    global INTERESTING_MATCHES
    global FILE_MATCH_COUNT
    FILE_MATCH_COUNT = {}
    INTERESTING_FILES = []
    INTERESTING_MATCHES = {}
    with open("READABLE_SHARES.txt", mode='w') as f:
        for share in READABLE_SHARES:
            f.write(share+"\n")
    with ThreadPoolExecutor(MAX_THREADS) as executor:
        _ = [executor.submit(crawlShare, i) for i in READABLE_SHARES]
    if args.regex == True:
        print("[*] Regex Scanning Interesting Files")
        with ThreadPoolExecutor(MAX_THREADS) as executor:
            _ = [executor.submit(scanInterestingFile, i) for i in INTERESTING_FILES]

def scanInterestingFile(file):
    global INTERESTING_MATCHES
    global FILE_MATCH_COUNT
    try:
        print(f"[+] Scanning: {file}")
        file_size = os.path.getsize(file)
        file_size_mb = file_size/1024/1024
        if file_size_mb > 100:
            print(f"[!] File Size > 100 MB, Skipping: {file}")
        else:
            with open(file, mode='r', encoding='utf-8', errors='replace') as f:
                file_data = f.read()
                #matches = re.findall(all_regex_compiled, file_data)
                #for m in matches:
                #    print(m)
                #if len(matches) != 0:
                    #for match in matches:
                for match in all_regex_compiled.finditer(file_data):
                    #print(match)
                    for name, value in match.groupdict().items():
                        if file+":"+name not in FILE_MATCH_COUNT:
                            FILE_MATCH_COUNT[file + ":" + name] = 0
                        if value is not None:
                            FILE_MATCH_COUNT[file+":"+name] += 1
                            print(f"[*] Found Matches for Patterns: {name}, {file}")

                        #print(f"[*] Found Matches for Pattern[s]: {name}, {file}")
                    #INTERESTING_MATCHES[file] = names_used
    except:
        print(traceback.format_exc())


def crawlShare(SHARE):
    global INTERESTING_FILES
    print(f"[+] Starting File Scan for: {SHARE}")
    interesting_extensions = ['.csv','.docx', '.xlsx', #Productivity Extensions
                              '.pem', '.p8','.cer','.der','.spc','.p7a','.p7b','.p7c','.pfx','.p12'] #Private Key Material

    # File Names are searched for
    interesting_names = 'ssn|password|password|passes|credentials|socials|secret|sensitive|pass|token|api|key'
    i_compiled = re.compile(interesting_names)
    interesting_full_name = ['web.config']
    for subdir, dirs, files in os.walk(SHARE):
        for file in files:
            full_path = os.path.join(subdir, file)
            name, extension = os.path.splitext(file)
            fullname = name+extension
            if re.search(i_compiled, full_path) and not full_path in INTERESTING_FILES:
                INTERESTING_FILES.append(full_path)
                print("[*] Interesting File: " + full_path)
            if ((extension in interesting_extensions) or (name.lower() in interesting_names) or (fullname in interesting_full_name)) and not (full_path in INTERESTING_FILES):
                INTERESTING_FILES.append(full_path)
                print("[*] Interesting File: "+full_path)


def main():
    global READABLE_SHARES
    getCurrentDomain()  #Not
    getDC()
    if args.users == True:
        getUsersNET()
    else:
        READABLE_SHARES = []
        if args.sharpshares is None:
            COMPUTER_LIST = getComputersNET()
        else:
            COMPUTER_LIST = []
            with open(args.sharpshares[0]) as f:
                for line in f:
                    if line.startswith('[r]') or line.startswith('[w]'):
                        line = line.replace('[r] ','')
                        line = line.replace('[w] ','')
                        COMPUTER_LIST.append(line.strip())
        COUNT = 0
        with ThreadPoolExecutor(MAX_THREADS) as executor:
            for i in COMPUTER_LIST:
                COUNT = COUNT + 1
                _ = executor.submit(getShares, i, COUNT, len(COMPUTER_LIST))
        if args.files == True:
            processShares(READABLE_SHARES)


main()