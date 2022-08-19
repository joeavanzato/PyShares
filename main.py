# Requires pythonnet, Python <=3.8, .NET Framework, pywin32
# pyinstaller --hidden-import=pythonnet --onefile .\pyshares.py
# "C:\Program Files\Python38\Scripts\pyinstaller.exe" --hidden-import=pythonnet --onefile PyShares.py
import argparse, socket, traceback, sys, clr, win32net, os, re, glob
from concurrent.futures import ThreadPoolExecutor
clr.FindAssembly("System.DirectoryServices.DirectorySearcher")
from System.DirectoryServices import DirectorySearcher

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
MAX_THREADS = 10

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
        if os.access(path, os.R_OK) and 'pyramid-dc' in path.lower(): #This works for checking read access. (Specifying dc for testing only)
            READABLE_SHARES.append(path)
        #if os.access(path, os.W_OK): #This returns ok even when we don't have write access to the base directory.
        #    print("WRITE OK")
    except:
        print(f"[!] Error Checking Share: {path}")

def processShares(READABLE_SHARES):
    global INTERESTING_FILES
    global INTERESTING_MATCHES
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
            _ = [executor.submit(crawlInterestingFiles, i) for i in INTERESTING_FILES]

def crawlInterestingFiles(file):
    global INTERESTING_MATCHES
    re_dict = {}
    re_dict["SSN"] = '\d{3}-\d{2}-\d{4}'
    re_dict["SSN_Proximity"] = '(SSN|ssn)(\w+\W+){1,200}?(\d{9})'
    print(f"[+] Scanning: {file}")
    file_size = os.path.getsize(file)
    file_size_mb = file_size/1024/1024
    if file_size_mb > 100:
        print(f"[!] File Size > 100 MB, Skipping: {file}")
    else:
        with open(file, mode='r', encoding='utf-8') as f:
            file_data = f.read()
        for k,v in re_dict.items():
            matches = re.findall(v, file_data)
            #for m in matches:
            #    print(m)
            if len(matches) != 0:
                print(f"[*] Found Matches for Pattern: {k}, {file}")
                INTERESTING_MATCHES[file] = k


def crawlShare(SHARE):
    global INTERESTING_FILES
    print(f"[+] Starting File Scan for: {SHARE}")
    interesting_extensions = ['.csv','.docx', '.xlsx']
    interesting_names = ['ssn', 'password','password','passes','keys','credentials','socials','secret','sensitive']
    interesting_full_name = ['web.config']
    for subdir, dirs, files in os.walk(SHARE):
        for file in files:
            full_path = os.path.join(subdir, file)
            name, extension = os.path.splitext(file)
            for i in interesting_names:
                i_compiled = re.compile(i)
                if re.search(i_compiled, name) and not full_path in INTERESTING_FILES:
                    INTERESTING_FILES.append(full_path)
                    print("[*] Interesting File: " + full_path)
                    break
            fullname = name+extension
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