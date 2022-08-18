# Requires pythonnet, Python <=3.8, .NET Framework, pywin32
# pyinstaller --hidden-import=pythonnet --onefile .\pyshares.py
# "C:\Program Files\Python38\Scripts\pyinstaller.exe" --hidden-import=pythonnet --onefile PyShares.py
import argparse, socket, traceback, sys, clr, win32net, os, re
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
    print("\n[*] Computer Object List;")
    try:
        searcher = DirectorySearcher()
        searcher.Filter = "(objectCategory=computer)"
        searcher.PropertiesToLoad.Add("name")
        data = searcher.FindAll()
        for item in data:
            for name in item.Properties['name']:
                COMPUTER_LIST.append(name)
                print(name)
        return COMPUTER_LIST
    except:
        print("[!] Oops!")
        print(traceback.format_exc())
        sys.exit(1)


def getShares(target):
    SHARE_LIST = []
    #getComputersNET()
    #for target in COMPUTER_LIST:
    print("\n[+] Scanning : "+target)
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
    except:
        print(traceback.format_exc())
        print("[!] Failed to Resolve Or Lacking Privileges: "+target)

def checkShare(path):
    global READABLE_SHARES
    try:
        path = "\\\\"+path
        print(f"[+] Checking: {path}")
        if os.access(path, os.R_OK): #This works for checking read access.
            READABLE_SHARES.append(path)
        #if os.access(path, os.W_OK): #This returns ok even when we don't have write access to the base directory.
        #    print("WRITE OK")
    except:
        print(f"[!] Error Checking Share: {path}")

def processShares(READABLE_SHARES):
    with open("READABLE_SHARES.txt", mode='w') as f:
        for share in READABLE_SHARES:
            f.write(share+"\n")
    with ThreadPoolExecutor() as executor:
        _ = [executor.submit(crawlShare, i) for i in READABLE_SHARES]

def crawlShare(SHARE):
    print(f"[+] Starting File Scan for: {SHARE}")
    interesting_extensions = ['csv','docx', 'xlsx']
    regex_patterns = []
    INTERESTING_FILE_NAMES = []
    FILES_CONTAIN_INTERESTING = []
    for subdir, dirs, files in os.walk(SHARE):
        for file in files:
            if (os.path.splitext(file)[-1] in interesting_extensions):
                INTERESTING_FILE_NAMES.append(os.path.join(subdir,file))
                print(os.path.join(subdir,file))


def main():
    global READABLE_SHARES
    getCurrentDomain()  #Not
    getDC()
    if args.users == True:
        getUsersNET()
    else:
        COMPUTER_LIST = getComputersNET()
        READABLE_SHARES = []
        with ThreadPoolExecutor() as executor:
            _ = [executor.submit(getShares, i) for i in COMPUTER_LIST]
        if args.files == True:
            processShares(READABLE_SHARES)


main()