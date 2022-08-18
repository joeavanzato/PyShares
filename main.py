# Requires pythonnet, Python <3.8, .NET Framework, pywin32
# pyinstaller --hidden-import=pythonnet --onefile .\pyshares.py
import argparse, socket, traceback, sys, clr, win32net
clr.FindAssembly("System.DirectoryServices.DirectorySearcher")
from System.DirectoryServices import DirectorySearcher

parser = argparse.ArgumentParser(
    usage='\n Share Sniffing in Python\n -l -- [Target Host/IP List]\n -u --users Dump out Domain Users, Skip Shares ')
parser.add_argument("-l", "--list",
                    help='Specify Target Host/IP List (Newline Separated List of Computers or IP Addresses)',
                    required=False, action='store_true')
parser.add_argument("-u", "--users",
                    help='Dump Domain Users',
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
print("Joe Avanzato @panscan")
print("github.com/joeavanzato\n")

def getCurrentDomain():
    global CURRENT_DOMAIN
    try:
        CURRENT_DOMAIN=socket.getfqdn().split('.',1)[1]
        print("Active Domain: "+CURRENT_DOMAIN)
    except:
        print("Oops!")
        print(traceback.format_exc())
        sys.exit(1)

def getDC():
    global DC_ADDRESS
    try:
        DC_ADDRESS = socket.gethostbyname(CURRENT_DOMAIN)
        print("Active DC: "+DC_ADDRESS)
    except:
        print("Oops!")
        print(traceback.format_exc())
        sys.exit(1)

def getUsersNET():
    global USER_LIST
    USER_LIST = []
    print("\nUser Object List;")
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
        print("Oops!")
        print(traceback.format_exc())
        sys.exit(1)

def getComputersNET():
    global COMPUTER_LIST
    COMPUTER_LIST = []
    print("\nComputer Object List;")
    try:
        searcher = DirectorySearcher()
        searcher.Filter = "(objectCategory=computer)"
        searcher.PropertiesToLoad.Add("name")
        data = searcher.FindAll()
        for item in data:
            for name in item.Properties['name']:
                COMPUTER_LIST.append(name)
                print(name)
    except:
        print("Oops!")
        print(traceback.format_exc())
        sys.exit(1)

def getShares():
    global SHARE_LIST
    SHARE_LIST = []
    getComputersNET()
    for target in COMPUTER_LIST:
        print("\nScanning : "+target)
        #ip = socket.gethostbyname(str(target))
        #print(target+" : "+ip)
        try:
            shares, _, _ = win32net.NetShareEnum(target, 0)  # 0 is Names, 1 is Names/Types/Comments, 2 is Names/Types/Permissions/Password/NumberofConnections, 502 is Blah, 503 is Blah
            for share in shares:
                for key in share:
                    value = target+"\\\\"+share[key]
                    SHARE_LIST.append(value)
                    print(value)
        except:
            print("Failed to Resolve Or Lacking Privileges: "+target)
def main():
    getCurrentDomain()  #Not
    getDC()
    if args.users == True:
        getUsersNET()
    else:
        getShares()


main()