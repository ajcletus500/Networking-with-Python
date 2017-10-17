#!/usr/bin/env python

import telnetlib
import threading
import os.path
import subprocess
import time
import sys


#Checking IP address validity
def ip_validity():
    check=False
    global ip_list

    while True:
        ip_file=input('Enter the file location with the extension: ')
        try:
            selected_file=open(ip_file, 'r')
            selected_file.seek(0)
            ip_list=selected_file.readlines()
            selected_file.close()
            ip_list=[a.strip('\n') for a in ip_list]
            print(ip_list)
        except IOError:
            print('{} does not exsist'.format(ip_file))


        print('a')
        #checking each IP Address
        for ip in ip_list:
            a=ip.split('.')
            #Checking for a valid IP Address
            if (len(a) == 4) and (1 <= int(a[0]) <= 223) and (int(a[0]) != 127) and (int(a[0]) != 169 or int(a[1]) != 254) and (0 <= int(a[1]) <= 255 and 0 <= int(a[2]) <= 255 and 0 <= int(a[3]) <= 255):
                check = True
                break
            else:
                print('The address is invalid, please renter it again: \n')
                check=False
                continue


        if check:
            break
        else:
            continue

    #Check for reachability

    print('Checking IP reachability')

    check2=False
    while True:
        for ip in ip_list:
            ping_reply=subprocess.call(['ping', '-c', '2', '-w', '2', '-q', '-n', ip])

            if ping_reply==0:
                check2=True
                continue
            elif ping_reply == 2:
                print("\n* No response from device %s." % ip)
                check2 = False
                break

            else:
                print("\n* Ping to the following device has FAILED:", ip)
                check2 = False
                break
        #print ('a')
        if check2==True:
            print('\n* All devices are reachable. Waiting for username/password file...\n')
            break

        elif check2==False:
            print("* Please re-check IP address list or device.\n")
            ip_validity()


#Checking the username password file validity
def user_is_valid():
    global user_file

    while True:

        user_file = input("# Enter user/pass file name and extension: ")

        # Changing output messages
        if os.path.isfile(user_file) == True:
            print("\n* Username/password file has been validated. Waiting for command file...\n")
            break

        else:
            print("\n* File %s does not exist! Please check and try again!\n" % user_file)
            continue


#Checking command file validity
def cmd_is_valid():
    global cmd_file
    
    while True:
        cmd_file = input("Enter command file name and extension: ")
        
        #Changing exception message
        if os.path.isfile(cmd_file) == True:
            print ("\nSending command(s) to device(s)...\n")
            break
        
        else:
            print ("\nFile %s does not exist! Please check and try again!\n" % cmd_file)
            continue

try:
    #Calling IP validity function
    ip_validity()
    
except KeyboardInterrupt:
    print( "\n\nProgram aborted by user. Exiting...\n")
    sys.exit()

try:
    # Calling user file validity function
    user_is_valid()

except KeyboardInterrupt:
    print("\n\n* Program aborted by user. Exiting...\n")
    sys.exit()

try:
    #Calling command file validity function
    cmd_is_valid()
    
except KeyboardInterrupt:
    print ("\n\nProgram aborted by user. Exiting...\n")
    sys.exit()


#Open telnet connection to devices
def open_telnet_conn(ip):
    #Change exception message
    try:
        #Define telnet parameters
        selected_user_file = open(user_file, 'r')

        selected_user_file.seek(0)

        username, password= selected_user_file.readlines()[0].split(',')
        password=password.strip('\n')

        #Telnet port (default is 23, anyway)
        port = 23
        
        connection_timeout = 5
        
        reading_timeout = 5
        
        #Logging into device
        connection = telnetlib.Telnet(ip, port, connection_timeout)
        
        #Waiting to be asked for an username
        router_output = connection.read_until("Username:", reading_timeout)

        connection.write(username + "\n")
        
        #Waiting to be asked for a password
        router_output = connection.read_until("Password:", reading_timeout)

        connection.write(password + "\n")
        time.sleep(1)	
        
        #Setting terminal length for the entire output - disabling pagination
        connection.write("terminal length 0\n")
        time.sleep(1)
        
        #Entering global config mode
        connection.write("\n")
        connection.write("configure terminal\n")
        time.sleep(1)
        
        selected_cmd_file = open(cmd_file, 'r')
            
        selected_cmd_file.seek(0)
        
        #Writing each line in the file to the device
        for each_line in selected_cmd_file.readlines():
            connection.write(each_line + '\n')
            time.sleep(1)
    
        #Closing the file
        selected_cmd_file.close()
        
        #router_output = connection.read_very_eager()
        #print router_output
        
        #Closing the connection
        connection.close()
        
    except IOError:
        print("Input parameter error! Please check username, password and file name.")

  
#Creating threads
def create_threads():
    threads = []
    for ip in ip_list:
        th = threading.Thread(target = open_telnet_conn, args = (ip,))
        th.start()
        threads.append(th)
        
    for th in threads:
        th.join()

#Calling threads creation function
create_threads()

