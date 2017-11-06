import paramiko
import threading
import os.path
import subprocess
import time
import re

import sys


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
        if check2:
            print('\n* All devices are reachable. Waiting for username/password file...\n')
            break

        elif check2:
            print("* Please re-check IP address list or device.\n")
            ip_validity()
            break


# Checking user file validity
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


# Checking command file validity
def cmd_is_valid():
    global cmd_file

    while True:

        cmd_file = input("# Enter command file name and extension: ")


        # Changing output messages
        if os.path.isfile(cmd_file) == True:
            print("\n* Sending command(s) to device(s)...\n")
            break

        else:
            print("\n* File %s does not exist! Please check and try again!\n" % cmd_file)
            continue



try:

    ip_validity()

except KeyboardInterrupt:
    print("\n\n* Program aborted by user. Exiting...\n")
    sys.exit()


try:

    user_is_valid()

except KeyboardInterrupt:
    print("\n\n* Program aborted by user. Exiting...\n")
    sys.exit()


try:

    cmd_is_valid()

except KeyboardInterrupt:
    print("\n\n* Program aborted by user. Exiting...\n")
    sys.exit()

#########################################################################################
# Open SSHv2 connection to devices
def open_ssh_conn(ip):
    # Change exception message
    try:
        # Define SSH parameters
        selected_user_file = open(user_file, 'r')

        selected_user_file.seek(0)

        username, password= selected_user_file.readlines()[0].split(',')
        password=password.strip('\n')

        #print(username,password)

        # Logging into device
        session = paramiko.SSHClient()

        session.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the device using username and password
        session.connect(ip, username=username, password=password)

        # Start an interactive shell session on the router
        connection = session.invoke_shell()

        # Setting terminal length for entire output - disable pagination
        connection.send("terminal length 0\n")
        time.sleep(1)

        # Entering global config mode
        connection.send("\n")
        connection.send("configure terminal\n")
        time.sleep(1)

        # Open user selected file for reading
        selected_cmd_file = open(cmd_file, 'r')

        # Starting from the beginning of the file
        selected_cmd_file.seek(0)

        for each_line in selected_cmd_file.readlines():
            connection.send(each_line + '\n')
            time.sleep(2)

        selected_user_file.close()

        selected_cmd_file.close()

        # Checking command output for IOS syntax errors
        router_output = connection.recv(65535)

        if re.search(" Invalid input detected at", router_output.decode('utf-8')):
            print("* There was at least one IOS syntax error on device %s" % ip)

        else:
            print("\nDONE for device %s" % ip)

        # Closing the connection
        session.close()

    except paramiko.AuthenticationException:
        print("* Invalid username or password. \n* Please check the username/password file or the device configuration!")
        print("* Closing program...\n")



# Creating threads
def create_threads():
    threads = []
    for ip in ip_list:
        th = threading.Thread(target=open_ssh_conn, args=(ip,))  # args is a tuple with a single element
        th.start()
        threads.append(th)

    for th in threads:
        th.join()


# Calling threads creation function
create_threads()
