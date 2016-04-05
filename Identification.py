__author__ = 'durga'

import csv
import getpass
import netifaces

global userdict
username = getpass.getuser()

def buildcsv():
    with open("userProfile.csv",'a') as csvfd:
        fieldnames = ['Name','MACaddress','Category']
        csvwriteobj = csv.DictWriter(csvfd,fieldnames=fieldnames)
        csvwriteobj.writeheader()

def checkProfile(username):
    '''
    check username against the userprofile.csv to determine the user identity
    :param username:
    :return:
    '''
    privilege = 'high'
    with open("userProfile.csv",'r+') as csvfd:
        userdict = csv.DictReader(csvfd)
        for line in userdict:
            #print line
            if line["Name"] == username and line['Category'] == 'U': # if username in profile file
                privilege = 'low'
            elif line["Name"] == username and line['Category'] == 'Y': # young
                privilege = 'vlow'
                return privilege
    return privilege

def updateProfile():
    '''
    update the userprofile.csv with username and corresponding mac addresses
    :return: updating the csv file
    '''
    usr = username
    macaddrs = macAddresses()
    print usr,macaddrs
    category =''
    while category =='':
        category = str(raw_input("Enter Catergory(under18(U)/over18(A)):" ))
        if category not in ['U','A','Y']: # to verify correct cateogry is entered
            category = ''
    fieldnames = ['Name','MACaddress','Category']
    with open('userProfile.csv','a') as csvfd:
        csvwriteobj = csv.DictWriter(csvfd,fieldnames=fieldnames)
        for macaddr in macaddrs:
            csvwriteobj.writerow({'Name':usr,
                                  'MACaddress':macaddr,
                                  'Category':category})

def macAddresses():
    '''
    return all the mac addresses of the interfaces
    :return: list of all the mac address - both physical and virtual
    '''
    interfaces = netifaces.interfaces()
    print interfaces
    macaddrs=[]
    for intf in interfaces:
        try:
            macaddrs.append(netifaces.ifaddresses(intf)[netifaces.AF_LINK][0]['addr'])
        except KeyError:
            pass
    return macaddrs


#buildcsv()
#updateProfile()
#print checkProfile('anish')

