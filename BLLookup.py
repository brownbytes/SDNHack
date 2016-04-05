__author__ = 'Durga'
'''
the below code looks up the existing list of blacklisted domains
the code implements binary search algorithm to match a domain
input : domain name
returns : blacklist or non-blacklist
'''
import os
import re

file1 = os.path.join('astrology','domains')
file2 = 'YwhiteL'
def importBL(file1):
    '''
    :param file: original blacklisttext file
    :return: list of all the domain names in file stripped off .com/n
    '''
    with open(file1,'r') as fd:
        alldomains = fd.readlines()
     
    for i in range(len(alldomains)):
        alldomains[i] = re.sub(r'\..',"",alldomains[i],0) # removing domain
        alldomains[i] = alldomains[i].rstrip() #removing newline char
    return alldomains

def importYWL(file2): # only few websites need to be accessed by young kids.
    with open(file2,'r') as fd:
        allydomains = fd.readlines()
    for i in range(len(allydomains)):
        allydomains[i] = allydomains[i].rstrip()
        
    return allydomains

def findInlist(domain):
    '''
    :param alldomains: list of all blaclisted domains
    :param domain: domain to query for
    :return:blacklist , whitelist
    '''
    print domain
    alldomains = importBL(file1)
    allydomains = importYWL(file2)
    for i in range(len(alldomains)):
        if domain in alldomains[i]:
            return 'blacklist'
    for j in range(len(allydomains)):
    	if domain in allydomains[j]:
            return 'Ywhitelist'
    else:
        return 'whitelist'

#print findInlist('asiaflashom')
#print findInlist('youtube')
#print findInlist('astro.qc.ca')
