__author__ = 'vijayadurga'

from pox.lib import *
from pox.core import core
import pox.lib.packet.dns as dns
from pox.lib.packet.ethernet import ethernet,ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpid_to_str,str_to_dpid
from pox.lib.addresses import EthAddr,IPAddr,IP_ANY,IP_BROADCAST

import BLLookup
import Identification
import time

log = core.getLogger()

ethertypes = ['IP_TYPE', 'ARP_TYPE']
INTERNET_PORT = 3

def launch():
    core.registerNew(ParentControl)
    log.debug("new connection detected")

class ParentControl(object):

    def __init__(self):
        '''
        adds the current component as listener to core.openflow
        :return:
        '''
        core.openflow.addListeners(self)
        self.switch_ports = {} # stores switch and correspondign port information
        self.arptable = {} # stroes ip address and port on switch
        self.macaddrtable = {} # stores mac address and port on switch
        self.dnsqueries={} # stores stats for DNS queries
        self.c=0 # count for blacklisted
        

    def _handle_ConnectionUp(self,event):
        '''
        handles initial connection establishment
        :return:
        '''
        self.connection = event.connection

        self.ofp = event.ofp
        log.debug("New Connection established to switch %s",dpid_to_str(event.dpid))
        _ports = []
        for port in self.ofp.ports:
            _ports.append((port.port_no,port.hw_addr))
        self.switch_ports[event.dpid]=_ports
        self.installDNSflow(event)

    def _handle_PacketIn(self,event):
        '''
        handles incoming packets
        :param event:
        :return:
        '''
        self.processPacketIn(event)

    def processPacketIn(self,event):
        '''
        process packets
        :param event:
        :return:
        '''
        parsedpkt = event.parsed
        inport = event.port
        srcdpid = event.dpid
        self.event = event

        if parsedpkt.type == parsedpkt.ARP_TYPE: # handling ARP packets
            arppkt = parsedpkt.payload
            self.buildMACTable(parsedpkt.payload,inport)
            self.processARP(arppkt)

        elif parsedpkt.type == parsedpkt.IP_TYPE: # handling IP packets
            ippkt = parsedpkt.payload
            if ippkt.protocol == ipv4.UDP_PROTOCOL: # if the packet is DNS packet
                names=[]
                #print ippkt.payload.srcport
                if ippkt.payload.srcport == 53: #DNS responses
                    # monitoring
                    dnspkt = ippkt.payload.payload # verifying the dns query responses
                    #print str(dnspkt)
                    answers = dnspkt.answers

                    for answer in answers:
                        if answer.qclass !=1: #
                            return
                        if answer.qtype in [dns.rr.CNAME_TYPE,dns.rr.A_TYPE]:
                            name = answer.name
                            doname=name.split('.')[1]

                    domaintype = self.DNSverify(doname)
                    try:
                    	self.c = self.dnsqueries[doname]
                    	self.c += 1
                    	self.dnsqueries[doname]=self.c
                    except KeyError:
                        self.dnsqueries[doname]=1
                    print "statistics till now"
                    print "-------------------------"
                    for doname in self.dnsqueries:
                        print doname , self.dnsqueries[doname]
               
                    if domaintype == ('blacklist','low'): #blocking blacklisted websites for under18
                        print "denying the packets for blacklisted website and low privilege(under18) user :" + str(Identification.username)
                        self.dropPacket()
                    elif domaintype == ('whitelist','low'): #allowing whitelisted websites for under18
                        print "allowing the packets for whitelisted  website and low privilege(under18) user :" + str(Identification.username)
                        
                        #self.sendPacket(event,self.macaddrtable[self.arptable[ippkt.dstip]])
                        self.PacketOut(event,self.macaddrtable[self.arptable[ippkt.dstip]])
                    elif domaintype[1] == 'high': #allowing all wesbites for over18
                        print "allowing the packets for high privilege(over18) users : " + str(Identification.username)
                        #self.dnsqueries[doname]= self.c2+1
                        #self.sendPacket(event,self.macaddrtable[self.arptable[ippkt.dstip]]) # this needs to be updated
                        self.PacketOut(event,self.macaddrtable[self.arptable[ippkt.dstip]])
                        
                    elif domaintype == ('Ywhitelist','vlow'):
                        self.PacketOut(event,self.macaddrtable[self.arptable[ippkt.dstip]])
                        print "allowing packets for vlow privilege users to young whitelisted web"
                        
                    elif domaintype == ('Ywhitelist','low'):
                        self.PacketOut(event,self.macaddrtable[self.arptable[ippkt.dstip]])
                        print "allowing packets for low privilege users to young whitelisted websites"
                        
                    if self.checkTime() == 'Drop':
                        if domaintype[1]  == 'high': # if time is over 8pm, but over18 is using comp , dont drop
                            #self.sendPacket(event,self.macaddrtable[self.arptable[ippkt.dstip]])
                            self.PacketOut(event,self.macaddrtable[self.arptable[ippkt.dstip]])
                            
                        elif domaintype[1]  == 'low': # if lower privilege user is using the computer, drop the packet
                            self.dropPacket()
                            print " beyond bedtime..."
                          
                else:

                    outport = self.macaddrtable[self.arptable[ippkt.dstip]]
                    self.sendPacket(event,outport)

            else: # IP payloads like ICMP or other packets, if local forward to respective port, else forward to internet port
                if self.matchIP(ippkt.srcip,ippkt.dstip):
                    outport = self.macaddrtable[self.arptable[ippkt.dstip]]
                else :
                    outport = 2 #INTERNET_PORT
                self.sendPacket(event,outport)

        else:
            try:
                outport = self.macaddrtable[parsedpkt.dst]
                self.sendPacket(event,outport)
            except KeyError:
                self.floodPacket(self.event)


    #### building  MAC address table####
    def buildMACTable(self,arppkt,port):
        '''builds MACaddress table for the switch and ARP table'''
        self.macaddrtable[arppkt.hwsrc]= port
        self.arptable[arppkt.protosrc] = arppkt.hwsrc

    def processARP(self,arppkt):
        if arppkt.hwdst in self.macaddrtable: # if destination macaddr in macaddrtable return port
            self.sendPacket(self.event,self.macaddrtable[arppkt.hwdst])
        else:
            self.floodPacket(self.event)

    #### parental control using DNS ####
    def identifyUser(self):
        '''
        identifies the logged in user based on the packets and return privilege level
        :return:
        '''
        return Identification.checkProfile(Identification.username)

    def DNSverify(self,name):
        '''
        verifies the DNS packet name field against the BLLookup blacklist
        this allows blacklisting or whitelisting the packets
        :return:
        '''
        domaincat = BLLookup.findInlist(name)
        print domaincat
        priv = self.identifyUser() # identify user
        return (domaincat,priv)


    def sendPacket(self,event,outport):
        '''
        install flow table entries to send the packet in a specific port
        the port can be boardcasts or a unicast
        :return:
        '''
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(event.parsed,event.port)
        msg.actions.append(of.ofp_action_output(port=outport))
        msg.data = event.ofp
        core.openflow.sendToDPID(event.dpid,msg)

    def PacketOut(self,event,outport):
        msg = of.ofp_packet_out(in_port=of.OFPP_CONTROLLER)
        msg.actions.append(of.ofp_action_output(port=outport))
        msg.data = event.parsed.pack()
        core.openflow.sendToDPID(event.dpid,msg)

    def dropPacket(self):
        '''
        drop the blacklisted packets
        :return:
        '''
        pass

    def floodPacket(self,event):
        for each_pr in self.switch_ports[event.dpid]:
            msg = of.ofp_packet_out(in_port=of.OFPP_CONTROLLER)
            msg.data = event.parsed.pack()
            if each_pr[0] != event.port:
                msg.actions.append(of.ofp_action_output(port=each_pr[0]))
                event.connection.send(msg)

    def installDNSflow(self,event):

        msg = of.ofp_flow_mod()
        msg.priority = 1
        msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE,nw_proto = ipv4.UDP_PROTOCOL,tp_src=53) # dns packet
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        event.connection.send(msg)

    def matchIP(self,ip1,ip2):
        """
        to match if two l3 devices connected to a OF switch, belong to same network .
        """
        subnetmask =  '255.255.255.0'
        sl = subnetmask.split('.')

        ip1 = str(ip1).split('.')
        ip2 = str(ip2).split('.')
        flag = False
        #print "** matching ip1 ,ip2" + str(ip1)+str(ip2)
        for i in range(3): # first 3 octets for comparision
            #print "***** subnet"+str(int(sl[i])-int(ip1[i]))+str(int(sl[i])-int(ip2[i]))
            if int(sl[i])-int(ip1[i]) == int(sl[i])-int(ip2[i]):
                flag = True
                continue
            else:
                flag = False
                break
        return flag

####### time module #####

    def checkTime(self):
        ''' no screentime beyond 8 pm'''
        if time.localtime().tm_hour >= 20:
            return "Drop"
        else:
            return "DontDrop"


