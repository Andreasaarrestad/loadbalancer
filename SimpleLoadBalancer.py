from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr

log = core.getLogger()
import time
import random
import pox.log.color

IDLE_TIMEOUT = 10
LOADBALANCER_MAC = EthAddr("00:00:00:00:00:FE")
ETHERNET_BROADCAST_ADDRESS = EthAddr("ff:ff:ff:ff:ff:ff") #Broadcast address

class SimpleLoadBalancer(object):

    def __init__(self, service_ip, server_ips=[]):
        core.openflow.addListeners(self)
        self.SERVERS = {}  # IPAddr(SERVER_IP)]={'server_mac':EthAddr(SERVER_MAC),'port': PORT_TO_SERVER}
        self.CLIENTS = {}
        self.LOADBALANCER_MAP = {}  # Mapping between clients and servers
        self.LOADBALANCER_IP = service_ip
        self.SERVER_IPS = server_ips
        self.ROBIN_COUNT = 0

    def _handle_ConnectionUp(self, event):
        self.connection = event.connection
        log.debug("FUNCTION: _handle_ConnectionUp")

        #Send ARP request to learn the MAC address of all the backend servers by going through all server IPs
        for server_ip in self.SERVER_IPS:
            self.send_arp_request(self.connection, server_ip)

        log.debug("Sent ARP Requests to all servers")

    def round_robin(self):
        log.debug("FUNCTION: round_robin")

        server = self.SERVER_IPS[self.ROBIN_COUNT]
        log.info("Round robin selected server number %s with ip address %s" % (self.ROBIN_COUNT + 1, server))

        # Logic to choose the next server
        self.ROBIN_COUNT = (self.ROBIN_COUNT + 1) % len(self.SERVER_IPS) #General case for any number of servers

        return server

    def update_lb_mapping(self, client_ip):
        log.debug("FUNCTION: update_lb_mapping")
        if client_ip in self.CLIENTS.keys():
            if client_ip not in self.LOADBALANCER_MAP.keys():
                selected_server = self.round_robin()
                self.LOADBALANCER_MAP[client_ip] = selected_server

    def send_arp_reply(self, packet, connection, outport):
        log.debug("FUNCTION: send_arp_reply")

        arp_rep = arp()
        arp_rep.hwtype = arp_rep.HW_TYPE_ETHERNET
        arp_rep.prototype = arp_rep.PROTO_TYPE_IP
        arp_rep.hwlen = 6
        arp_rep.protolen = arp_rep.protolen
        arp_rep.opcode = arp.REPLY
        arp_rep.hwdst = packet.src
        arp_rep.hwsrc = LOADBALANCER_MAC

        # Reverse the src, dest to have an answer
        arp_rep.protosrc = packet.payload.protodst
        arp_rep.protodst = packet.payload.protosrc

        eth = ethernet() #Creating ethernet frame
        eth.type = eth.ARP_TYPE
        eth.dst = packet.src
        eth.src = LOADBALANCER_MAC
        eth.set_payload(arp_rep)

        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT)) #Appending the output port which the packet should be forwarded to the openflow message
        msg.in_port = outport

        connection.send(msg)

    def send_arp_request(self, connection, ip):

        log.debug("FUNCTION: send_arp_request")

        arp_req = arp()
        arp_req.hwtype = arp_req.HW_TYPE_ETHERNET
        arp_req.prototype = arp_req.PROTO_TYPE_IP
        arp_req.hwlen = 6
        arp_req.protolen = arp_req.protolen
        arp_req.opcode = arp.REQUEST
        arp_req.protodst = ip
        arp_req.hwsrc = LOADBALANCER_MAC
        arp_req.hwdst = ETHERNET_BROADCAST_ADDRESS
        arp_req.protosrc = self.LOADBALANCER_IP

        eth = ethernet() #Creating ethernet frame
        eth.type = eth.ARP_TYPE
        eth.dst = ETHERNET_BROADCAST_ADDRESS
        eth.set_payload(arp_req)

        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_nw_addr(of.OFPAT_SET_NW_DST, ip))
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD)) #Appending the action to the message telling the switch to flood the package

        connection.send(msg)

    def install_flow_rule_client_to_server(self, event, connection, outport, client_ip, server_ip):
        log.debug("FUNCTION: install_flow_rule_client_to_server")
        self.install_flow_rule_server_to_client(connection, event.port, server_ip, client_ip)

        msg = of.ofp_flow_mod()
        msg.idle_timeout = IDLE_TIMEOUT
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_src = client_ip
        msg.match.nw_dst = self.LOADBALANCER_IP

        msg.actions.append(of.ofp_action_dl_addr.set_src(LOADBALANCER_MAC))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(self.SERVERS[server_ip].get('server_mac')))
        msg.actions.append(of.ofp_action_nw_addr.set_src(client_ip))
        msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        msg.actions.append(of.ofp_action_output(port=outport))

        self.connection.send(msg)
        log.info("Installed flow rule: %s -> %s" % (client_ip, server_ip))

    def install_flow_rule_server_to_client(self, connection, outport, server_ip, client_ip):
        log.debug("FUNCTION: install_flow_rule_server_to_client")

        msg = of.ofp_flow_mod()
        msg.idle_timeout = IDLE_TIMEOUT

        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_src = server_ip
        msg.match.nw_dst = client_ip

        msg.actions.append(of.ofp_action_dl_addr.set_src(LOADBALANCER_MAC))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(self.CLIENTS[client_ip].get('client_mac')))
        msg.actions.append(of.ofp_action_nw_addr.set_src(self.LOADBALANCER_IP))
        msg.actions.append(of.ofp_action_nw_addr.set_dst(client_ip))
        msg.actions.append(of.ofp_action_output(port=outport))

        self.connection.send(msg)
        log.info("Installed flow rule: %s -> %s" % (server_ip, client_ip))

    def _handle_PacketIn(self, event):
        log.debug("FUNCTION: _handle_PacketIn")
        packet = event.parsed
        connection = event.connection
        inport = event.port

        # Handle LLDP or Ipv6 packets
        if packet.type == packet.LLDP_TYPE or packet.type == packet.IPV6_TYPE:
            log.info("Received LLDP or IPv6 Packet...")

        # Handle ARP packets
        elif packet.type == packet.ARP_TYPE:
            log.debug("Received ARP Packet")
            response = packet.payload

            # Handle ARP reply
            if response.opcode == response.REPLY:
                log.debug("ARP REPLY Received")
                if response.protosrc not in self.SERVERS.keys():
                    # Adding the servers' MAC addresses and port numbers to the SERVERS dictionary if they're not
                    # there already
                    self.SERVERS[IPAddr(response.protosrc)] = {'server_mac': EthAddr(response.hwsrc), 'port': inport}

            # Handle ARP request
            elif response.opcode == response.REQUEST:
                log.debug("ARP REQUEST Received")
                if response.protosrc not in self.SERVERS.keys() and response.protosrc not in self.CLIENTS.keys():

                    # Indexing the client IP, mac and port number in a forwarding table
                    self.CLIENTS[response.protosrc] = {'client_mac': EthAddr(packet.payload.hwsrc), 'port': inport}

                if response.protosrc in self.CLIENTS.keys() and response.protodst == self.LOADBALANCER_IP:
                    log.info("Client %s sent ARP req to LB %s" % (response.protosrc, response.protodst))
                    self.send_arp_reply(packet, connection, inport)

                elif response.protosrc in self.SERVERS.keys() and response.protodst in self.CLIENTS.keys():
                    log.info("Server %s sent ARP req to client" % response.protosrc)
                    self.send_arp_reply(packet, connection, inport)

                else:
                    log.info("Invalid ARP request")

        # Handle IPv4 packets
        elif packet.type == packet.IP_TYPE:
            log.debug("Received IP Packet from %s" % packet.next.srcip)

            # Handle Requests from Clients to Servers

            # Install flow rule Client -> Server
            if (packet.next.dstip == self.LOADBALANCER_IP) and (packet.next.srcip not in self.SERVERS.keys()):

                self.update_lb_mapping(packet.next.srcip)
                client_ip = packet.payload.srcip
                server_ip = self.LOADBALANCER_MAP.get(packet.next.srcip)
                outport = self.SERVERS[server_ip].get('port')

                self.install_flow_rule_client_to_server(event, connection, outport, client_ip, server_ip)

                eth = ethernet() #Creating ethernet frame
                eth.type = eth.IP_TYPE
                eth.dst = self.SERVERS[server_ip].get('server_mac')
                eth.src = LOADBALANCER_MAC
                eth.set_payload(packet.next)

                # Send the first packet (which was sent to the controller from the switch)
                # to the chosen server, so there is no packetloss
                msg = of.ofp_packet_out()
                msg.data = eth.pack()
                msg.in_port = inport

                msg.actions.append(of.ofp_action_dl_addr.set_src(LOADBALANCER_MAC))
                msg.actions.append(of.ofp_action_dl_addr.set_dst(self.SERVERS[server_ip].get('server_mac')))
                msg.actions.append(of.ofp_action_nw_addr.set_src(client_ip))
                msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
                msg.actions.append(of.ofp_action_output(port=outport))

                connection.send(msg)

            # Handle traffic from Server to Client
            # Install flow rule Client <- Server
            elif packet.next.dstip in self.CLIENTS.keys():  # server to client
                log.info("Installing flow rule from Server -> Client")
                if packet.next.srcip in self.SERVERS.keys():
                    server_ip = packet.next.srcip

                    client_ip = self.LOADBALANCER_MAP.keys()[
                    list(self.LOADBALANCER_MAP.values()).index(packet.next.srcip)]
                    outport = self.CLIENTS[client_ip].get('port')
                    self.install_flow_rule_server_to_client(connection, outport, server_ip, client_ip)


                    eth = ethernet() #Creating ethernet frame
                    eth.type = eth.IP_TYPE
                    eth.dst = self.SERVERS[server_ip].get('server_mac')
                    eth.src = LOADBALANCER_MAC
                    eth.set_payload(packet.next)

                    # Send the first packet (which was sent to the controller from the switch)
                    # to the chosen server, so there is no packetloss
                    msg = of.ofp_packet_out()
                    msg.data = eth.pack()
                    msg.in_port = inport

                    msg.actions.append(of.ofp_action_dl_addr.set_src(LOADBALANCER_MAC))
                    msg.actions.append(of.ofp_action_dl_addr.set_dst(self.CLIENTS[client_ip].get('client_mac')))
                    msg.actions.append(of.ofp_action_nw_addr.set_src(self.LOADBALANCER_IP))
                    msg.actions.append(of.ofp_action_nw_addr.set_dst(client_ip))
                    msg.actions.append(of.ofp_action_output(port=outport))

                    self.connection.send(msg)

        else:
            log.info("Unknown Packet type: %s" % packet.type)
            return
        return


def launch(loadbalancer, servers):
    # Color-coding and pretty-printing the log output
    pox.log.color.launch()
    pox.log.launch(format="[@@@bold@@@level%(name)-23s@@@reset] " +
                          "@@@bold%(message)s@@@normal")
    log.info(
        "Loading Simple Load Balancer module:\n\n-----------------------------------CONFIG----------------------------------\n")
    server_ips = servers.replace(",", " ").split()
    server_ips = [IPAddr(x) for x in server_ips]
    loadbalancer_ip = IPAddr(loadbalancer)
    log.info("Loadbalancer IP: %s" % loadbalancer_ip)
    log.info(
        "Backend Server IPs: %s\n\n---------------------------------------------------------------------------\n\n" % ', '.join(
            str(ip) for ip in server_ips))
    core.registerNew(SimpleLoadBalancer, loadbalancer_ip, server_ips)
