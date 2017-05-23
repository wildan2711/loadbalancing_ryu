# Copyright 2017 Wildan Maulana Syahidillah

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, arp, ipv6, icmp
from ryu.lib.packet import ether_types, in_proto
from ryu.lib import mac, hub
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
from ryu.ofproto import ether, inet
from thread import start_new_thread
import time
import random

UINT32_MAX = 0xffffffff

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.datapath_list = {} # maps dpid to switch object
        self.arp_table = {} # maps IP to MAC
        self.controller_mac = 'dd:dd:dd:dd:dd:dd' # decoy MAC
        self.controller_ip = '10.0.0.100' # decoy IP
        self.server_ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3'] # server IPs to monitor
        self.server_switch = 1 # switch dpid with connections to the servers
        self.latency = {} # maps IP to the latency value
        self.virtual_ip = '10.0.0.20'
        self.virtual_mac = 'df:d8:e9:21:34:f2'
        self.server_index = 0
        self.arp_table = {}
        self.rewrite_ip_header = True
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
    
    """
        Initializes ARP entries for the controller decoy addresses
    """
    def request_arp(self, datapath, ip):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        ARP_Request = packet.Packet()

        ARP_Request.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=mac.BROADCAST_STR,
            src=self.controller_mac))
        ARP_Request.add_protocol(arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=self.controller_mac,
            src_ip=self.controller_ip,
            dst_mac=mac.BROADCAST_STR,
            dst_ip=ip))

        ARP_Request.serialize()

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions, data=ARP_Request.data)
        datapath.send_msg(out)
    
    """
        This is needed to resolve the decoy controller ARP entries
        for ARP poisoning prevention systems, by replying ARP 
        requests sent to the controller.
    """
    def reply_arp(self, datapath, eth_dst, eth_src, ip_dst, ip_src, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(in_port)]
        ARP_Reply = packet.Packet()

        ARP_Reply.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=eth_dst,
            src=eth_src))
        ARP_Reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=eth_src,
            src_ip=ip_src,
            dst_mac=eth_dst,
            dst_ip=ip_dst))

        ARP_Reply.serialize()

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions, data=ARP_Reply.data)
        datapath.send_msg(out)

    def formulate_arp_reply(self, dst_mac, dst_ip):
        if self.virtual_ip == None:
            return

        src_mac = self.virtual_mac
        src_ip = self.virtual_ip
        arp_opcode = arp.ARP_REPLY
        arp_target_mac = dst_mac

        ether_proto = ether.ETH_TYPE_ARP
        hwtype = 1
        arp_proto = ether.ETH_TYPE_IP
        hlen = 6
        plen = 4

        pkt = packet.Packet()
        e = ethernet.ethernet(dst_mac, src_mac, ether_proto)
        a = arp.arp(hwtype, arp_proto, hlen, plen, arp_opcode,
                    src_mac, src_ip, arp_target_mac, dst_ip)
        pkt.add_protocol(e)
        pkt.add_protocol(a)
        pkt.serialize()

        return pkt

    def load_balancing_handler(self, ev, eth, iphdr, in_port):
        
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        # Round robin selection of servers
        total_servers = len(self.server_ips)
        
        index = self.server_index % total_servers
        selected_server_ip = self.server_ips[index]
        selected_server_mac = self.arp_table[selected_server_ip]
        selected_server_outport = self.mac_to_port[selected_server_mac]
        self.server_index += 1
        print("Selected server %s" % selected_server_ip)

        ########### Setup route to server
        match = ofp_parser.OFPMatch(in_port=in_port,
                eth_type=eth.ethertype,  eth_src=eth.src,    eth_dst=eth.dst,
                ip_proto=iphdr.proto,    ipv4_src=iphdr.src, ipv4_dst=iphdr.dst)

        if self.rewrite_ip_header:
            actions = [ofp_parser.OFPActionSetField(eth_dst=selected_server_mac),
                       ofp_parser.OFPActionSetField(ipv4_dst=selected_server_ip),
                       ofp_parser.OFPActionOutput(selected_server_outport) ]
        else:
            actions = [ofp_parser.OFPActionSetField(eth_dst=selected_server_mac),
                       ofp_parser.OFPActionOutput(selected_server_outport) ]

        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        cookie = random.randint(0, 0xffffffffffffffff)

        mod = ofp_parser.OFPFlowMod(datapath=datapath, match=match, idle_timeout=10,
                instructions=inst, buffer_id = msg.buffer_id, cookie=cookie)
        datapath.send_msg(mod)

        ########### Setup reverse route from server
        match = ofp_parser.OFPMatch(in_port=selected_server_outport,
                eth_type=eth.ethertype,  eth_src=selected_server_mac, eth_dst=eth.src,
                ip_proto=iphdr.proto,    ipv4_src=selected_server_ip, ipv4_dst=iphdr.src)

        if self.rewrite_ip_header:
            actions = ([ofp_parser.OFPActionSetField(eth_src=self.virtual_mac),
                       ofp_parser.OFPActionSetField(ipv4_src=self.virtual_ip),
                       ofp_parser.OFPActionOutput(in_port) ])
        else:
            actions = ([ofp_parser.OFPActionSetField(eth_src=self.virtual_mac),
                       ofp_parser.OFPActionOutput(in_port) ])

        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        cookie = random.randint(0, 0xffffffffffffffff)

        mod = ofp_parser.OFPFlowMod(datapath=datapath, match=match, idle_timeout=10,
                instructions=inst, cookie=cookie)
        datapath.send_msg(mod)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether.ETH_TYPE_ARP:
            arp_hdr = pkt.get_protocols(arp.arp)[0]

            if arp_hdr.dst_ip == self.virtual_ip and arp_hdr.opcode == arp.ARP_REQUEST:

                reply_pkt = self.formulate_arp_reply(arp_hdr.src_mac,
                        arp_hdr.src_ip)

                actions = [ofp_parser.OFPActionOutput(in_port)]
                out = ofp_parser.OFPPacketOut(datapath=datapath,
                           in_port=ofp.OFPP_ANY, data=reply_pkt.data,
                           actions=actions, buffer_id = UINT32_MAX)
                datapath.send_msg(out)
            elif arp_hdr.dst_mac == self.controller_mac and arp_hdr.opcode == arp.ARP_REPLY:
                self.mac_to_port[arp_hdr.src_mac] = in_port
                self.arp_table[arp_hdr.src_ip] = arp_hdr.src_mac
                self.arp_table[arp_hdr.dst_ip] = arp_hdr.dst_mac
                match = ofp_parser.OFPMatch(eth_dst=arp_hdr.src_mac)
                actions = [ofp_parser.OFPActionOutput(in_port)]
                match_ip = ofp_parser.OFPMatch(
                    eth_type=0x0800, 
                    ipv4_dst=arp_hdr.src_ip
                )
                match_arp = ofp_parser.OFPMatch(
                    eth_type=0x0806, 
                    arp_tpa=arp_hdr.src_ip
                )
                self.add_flow(datapath, 1, match_ip, actions)
                self.add_flow(datapath, 1, match_arp, actions)
            elif arp_hdr.dst_mac == '00:00:00:00:00:00' and arp_hdr.opcode == 1:
                actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
                data = None
                if msg.buffer_id == ofp.OFP_NO_BUFFER:
                    data = msg.data

                out = ofp_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                    actions=actions, data=data)
                datapath.send_msg(out)

            return

        # Only handle IPv4 traffic going forward
        elif eth.ethertype != ether.ETH_TYPE_IP:
            return
        
        iphdr = pkt.get_protocols(ipv4.ipv4)[0]

        # Handle load balancing
        if iphdr.dst == self.virtual_ip:
            self.load_balancing_handler(ev, eth, iphdr, in_port)
            return

        # If we there are no servers with location known, then skip

        

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, event):
        switch = event.switch
        ofp_parser = switch.dp.ofproto_parser
        if switch.dp.id not in self.datapath_list:
            self.datapath_list[switch.dp.id] = switch
        if switch.dp.id == self.server_switch:
            for server in self.server_ips:
                self.request_arp(switch.dp, server)
            