import eventlet
import numpy
import time
import random
import multiprocessing as mp
import pcap
import dpkt
import socket
import binascii
import operator
import struct

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet as libpacket
from ryu.lib.packet import ethernet
from ryu.lib import hub
from ryu.lib import addrconv
from ryu.lib.mac import haddr_to_bin
from ryu.lib.mac import haddr_to_str


unparsed_q = mp.Queue()
parsed_q = eventlet.Queue()
if socket.gethostname() == 'lt-debian':
    monitor_port = 65534
    dev = 'br0'
elif socket.gethostname() == 'OVS-Switch':
    monitor_port = 65534
    dev = 'br0'
else:
    monitor_port = 34
    dev = 'eth1'

# Set detection mechanism to use.
mode = 6
outgoing_block_mode_v1_dict = {}
outgoing_block_mode_v2_dict = {}
datapath = None


def random_int():
    return int(''.join(str(random.choice(range(10))) for _ in range(10)))


def ipv4_text_to_int(ip_text):
    if ip_text == 0:
        return ip_text
    assert isinstance(ip_text, str)
    return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_text))[0]


class Sniffer(mp.Process):
    def __init__(self, q, dev_='eth1'):
        super(Sniffer, self).__init__()
        self.q = q
        self.dev = dev_
        print 'sniffer started'

    def run(self):
        p = pcap.pcapObject()
        # Get only the first 320 bits of the packet.
        p.open_live(self.dev, 320, 1, 0)

        def dump(pktlen, data, timestamp):
            self.q.put((pktlen, data, timestamp))

        try:
            while True:
                p.dispatch(1, dump)
        except KeyboardInterrupt:
            pass
        print 'PCAP STATS: ' + repr(p.stats())


class Parser():
    def __init__(self, in_q, out_q):
        self.in_q = in_q
        self.out_q = out_q

    @staticmethod
    def parse(pktlen, data, timestamp):
        packet = {'len': pktlen, 'time': timestamp}
        eth = dpkt.ethernet.Ethernet(data)
        ip = eth.data

        def get_mac_addr(_mac):
            maclist = []
            for Z in range(12/2):
                maclist.append(_mac[Z*2:Z*2+2])
            mac = ":".join(maclist)
            return mac

        if isinstance(ip, dpkt.ip.IP):
            data = ip.data
            packet['type'] = data.__class__.__name__.lower()
            packet['ip_src'] = socket.inet_ntoa(ip.src)
            packet['ip_dst'] = socket.inet_ntoa(ip.dst)
            packet['mac_src'] = get_mac_addr(binascii.hexlify(eth.src))
            packet['mac_dst'] = get_mac_addr(binascii.hexlify(eth.dst))
        else:
            return
        if isinstance(data, dpkt.tcp.TCP) or isinstance(data, dpkt.udp.UDP):
            packet['port_src'] = data.sport
            packet['port_dst'] = data.dport
            # packet['seq'] = data.seq
            # packet['ack'] = data.ack
            # packet['flags'] = data.flags
            packet['icmp_code'] = "''"
        elif isinstance(data, dpkt.icmp.ICMP):
            packet['port_src'] = "''"
            packet['port_dst'] = "''"
            packet['icmp_code'] = data.code
        else:
            return
        return packet

    def run(self):
        while True:
            eventlet.sleep(0)
            try:
                item = self.in_q.get(True, 0.05)
                if item is None:
                    continue
                parsed = self.parse(item[0], item[1], item[2])
                self.out_q.put(parsed)
            except eventlet.queue.Empty:
                pass


class Counter():
    def __init__(self, q):
        self.q = q
        self.dst_count = {}
        self.src_count = {}
        self.ratio_count = {}
        self.block_packet_count = {}
        self.seqcounter = {}
        self.blocked_sources = []
        self.already_blocked = []

    def create_blocking_flow(self, ip_src):
        # This should be reset when the flow has timed out
        if not ip_src in self.blocked_sources:
            self.blocked_sources.append(ip_src)
            match = datapath.ofproto_parser.OFPMatch(dl_type=0x0800, nw_src=ipv4_text_to_int(ip_src), nw_src_mask=32)
            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=random_int(),
                command=datapath.ofproto.OFPFC_ADD, idle_timeout=10, hard_timeout=0,
                priority=0x8000, flags=datapath.ofproto.OFPFF_SEND_FLOW_REM)
            datapath.send_msg(mod)
            print 'creating blocking flow for source: {0}'.format(ip_src)

    def dst_counter(self, packet):
        if packet['ip_dst'] in self.dst_count:
            self.dst_count[packet['ip_dst']] += 1
        else:
            self.dst_count[packet['ip_dst']] = 1

    def src_counter(self, packet):
        if packet['ip_src'] in self.src_count:
            self.src_count[packet['ip_src']] += 1
            if self.src_count[packet['ip_src']] > 10000:
                self.create_blocking_flow(packet['ip_src'])
        else:
            self.src_count[packet['ip_src']] = 1

    def highest_counter(self):
        if len(self.dst_count) > 0:
            target = max(self.dst_count.iteritems(), key=operator.itemgetter(1))
            print 'target: {0}: {1}'.format(target[0], target[1])
        else:
            print 'dst_count empty'

    def ratio_counter(self, packet):
        pair_list = sorted([packet['ip_src'], packet['ip_dst']])
        pair = '-'.join(pair_list)
        if pair in self.ratio_count:
            self.ratio_count[pair][packet['ip_src']] += 1
            ratio = float(self.ratio_count[pair][pair_list[0]]) / float(self.ratio_count[pair][pair_list[1]])
            self.ratio_count[pair]['ratio'] = ratio
            if ratio > 1000:
                self.create_blocking_flow(packet['ip_src'])
        else:
            self.ratio_count[pair] = {packet['ip_src']: 1, packet['ip_dst']: 1, 'ratio': 1}

    def bad_ratios(self):
        ratios = list((k, v['ratio']) for k, v in self.ratio_count.items() if v['ratio'] > 50)
        if len(ratios) > 0:
            for i in ratios:
                print 'Bad ratio: {0}: {1}'.format(i[0].split('-')[0], i[1])
        else:
            print 'No bad ratios'

    def outgoing_block_v1(self, packet):
    # Outgoing_block_V1 starts sampling from the moment we pushed the block flow.
        mac_dst = packet['mac_dst']

        if mac_dst in outgoing_block_mode_v1_dict:
            packet_time = packet['time'] * 1000  # msec
            if packet_time > outgoing_block_mode_v1_dict[mac_dst]:
                pair_list = sorted([packet['ip_src'], packet['ip_dst']])
                pair = '-'.join(pair_list)
                if pair in self.block_packet_count:
                    if time.time() - self.block_packet_count[pair]['last_update'] > 60:
                         # These results weren't updated for over 2 seconds. Reset first.
                        self.block_packet_count[pair][packet['ip_src']] = 1
                        self.block_packet_count[pair]['last_update'] = time.time()

                    self.block_packet_count[pair][packet['ip_src']] += 1
                    ratio = float(self.block_packet_count[pair][pair_list[0]]) / \
                        float(self.block_packet_count[pair][pair_list[1]])
                    self.block_packet_count[pair]['ratio'] = ratio
                    self.block_packet_count[pair]['last_update'] = time.time()

                   # If we receive more than X packets while knowing we didn't reply:
                    if ratio > 10000:
                        print "blocking ", packet['ip_src']
                        self.create_blocking_flow(packet['ip_src'])

                else:
                    self.block_packet_count[pair] = {packet['ip_src']: 1, packet['ip_dst']: 1,
                                                     'ratio': 1, 'last_update': time.time()}
        else:
            print "We're not supposed to sample this packet..."

    def outgoing_block_v2(self, packet):
        #First sample for X seconds knowing that its non-blocked traffic,
        # then sample the packages that we know should been blocked by the outgoing drop flow
        # as the higher priority flow mod was dropped by the switch's timeout.
        mac_dst = packet['mac_dst']
        if mac_dst in outgoing_block_mode_v2_dict:
            packet_time = int(packet['time'] * 1000)  # msec
            pair_list = sorted([packet['ip_src'], packet['ip_dst']])
            pair = '-'.join(pair_list)
            if outgoing_block_mode_v2_dict[mac_dst][0] < packet_time < \
                    (outgoing_block_mode_v2_dict[mac_dst][0] + 2000):  # 2000 ms
                # Dump counters into class dict while keeping note of time, resetting if data is too old.
                if pair in self.block_packet_count:
                    # Reset old data (older than 30 seconds)
                    if self.block_packet_count[pair]['time_created'] < (time.time() - 30):
                        self.block_packet_count[pair] = {'packets_before': 1, 'packets_after': 1,
                                                         'time_created': time.time()}
                    else:
                        self.block_packet_count[pair]['packets_before'] += 1
                else:
                    self.block_packet_count[pair] = {'packets_before': 1, 'packets_after': 1,
                                                     'time_created': time.time()}

            block_time = outgoing_block_mode_v2_dict[mac_dst][0] + 2000
            if packet_time > block_time:
                if not pair in self.block_packet_count:
                    pass
                else:
                    if block_time < packet_time < (block_time + 250):
                        # First 250 ms after installing block flow is discarded
                        pass
                    elif packet_time > block_time and (block_time + 250) < packet_time < (block_time + 750):
                        self.block_packet_count[pair]['packets_after'] += 1
                    elif (block_time + 750) < packet_time < (block_time + 1100):
                        # Last 250 ms is used to trigger the final check to decide wether to
                        # block the source from this packet or not.
                        p_before = self.block_packet_count[pair]['packets_before']
                        # Check if packet tresholds are met:
                        if p_before > 1000:
                            ratio = float(self.block_packet_count[pair]['packets_before']) \
                                / float((self.block_packet_count[pair]['packets_after'] * 4))
                        else:
                            # If treshold is not met we will not block.
                            ratio = 1
                        if ratio < 5:
                            ## Switch flood protection
                            if not packet['ip_src'] in self.already_blocked:
                                self.create_blocking_flow(packet['ip_src'])
                                self.already_blocked.append(packet['ip_src'])
                                print "Created blocking flow for: ", packet['ip_src']

    def run(self):
        while True:
            eventlet.sleep(0)
            try:
                packet = self.q.get(True, 0.05)
                if packet is None:
                    continue
            except eventlet.queue.Empty:
                continue

            if mode == 1:
                self.dst_counter(packet)
            elif mode == 2:
                self.ratio_counter(packet)
            elif mode == 3:
                self.dst_counter(packet)
                self.ratio_counter(packet)
            elif mode == 4:
                self.src_counter(packet)
            elif mode == 5:
                self.outgoing_block_v1(packet)
            elif mode == 6:
                self.outgoing_block_v2(packet)

sniffer = Sniffer(unparsed_q, dev)
sniffer.start()
parser = Parser(unparsed_q, parsed_q)
counter = Counter(parsed_q)


class RyuController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RyuController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flowstats = {}
        self.detected_flags = {}
        self.done = False
        self.byte_treshold = 500000
        self.packet_treshold = 5000
        self.detected_flags = {}
        if socket.gethostname() == 'lt-debian':
            self.gateway_port = 1
            self.map_port_mac = {
                3: '52:54:00:12:e9:0b',
                1: '52:54:00:34:0d:1f',
                65534: '32:32:7c:ac:49:42'
            }
        elif socket.gethostname() == 'OVS-Switch':
            self.gateway_port = 1
            self.map_port_mac = {
                1: '52:54:00:ee:6e:d7',
                2: '52:54:00:2d:0f:99',
                65534: '82:c8:6a:fe:33:4f'
            }
        else:
            self.gateway_port = 33
            self.map_port_mac = {
                32: '00:0c:29:a7:de:cd',
                33: '00:0a:f7:1a:a9:34',
                34: '00:1b:21:bd:dc:9d'
            }
        self.gateway_mac = haddr_to_bin(self.map_port_mac[self.gateway_port])
        self.threads.append(hub.spawn(parser.run))
        self.threads.append(hub.spawn(counter.run))
        self.threads.append(hub.spawn(self.poller))

    @staticmethod
    def clear_flows():
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch()

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0, command=ofproto.OFPFC_DELETE,
            flags=ofproto.OFPFF_SEND_FLOW_REM)
        datapath.send_msg(mod)

    @staticmethod
    def add_flow(in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

        print 'MOD'

    def static_flows(self):
        ofproto = datapath.ofproto
        for k, v in self.map_port_mac.items():
            actions = [datapath.ofproto_parser.OFPActionOutput(k)]

            match = datapath.ofproto_parser.OFPMatch(dl_dst=haddr_to_bin(v))
            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=random_int(),
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=0x4000,
                flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
            datapath.send_msg(mod)

    @staticmethod
    def poller():
        while True:
            if datapath:
                match = datapath.ofproto_parser.OFPMatch(datapath.ofproto.OFPFW_ALL,
                                                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
                req = datapath.ofproto_parser.OFPFlowStatsRequest(datapath, 0, match, 0xff,
                                                                  datapath.ofproto.OFPP_NONE)
                datapath.send_msg(req)
            eventlet.sleep(2)

    # Commented in OpenVswitch to prevent assertion errors. We use static flows. Enable for learning.
    # @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        ofproto = datapath.ofproto

        pkt = libpacket.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
            # print 'mac_to_port = ' + repr(self.mac_to_port)

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(msg.in_port, dst, actions)

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, data=msg.data,
            in_port=msg.in_port, actions=actions)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)

    @set_ev_cls(ofp_event.EventOFPHello, HANDSHAKE_DISPATCHER)
    def _hello_reply_handler(self, ev):
        msg = ev.msg
        global datapath
        datapath = msg.datapath
        self.clear_flows()
        self.static_flows()

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _stats_reply_handler(self, ev):
        msg = ev.msg
        if not msg.datapath == datapath:
            print 'ERROR'
            return

        for stats in msg.body:
            if stats.actions:
                if not stats.cookie in self.flowstats:
                    self.flowstats[stats.cookie] = {
                        'packet_count': [stats.packet_count],
                        'byte_count': [stats.byte_count]
                    }
                else:
                    for k in ["byte_count", "packet_count"]:
                        data = self.flowstats[stats.cookie][k]
                        if len(data) > 60:
                            data.pop()
                        data.reverse()
                        if k == "byte_count":
                            data.append(stats.byte_count)
                        if k == "packet_count":
                            data.append(stats.packet_count)
                        data.reverse()
                        self.flowstats[stats.cookie][k] = data

                    check_result_bytes = self.detect(stats.cookie, self.byte_treshold,
                                                     self.flowstats[stats.cookie]['byte_count'])
                    check_result_packets = self.detect(stats.cookie, self.packet_treshold,
                                                       self.flowstats[stats.cookie]['packet_count'])

                    if check_result_bytes == 1 or check_result_packets == 1:
                        print 'DDoS detected!!', "bytes / packets:", check_result_bytes, '/', check_result_packets
                        if monitor_port not in list(i.port for i in stats.actions):
                            # Temp action mode flag, bypassing the normal sample flow mode for the blockflow mechanism.
                            if mode == 5:
                                self.block_out_sample_in(stats)
                            elif mode == 6:
                                self.sample_first_block_later(stats)
                            else:
                                self.sample_in_out(stats)

    def detect(self, cookie, treshold, data):
        difference_list = []
        for i in range(0, (len(data) - 1)):
            difference = data[i] - data[i + 1]
            difference_list.append(difference)
        if len(difference_list) == 0:
            return 0
        average_difference = sum(difference_list) / len(difference_list)
        std = numpy.std(difference_list)

        for item in difference_list:
            if item - average_difference > 3 * std and item > treshold and std >= 0:
                # print item, " is > then 3 times the standard deviation", std, " item: ", item
                if not cookie in self.detected_flags:
                    self.detected_flags[cookie] = 1
                    return 1
                else:
                    if self.detected_flags[cookie] == 1:
                        return 0
                    elif self.detected_flags[cookie] == 0:
                        self.detected_flags[cookie] = 1
                        return 1
            else:
                return 0

    def block_out_sample_in(self, stats):
        ofproto = datapath.ofproto
        #SRC BLOCK FLOW
        src_mac = stats.match.dl_dst
        if not src_mac == self.gateway_mac:
            src_match = datapath.ofproto_parser.OFPMatch(dl_src=src_mac, dl_dst=self.gateway_mac)

            src_flow = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=src_match, cookie=random_int(),
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=2,
                priority=0x6000,
                flags=ofproto.OFPFF_SEND_FLOW_REM)
            datapath.send_msg(src_flow)

        eventlet.sleep(0.1)

        # DST BLOCK FLOW - We only sample this flow for 1 second,
        # Destination does not receive anything.
        dst_mac = stats.match.dl_dst
        if not dst_mac == self.gateway_mac:
            dst_match = datapath.ofproto_parser.OFPMatch(dl_src=self.gateway_mac, dl_dst=dst_mac)

            dst_actions = [datapath.ofproto_parser.OFPActionOutput(monitor_port)]

            dst_flow = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=dst_match, cookie=random_int(),
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=1,
                priority=0x6000,
                flags=ofproto.OFPFF_SEND_FLOW_REM, actions=dst_actions)
            datapath.send_msg(dst_flow)

        #Notify parser of this source/destination being blocked from this point on.
        outgoing_block_mode_v1_dict[(haddr_to_str(src_mac))] = int(time.time() * 1000)

    def sample_first_block_later(self, stats):
        # DST flow with slightly higher priority
        ofproto = datapath.ofproto
        dst_mac = stats.match.dl_dst
        if not dst_mac == self.gateway_mac:
            dst_match = datapath.ofproto_parser.OFPMatch(dl_src=self.gateway_mac, dl_dst=dst_mac)

            dst_actions = stats.actions
            dst_actions.append(datapath.ofproto_parser.OFPActionOutput(monitor_port))

            dst_flow = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=dst_match, cookie=random_int(),
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=2,
                priority=0x6001,
                flags=ofproto.OFPFF_SEND_FLOW_REM, actions=dst_actions)
            datapath.send_msg(dst_flow)

        outgoing_block_mode_v2_dict[(haddr_to_str(dst_mac))] = []
        # Time of installing first sample flow.
        outgoing_block_mode_v2_dict[(haddr_to_str(dst_mac))].append(int(time.time() * 1000))

        # Not sampling this flow for now. Could check relation between outgoing requests
        # and incoming responses if we sampled this.
        src_mac = stats.match.dl_dst
        if not src_mac == self.gateway_mac:
            src_match = datapath.ofproto_parser.OFPMatch(dl_src=src_mac, dl_dst=self.gateway_mac)

            src_actions = [datapath.ofproto_parser.OFPActionOutput(self.gateway_port)]

            src_flow = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=src_match, cookie=random_int(),
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=2,
                priority=0x6001,
                flags=ofproto.OFPFF_SEND_FLOW_REM, actions=src_actions)
            datapath.send_msg(src_flow)

        #SRC BLOCK FLOW
        src_mac = stats.match.dl_dst
        if not src_mac == self.gateway_mac:
            src_match = datapath.ofproto_parser.OFPMatch(dl_src=src_mac, dl_dst=self.gateway_mac)

            src_flow = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=src_match, cookie=random_int(),
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=3,
                priority=0x6000,
                flags=ofproto.OFPFF_SEND_FLOW_REM)
            datapath.send_msg(src_flow)

        # Time of installing DROP flow. We do not want to count packets after this flow expired
        # (3 seconds from this moment on)
        outgoing_block_mode_v2_dict[(haddr_to_str(dst_mac))].append(int(time.time() * 1000))

        # DST BLOCK FLOW - We only sample this flow for 1 second,
        # destination does not receive anything.
        dst_mac = stats.match.dl_dst
        if not dst_mac == self.gateway_mac:
            dst_match = datapath.ofproto_parser.OFPMatch(dl_src=self.gateway_mac, dl_dst=dst_mac)

            dst_actions = [datapath.ofproto_parser.OFPActionOutput(monitor_port)]

            dst_flow = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=dst_match, cookie=random_int(),
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=3,
                priority=0x6000,
                flags=ofproto.OFPFF_SEND_FLOW_REM, actions=dst_actions)
            datapath.send_msg(dst_flow)

    def sample_in_out(self, stats):
        print 'sample_in_out started'
        ofproto = datapath.ofproto
        # DST flow
        dst_mac = stats.match.dl_dst
        if not dst_mac == self.gateway_mac:
            dst_match = datapath.ofproto_parser.OFPMatch(dl_src=self.gateway_mac, dl_dst=dst_mac)

            dst_actions = stats.actions
            dst_actions.append(datapath.ofproto_parser.OFPActionOutput(monitor_port))

            dst_flow = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=dst_match, cookie=random_int(),
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=10,
                priority=0x6000,
                flags=ofproto.OFPFF_SEND_FLOW_REM, actions=dst_actions)
            datapath.send_msg(dst_flow)
            print 'Creating dst match sample flow'

        # SRC flow
        src_mac = stats.match.dl_dst
        if not src_mac == self.gateway_mac:
            src_match = datapath.ofproto_parser.OFPMatch(dl_src=src_mac, dl_dst=self.gateway_mac)

            src_actions = [datapath.ofproto_parser.OFPActionOutput(self.gateway_port),
                           datapath.ofproto_parser.OFPActionOutput(monitor_port)]

            src_flow = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=src_match, cookie=random_int(),
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=60,
                priority=0x6000,
                flags=ofproto.OFPFF_SEND_FLOW_REM, actions=src_actions)
            datapath.send_msg(src_flow)
            print 'Creating src match sample flow'