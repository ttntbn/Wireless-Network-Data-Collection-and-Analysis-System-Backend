from scapy.all import RadioTap
from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11QoS, Dot11Beacon
import time


# =========================
# AWID HEADERS
# =========================

AWID_HEADERS = [
"frame.time_epoch","frame.len","frame.cap_len",

"radiotap.length",
"radiotap.datarate",
"radiotap.channel.freq",
"radiotap.dbm_antsignal",
"radiotap.antenna",
"radiotap.flags.wep",
"radiotap.flags.frag",
"radiotap.flags.badfcs",

"wlan.fc.type_subtype",
"wlan.fc.type",
"wlan.fc.subtype",
"wlan.fc.retry",
"wlan.fc.pwrmgt",
"wlan.fc.moredata",
"wlan.fc.protected",
"wlan.fc.order",

"wlan.duration",
"wlan.ra",
"wlan.ta",
"wlan.sa",
"wlan.da",
"wlan.bssid",
"wlan.seq",
"wlan.frag",

"wlan_mgt.ssid",
"wlan_mgt.ds.current_channel",
"wlan_mgt.tim.dtim_count",
"wlan_mgt.tim.dtim_period",
"wlan_mgt.rsn.version",

"wlan.qos.tid",

"data.len",
"class"
]


# =========================
# FRAME
# =========================

def parse_frame(pkt,data):

    now=time.time()

    data["frame.time_epoch"]=now
    data["frame.len"]=len(pkt)
    data["frame.cap_len"]=len(pkt)


# =========================
# RADIOTAP
# =========================

def parse_radiotap(pkt,data):

    if not pkt.haslayer(RadioTap):
        return

    rt=pkt[RadioTap]

    data["radiotap.length"]=getattr(rt,"len",0)
    data["radiotap.datarate"]=getattr(rt,"Rate",0)
    data["radiotap.channel.freq"]=getattr(rt,"ChannelFrequency",0)
    data["radiotap.dbm_antsignal"]=getattr(rt,"dBm_AntSignal",0)
    data["radiotap.antenna"]=getattr(rt,"Antenna",0)

    flags=getattr(rt,"Flags",0)

    data["radiotap.flags.wep"]=1 if flags & 0x10 else 0
    data["radiotap.flags.frag"]=1 if flags & 0x04 else 0
    data["radiotap.flags.badfcs"]=1 if flags & 0x40 else 0


# =========================
# WLAN CORE
# =========================

def parse_wlan(pkt,data):

    if not pkt.haslayer(Dot11):
        return

    dot11=pkt[Dot11]

    data["wlan.fc.type"]=dot11.type
    data["wlan.fc.subtype"]=dot11.subtype
    data["wlan.fc.type_subtype"]=dot11.type*16+dot11.subtype

    fc=dot11.FCfield

    data["wlan.fc.retry"]=1 if fc & 0x08 else 0
    data["wlan.fc.pwrmgt"]=1 if fc & 0x10 else 0
    data["wlan.fc.moredata"]=1 if fc & 0x20 else 0
    data["wlan.fc.protected"]=1 if fc & 0x40 else 0
    data["wlan.fc.order"]=1 if fc & 0x80 else 0

    data["wlan.ra"]=dot11.addr1 or ""
    data["wlan.ta"]=dot11.addr2 or ""
    data["wlan.sa"]=dot11.addr2 or ""
    data["wlan.da"]=dot11.addr1 or ""
    data["wlan.bssid"]=dot11.addr3 or ""

    sc=getattr(dot11,"SC",0) or 0

    data["wlan.seq"]=sc>>4
    data["wlan.frag"]=sc & 0xF

    data["wlan.duration"]=getattr(dot11,"ID",0)


# =========================
# MANAGEMENT FRAMES
# =========================

def parse_management(pkt,data):

    if pkt.haslayer(Dot11Beacon):

        beacon=pkt[Dot11Beacon]

        data["wlan_mgt.fixed.beacon"]=beacon.beacon_interval

    if not pkt.haslayer(Dot11Elt):
        return

    elt=pkt.getlayer(Dot11Elt)

    while elt:

        if elt.ID==0:

            try:
                data["wlan_mgt.ssid"]=elt.info.decode(errors="ignore")
            except:
                pass

        elif elt.ID==3:

            if elt.info:
                data["wlan_mgt.ds.current_channel"]=elt.info[0]

        elif elt.ID==5:

            if len(elt.info)>=2:
                data["wlan_mgt.tim.dtim_count"]=elt.info[0]
                data["wlan_mgt.tim.dtim_period"]=elt.info[1]

        elif elt.ID==48:

            data["wlan_mgt.rsn.version"]=1

        elt=elt.payload.getlayer(Dot11Elt)


# =========================
# QOS
# =========================

def parse_qos(pkt,data):

    if not pkt.haslayer(Dot11QoS):
        return

    qos=pkt[Dot11QoS]

    data["wlan.qos.tid"]=qos.TID


# =========================
# DATA
# =========================

def parse_data(pkt,data):

    try:
        data["data.len"]=len(pkt.payload)
    except:
        pass


# =========================
# MAIN PARSER
# =========================

def extract_awid_fields(pkt):

    data={h:0 for h in AWID_HEADERS}

    parse_frame(pkt,data)
    parse_radiotap(pkt,data)
    parse_wlan(pkt,data)
    parse_management(pkt,data)
    parse_qos(pkt,data)
    parse_data(pkt,data)

    return data


# =========================
# PACKET HANDLER
# =========================

def handle_packet(pkt,writer,logger):

    if not pkt.haslayer(Dot11):
        return

    try:

        data=extract_awid_fields(pkt)

        row=[data.get(h,0) for h in AWID_HEADERS]

        writer.writerow(row)

    except Exception:

        logger.exception("Packet parsing error")