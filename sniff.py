from scapy.all import sniff, Dot11, RadioTap, Dot11QoS
import csv, time, os

ts_file = time.strftime("%Y%m%d_%H%M%S") #Start Sniff Time

INTERFACE = "wlx1cbfceb8b5ea"
CSV_FILE = f"../data/wifi_packets_{ts_file}.csv"

os.makedirs(os.path.dirname(CSV_FILE), exist_ok=True)
file_exists = os.path.isfile(CSV_FILE)

csvfile = open(CSV_FILE, "a", newline="", encoding="utf-8")
writer = csv.writer(csvfile)

if not file_exists: #header
    writer.writerow([
        "timestamp",
        "channel","freq",
        "type","subtype",
        "src_mac","dst_mac","bssid","ssid",
        "rssi","noise","antenna",
        "data_rate","mcs",
        "frame_len","sequence",
        "retry","to_ds","from_ds",
        "qos_tid"
    ])

def handle(pkt): #จัดการ 1 packet
    if not pkt.haslayer(Dot11): #Dot11 = payload ของ wifi
        return

    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    dot11 = pkt[Dot11] #focus ที่ dot11

    src = dot11.addr2 #แยก field
    dst = dot11.addr1
    bssid = dot11.addr3
    ftype = dot11.type
    fsub = dot11.subtype
    frame_len = len(pkt)

    #Frame Control
    retry = bool(dot11.FCfield & 0x08)
    to_ds = bool(dot11.FCfield & 0x01)
    from_ds = bool(dot11.FCfield & 0x02)

    sequence = None
    if getattr(dot11, "SC", None) is not None:
        sequence = dot11.SC >> 4 #shift 4 เอาแค่ seq num


    # ---------- QoS ----------
    qos_tid = None
    if pkt.haslayer(Dot11QoS):
        qos_tid = pkt[Dot11QoS].TID

    # ---------- SSID ----------
    ssid = None
    if ftype == 0 and fsub in [8, 5]:  # beacon / probe response
        ssid = dot11.info.decode(errors="ignore") if dot11.info else None

    # ---------- RadioTap ----------
    rssi = noise = antenna = rate = mcs = channel = freq = None

    if pkt.haslayer(RadioTap): #ใส่ค่า rt ถ้ามี
        rt = pkt[RadioTap]

        if hasattr(rt, "dBm_AntSignal"):
            rssi = rt.dBm_AntSignal

        if hasattr(rt, "dBm_AntNoise"):
            noise = rt.dBm_AntNoise

        if hasattr(rt, "Antenna"):
            antenna = rt.Antenna

        if hasattr(rt, "Rate"):
            rate = rt.Rate

        if hasattr(rt, "ChannelFrequency"):
            freq = rt.ChannelFrequency

        if hasattr(rt, "Channel"):
            try:
                channel = rt.Channel
            except:
                channel = None

        if hasattr(rt, "MCS"):
            mcs = rt.MCS

    writer.writerow([
        ts,
        channel, freq,
        ftype, fsub,
        src, dst, bssid, ssid,
        rssi, noise, antenna,
        rate, mcs,
        frame_len, sequence,
        retry, to_ds, from_ds,
        qos_tid
    ])

    csvfile.flush()

print("[*] Wi-Fi monitor sniffing started")
sniff(iface=INTERFACE, prn=handle, store=False)
