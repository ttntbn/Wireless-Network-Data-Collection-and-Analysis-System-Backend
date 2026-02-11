from scapy.all import sniff, Dot11, RadioTap, Dot11QoS
import csv, time, os, sys
from logger_config import setup_logger

ts_file = time.strftime("%Y%m%d_%H%M%S")
logger = setup_logger()

INTERFACE = "wlx1cbfceb8b5ea"
CSV_FILE = f"../data/manual_wifi_packets_{ts_file}.csv"

os.makedirs(os.path.dirname(CSV_FILE), exist_ok=True)
file_exists = os.path.isfile(CSV_FILE)

csvfile = open(CSV_FILE, "a", newline="", encoding="utf-8")
writer = csv.writer(csvfile)

if not file_exists:
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

def handle(pkt):
    try:
        if not pkt.haslayer(Dot11):
            return

        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        dot11 = pkt[Dot11]

        # -------- Basic Fields --------
        src = getattr(dot11, "addr2", None)
        dst = getattr(dot11, "addr1", None)
        bssid = getattr(dot11, "addr3", None)
        ftype = getattr(dot11, "type", None)
        fsub = getattr(dot11, "subtype", None)
        frame_len = len(pkt)

        # -------- Frame Control --------
        fc = getattr(dot11, "FCfield", 0)
        retry = bool(fc & 0x08)
        to_ds = bool(fc & 0x01)
        from_ds = bool(fc & 0x02)

        # -------- Sequence --------
        sequence = None
        sc = getattr(dot11, "SC", None)
        if sc is not None:
            try:
                sequence = sc >> 4
            except:
                sequence = None

        # -------- QoS --------
        qos_tid = None
        if pkt.haslayer(Dot11QoS):
            qos = pkt[Dot11QoS]
            qos_tid = getattr(qos, "TID", None)

        # -------- SSID --------
        ssid = None
        if ftype == 0 and fsub in [8, 5]:  # beacon / probe response
            try:
                raw_ssid = getattr(dot11, "info", None)
                if raw_ssid:
                    ssid = raw_ssid.decode(errors="ignore")
            except:
                ssid = None

        # -------- RadioTap --------
        rssi = noise = antenna = rate = mcs = channel = freq = None

        if pkt.haslayer(RadioTap):
            rt = pkt[RadioTap]

            rssi = getattr(rt, "dBm_AntSignal", None)
            noise = getattr(rt, "dBm_AntNoise", None)
            antenna = getattr(rt, "Antenna", None)
            rate = getattr(rt, "Rate", None)
            freq = getattr(rt, "ChannelFrequency", None)
            mcs = getattr(rt, "MCS", None)

            try:
                channel = getattr(rt, "Channel", None)
            except:
                channel = None

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

    except Exception as e:
        # กัน crash ทั้งโปรแกรม
        logger.exception("Packet processing error")

logger.info("Wi-Fi monitor sniffing started (^C to stop)")

try:
    sniff(iface=INTERFACE, prn=handle, store=False)
except KeyboardInterrupt:
    logger.info("Stopping sniffer...")
finally:
    csvfile.close()
    logger.info("[*] CSV file closed")
