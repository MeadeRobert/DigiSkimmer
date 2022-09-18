from datetime import datetime, timedelta
from digiskr.wsprnet import Wsprnet
from digiskr.parser import LineParser
import re
import time
from digiskr.pskreporter import PskReporter
from digiskr.base import AudioDecoderProfile
from digiskr.config import Config
from abc import ABC, ABCMeta, abstractmethod
import threading
import sys
import logging
import socket
import struct
from . import pywsjtx


def freq_to_band(f):
    if f >= 1.8e6 and f <= 2.0e6:
        return '160m'
    elif f >= 3.5e6 and f <= 4.0e6:
        return '80m'
    elif f >= 5329e3 and f <= 5405:
        return '60m'
    elif f >= 7.0e6 and f <= 7.3e6:
        return '40m'
    elif f >= 10.1e6 and f <= 10.15e6:
        return '30m'
    elif f >= 14.0e6 and f <= 14350e3:
        return '20m'
    elif f >= 18068e3 and f <= 18168e3:
        return '17m'
    elif f >= 21.0e6 and f <= 21450e3:
        return '15m'
    elif f >= 24890 and f <= 24990e3:
        return '12m'
    elif f >= 28.0e6 and f <= 29.7e6:
        return '10m'
    elif f >= 50e6 and f <= 54e6:
        return '6m'
    elif f >= 144e6 and f <= 148e6:
        return '2m'
    elif f >= 222e6 and f <= 225e6:
        return '1.25m'
    elif f >= 420e6 and f <= 450e6:
        return '70cm'
    else:
        return 'OOB'

class WSJTXUDPService(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.addr = '224.0.0.1'
        self.port = 2237
        self.addr_port = (self.addr,self.port)
        self.sock.bind(self.addr_port)
        mreq = struct.pack("4sl", socket.inet_aton(self.addr), socket.INADDR_ANY)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        self.in_use = {}

    def run(self):
        while True:
            try:
                pkt = self.sock.recvfrom(4096)
                wsjtx_pkt = pywsjtx.WSJTXPacketClassFactory.from_udp_packet(self.addr_port, pkt[0])
                if wsjtx_pkt.pkt_type == pywsjtx.StatusPacket.TYPE_VALUE and 'DigiSkr' not in wsjtx_pkt.wsjtx_id:
                    self.in_use[wsjtx_pkt.wsjtx_id] = (wsjtx_pkt.mode, freq_to_band(wsjtx_pkt.dial_frequency))
            except Exception as e:
                print(e)
                print(pkt)

wsjtx_udp_service = WSJTXUDPService()
wsjtx_udp_service.start()

class WsjtProfile(AudioDecoderProfile, metaclass=ABCMeta):
    def decoding_depth(self, mode):
        conf = Config.get()
        if "WSJTX" in conf:
            conf = conf["WSJTX"]
            # mode-specific setting?
            if "decoding_depth_modes" in conf and mode in conf["decoding_depth_modes"]:
                return conf["decoding_depth_modes"][mode]
            # return global default
            if "decoding_depth_global" in conf:
                return conf["decoding_depth_global"]

        # default when no setting is provided
        return 3

    @staticmethod
    def get(mode: str):
        if mode == "FT8":
            return FT8Profile()
        elif mode == "FT4":
            return FT4Profile()
        elif mode == "WSPR":
            return WsprProfile()
        elif mode == "JT65":
            return JT65Profile()
        elif mode == "JT9":
            return JT9Profile()
        elif mode == "FST4W":
            return Fst4wProfile()
        else:
            raise Exception("invalid mode!")


class FT8Profile(WsjtProfile):
    def getMode(self):
        return "FT8"

    def getInterval(self):
        return 15

    def getFileTimestampFormat(self):
        return "%y%m%d_%H%M%S"

    def decoder_commandline(self, file):
        return ["jt9", "--ft8", "-d", str(self.decoding_depth(self.getMode())), file]


class FT4Profile(WsjtProfile):
    def getMode(self):
        return "FT4"

    def getInterval(self):
        return 7.5

    def getFileTimestampFormat(self):
        return "%y%m%d_%H%M%S"

    def decoder_commandline(self, file):
        return ["jt9", "--ft4", "-d", str(self.decoding_depth(self.getMode())), file]


class WsprProfile(WsjtProfile):
    def getMode(self):
        return "WSPR"

    def getInterval(self):
        return 120

    def getFileTimestampFormat(self):
        return "%y%m%d_%H%M"

    def decoder_commandline(self, file):
        # Options of wsprd:
        # -B disable block demodulation - use single-symbol noncoherent demod
        # -c write .c2 file at the end of the first pass
        # -C maximum number of decoder cycles per bit, default 10000
        # -d deeper search. Slower, a few more decodes
        # -e x (x is transceiver dial frequency error in Hz)
        # -f x (x is transceiver dial frequency in MHz)
        # -H do not use (or update) the hash table
        # -J use the stack decoder instead of Fano decoder
        # -m decode wspr-15 .wav file
        # -o n (0<=n<=5), decoding depth for OSD, default is disabled
        # -q quick mode - doesn't dig deep for weak signals
        # -s single pass mode, no subtraction (same as original wsprd)
        # -w wideband mode - decode signals within +/- 150 Hz of center
        # -z x (x is fano metric table bias, default is 0.45)
        cmd = ["wsprd", "-C", "500", "-w"]
        if self.decoding_depth(self.getMode()) > 1:
            cmd += ["-o", "4", "-d"]
        cmd += [file]
        return cmd


class JT65Profile(WsjtProfile):
    def getMode(self):
        return "JT65"

    def getInterval(self):
        return 60

    def getFileTimestampFormat(self):
        return "%y%m%d_%H%M"

    def decoder_commandline(self, file):
        return ["jt9", "--jt65", "-d", str(self.decoding_depth(self.getMode())), file]


class JT9Profile(WsjtProfile):
    def getMode(self):
        return "JT9"

    def getInterval(self):
        return 60

    def getFileTimestampFormat(self):
        return "%y%m%d_%H%M"

    def decoder_commandline(self, file):
        return ["jt9", "--jt9", "-d", str(self.decoding_depth(self.getMode())), file]


class Fst4wProfile(WsjtProfile):
    availableIntervals = [120, 300, 900, 1800]

    def getMode(self):
        return "FST4W"

    def getInterval(self):
        conf = Config.get()
        if "WSJTX" in conf:
            conf = conf["WSJTX"]
            if "interval" in conf and self.getMode() in conf["interval"]:
                return conf["interval"][self.getMode()] if conf["interval"][self.getMode()] in self.availableIntervals else self.availableIntervals[0]

        # default when no setting is provided
        return self.availableIntervals[0]

    def getFileTimestampFormat(self):
        return "%y%m%d_%H%M"

    def decoder_commandline(self, file):
        return ["jt9", "--fst4w", "-p", str(self.getInterval()), "-F", str(100), "-d", str(self.decoding_depth(self.getMode())), file]

class WsjtParser(LineParser):

    def parse(self, messages):
        for data in messages:
            try:
                profile, freq, raw_msg = data
                self.dial_freq = freq
                msg = raw_msg.decode().rstrip()
                # known debug messages we know to skip
                if msg.startswith("<DecodeFinished>"):  # this is what jt9 std output
                    continue
                if msg.startswith(" EOF on input file"):  # this is what jt9 std output
                    continue

                if isinstance(profile, WsprProfile):
                    decoder = WsprDecoder()
                else:
                    decoder = JT9Decoder()
                out = decoder.parse(msg, freq)
                logging.info("[%s] %s T%s DB%2.1f DT%2.1f F%2.6f %s : %s %s",
                             self.getStation(),
                             out["mode"],
                             time.strftime("%H%M%S",  time.localtime(out["timestamp"])),
                             out["db"], out["dt"], out["freq"], out["msg"],
                             out["callsign"] if "callsign" in out else "-",
                             out["locator"] if "locator" in out else "")

                f = int(out["freq"]*1e6)
                band = freq_to_band(f)
                t = datetime.utcfromtimestamp(out["timestamp"])
                millis_since_midnight = 1000 * (t.hour * 3600 + t.minute * 60 + t.second)

                if (out["mode"], band) not in wsjtx_udp_service.in_use.values():
                    print("sending status " + out["mode"] + ", " +  band)
                    #heartbeat = pywsjtx.HeartBeatPacket.Builder(wsjtx_id='DigiSkr-'+band,max_schema=3,version='2.5.4',revision='d28164')
                    status = pywsjtx.StatusPacket.Builder(wsjtx_id='DigiSkr-'+band, dial_frequency=f, mode=out["mode"], dx_call='', report='', tx_mode=out["mode"], tx_enabled=0, transmitting=0, decoding=0, rx_df=0, tx_df=0, de_call='KB3WFQ', de_grid='FN20GF', dx_grid='', tx_watchdog=0, sub_mode=b'', fast_mode=0, special_op_mode=0, freq_tolerance=-1, tr_period=-1, config_name='Default', tx_message='')
                    decode = pywsjtx.DecodePacket.Builder(wsjtx_id='DigiSkr-'+band, new_decode=1, millis_since_midnight=millis_since_midnight, snr=int(out["db"]), delta_t=0, delta_f=0, mode=out["mode"], message=out["msg"], low_confidence=0)
                    wsjtx_udp_service.sock.sendto(status, wsjtx_udp_service.addr_port)
                    wsjtx_udp_service.sock.sendto(decode, wsjtx_udp_service.addr_port)

                if "mode" in out:
                    if "callsign" in out and "locator" in out:
                        PskReporter.getSharedInstance(self.getStation()).spot(out)
                        # upload beacons to wsprnet as well
                        if out["mode"] in ["WSPR", "FST4W"]:
                            Wsprnet.getSharedInstance(self.getStation()).spot(out)

            except ValueError:
                logging.exception("error while parsing wsjt message")


class Decoder(ABC):
    def parse_timestamp(self, instring, dateformat):
        ts = datetime.strptime(instring, dateformat)
        return int(
            datetime.combine(datetime.now().date(), ts.time()).timestamp()
        )

    @abstractmethod
    def parse(self, msg, dial_freq):
        pass


class JT9Decoder(Decoder):
    jt9_modes = {"~": "FT8", "#": "JT65", "@": "JT9", "+": "FT4", "`": "FST4W"}
    # CQ DX BD7MQB OM92
    locator_pattern = re.compile(
        ".+[A-Z0-9/]+\s([A-Z0-9/]+?)\s([A-R]{2}[0-9]{2})$")
    # HU4FUJ CV1KUS/R R NC08
    locator_pattern2 = re.compile(
        ".+[A-Z0-9/]+\s([A-Z0-9/]+?)\s[A-Z]\s([A-R]{2}[0-9]{2})$")

    def parse(self, msg, dial_freq):
        # ft8 sample
        # '222100 -15 -0.0  508 ~  CQ EA7MJ IM66'
        # '000000 -11  0.2 1000 ~  CQ EU BG4WOM OM92'
        # jt65 sample
        # '2352  -7  0.4 1801 #  R0WAS R2ABM KO85'
        # '0003  -4  0.4 1762 #  CQ R2ABM KO85'

        modes = list(self.jt9_modes.keys())
        if msg[19] in modes:
            dateformat = "%H%M"
        else:
            dateformat = "%H%M%S"
        timestamp = self.parse_timestamp(msg[0: len(dateformat)], dateformat)
        msg = msg[len(dateformat) + 1:]
        modeChar = msg[14:15]
        mode = self.jt9_modes[modeChar] if modeChar in self.jt9_modes else "unknown"
        wsjt_msg = msg[17:53].strip()

        result = {
            "timestamp": timestamp,
            "db": float(msg[0:3]),
            "dt": float(msg[4:8]),
            "freq": (dial_freq * 1000 + int(msg[9:13])) / 1e6,
            "mode": mode,
            "msg": wsjt_msg,
        }
        if mode == "FST4W":
            result.update(self.parseBeaconMessage(wsjt_msg))
        else:
            result.update(self.parseQSOMessage(wsjt_msg))

        return result

    def parseBeaconMessage(self, msg):
        m = WsprDecoder.wspr_splitter_pattern.match(msg)
        if m is None:
            return {}
        return {
                "sync_quality": 0.7, "drift": 0, 
                "callsign": m.group(1), "locator": m.group(2), "watt": int(m.group(3))
                }

    def parseQSOMessage(self, msg):
        if msg.startswith("CQ") or len(msg.split(" ")) == 3:
            m = JT9Decoder.locator_pattern.match(msg)
        else:
            m = JT9Decoder.locator_pattern2.match(msg)

        if m is None:
            return {}
        if m.group(2) == "RR73":
            return {"callsign": m.group(1).split("/")[0]}
        return {"callsign": m.group(1).split("/")[0], "locator": m.group(2)}


class WsprDecoder(Decoder):
    wspr_splitter_pattern = re.compile("[<]?([A-Z0-9/]*)[>]?\s([A-R]{2}[0-9]{2}[\w]{0,2})\s([0-9]+)")

    def parse(self, msg, dial_freq):
        # wspr sample
        # '2600 -24  0.4   0.001492 -1  G8AXA JO01 33'
        # '0052 -29  2.6   0.001486  0  G02CWT IO92 23'
        # '0132 -22  0.6   0.001486  0  <JA8XMC/B> QN03QB 37'
        # <time UTC> <SNR in dB> <DT> <Audio frequency in Hz> <Drift> <Callsign received> <Grid of received station> <Reported TX power in dBm>

        # fst4w sample
        # 0000  13  0.2 1573 `  KA7OEI DN40 17
        # <time UTC> <SNR in dB> <DT> <Audio frequency in Hz> <Mode> <Callsign received> <Grid of received station> <Reported TX power in dBm>

        wsjt_msg = msg[29:].strip()
        result = {
            "timestamp": self.parse_timestamp(msg[0:4], "%H%M"),
            "db": float(msg[5:8]),
            "dt": float(msg[9:13]),
            "freq": (dial_freq * 1000 + int(float(msg[14:24]) * 1e6)) / 1e6,
            "drift": int(msg[25:28]),
            "mode": "WSPR",
            # FIXME: No idea what sync_quality used for but we need to add this field to bypass the upload check,
            # it seems to useless because the static files downloaded from wsprnet.org doesn't contain this field.
            # i don't want to read it from wspr_spots.txt so i simply pick a random value :)
            "sync_quality": 0.7,
            "msg": wsjt_msg,
        }

        # TODO: cleanup ALL_WSPR.txt to avoid disk full
        result.update(self.parseMessage(wsjt_msg))
        return result

    def parseMessage(self, msg):
        m = WsprDecoder.wspr_splitter_pattern.match(msg)
        if m is None:
            return {}
        # TODO: handle msg type "<G0EKQ>        IO83PI 37"
        return {"callsign": m.group(1), "locator": m.group(2), "watt": int(m.group(3))}
