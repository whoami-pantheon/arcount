"""Best-guess device type from the maker's name (offline; a hint, never proof).

A MAC address names the company that made the network chip, not the device. Specialist makers
(camera, printer and router companies) give a confident answer; makers that sell many kinds of
product give a list with a trailing "?". Randomised and virtual addresses are labelled as such.
"""
from __future__ import annotations

import re

# Most specific first: the first matching row wins. Keywords match whole words, case-insensitive.
_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("camera", ("hikvision", "dahua", "uniview", "uniarch", "axis communications", "hanwha",
                "vivotek", "reolink", "amcrest", "foscam", "mobotix", "geovision", "ezviz",
                "tiandy", "annke", "lorex", "swann", "wyze", "arlo", "ring", "blink", "verkada",
                "hikmicro", "imou", "tvt digital", "milesight", "avigilon", "pelco", "bosch security")),
    ("printer", ("brother industries", "canon", "seiko epson", "epson", "lexmark", "xerox", "ricoh",
                 "kyocera", "konica minolta", "oki data", "zebra technologies", "sharp document")),
    ("VoIP phone", ("polycom", "yealink", "grandstream", "mitel", "snom", "fanvil", "avaya",
                    "aastra", "gigaset", "panasonic communications")),
    ("NAS / storage", ("synology", "qnap", "asustor", "western digital", "drobo", "buffalo",
                       "netapp", "terramaster")),
    ("game console", ("nintendo", "sony interactive", "sony computer entertainment", "valve")),
    ("TV / streaming", ("roku", "vizio", "hisense", "skyworth", "tivo", "tcl", "chromecast",
                        "sonos", "bose", "denon", "marantz", "harman", "pioneer", "onkyo", "yamaha")),
    ("smart home / IoT", ("espressif", "tuya", "silicon laboratories", "nordic semiconductor",
                          "texas instruments", "shelly", "allterco", "itead", "sonoff", "ecobee",
                          "nest labs", "signify", "philips lighting", "lifx", "ikea", "sengled",
                          "ledvance", "em microelectronic", "raspberry pi", "arduino", 
                          "shenzhen rf-star", "ai-thinker", "wiz", "meross",
                          "broadlink", "ezlo", "smartthings", "aqara", "lumi united", "roborock",
                          "irobot", "ecovacs", "dreame")),
    ("router / network gear", ("ubiquiti", "mikrotik", "routerboard", "cisco", "juniper", "netgear",
                               "tp-link", "d-link", "zyxel", "ruckus", "aruba", "eero", "arris",
                               "sagemcom", "fiberhome", "zte", "vantiva", "technicolor",
                               "arcadyan", "askey", "h3c", "extreme networks", "linksys", "belkin",
                               "sercomm", "actiontec", "calix", "adtran", "cambium", "engenius",
                               "draytek", "fortinet", "palo alto", "sonicwall", "watchguard",
                               "peplink", "teltonika", "cradlepoint", "commscope", "ubee",
                               "netcomm", "huawei technologies", "sichuan tianyi", "2wire", "humax", "hitron", "avm audiovisuelles", "sky uk",
                               "t&w electronics", "gaoshengda", "gongjin", "adb broadband", "nortel",
                               "arista", "brocade", "ciena", "mellanox", "ericsson", "cloud network technology",
                               "china mobile group device", "youhua", "superelectron", "bilian", "fn-link", "comtrend",
                               "tenda", "mercusys", "ruijie", "cambridge industries", "alcatel-lucent",
                               "plume design", "aerohive", "meraki", "peplink", "zhone", "nokia solutions")),
    ("computer", ("dell", "lenovo", "acer", "micro-star", "gigabyte", "toshiba", "fujitsu",
                  "giga-byte", "lcfc", "framework computer", "system76", "razer", "alienware", "killer networking")),
)

# Makers of many kinds of product: the honest answer is a short list with a "?".
_AMBIGUOUS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("iPhone / Mac / iPad / Apple TV?", ("apple",)),
    ("phone / TV / appliance?", ("samsung",)),
    ("TV / phone / appliance?", ("lg electronics",)),
    ("TV / console / phone?", ("sony",)),
    ("Echo / Fire TV / Kindle?", ("amazon",)),
    ("Pixel / Chromecast / Nest?", ("google",)),
    ("PC / Xbox?", ("microsoft",)),
    ("PC / printer?", ("hewlett packard", "hp inc")),
    ("phone?", ("htc corporation",)),
    ("appliance (air-con etc.)?", ("midea",)),
    ("remote control?", ("universal electronics",)),
    ("IoT module?", ("quectel", "lg innotek", "alpsalpine", "renesas", "china mobile iot")),
    ("PC / router?", ("asustek", "asus")),
    ("phone / router?", ("huawei",)),
    ("phone / IoT?", ("xiaomi",)),
    ("PC (Wi-Fi / Ethernet chip)?", ("intel",)),
    ("phone?", ("oppo", "vivo", "motorola", "oneplus", "realme", "itel", "tecno", "tct mobile",
                "hmd global", "honor", "nothing technology", "fairphone", "infinix", "zte mobile")),
    ("various (module maker)?", ("hon hai", "foxconn", "fugui", "pegatron", "compal", "wistron", "quanta",
                                 "inventec", "usi", "universal global scientific")),
    ("router / phone?", ("nokia",)),
    ("PC (Wi-Fi card)?", ("liteon", "azurewave")),
    ("various (chip maker)?", ("realtek", "broadcom", "qualcomm", "mediatek", "ralink", "murata",
                               "marvell", "atheros")),
)

_VM_PREFIXES = {
    "00:0c:29": "virtual machine (VMware)", "00:50:56": "virtual machine (VMware)",
    "00:05:69": "virtual machine (VMware)", "08:00:27": "virtual machine (VirtualBox)",
    "00:15:5d": "virtual machine (Hyper-V)", "00:1c:42": "virtual machine (Parallels)",
    "52:54:00": "virtual machine (QEMU/KVM)", "02:42:ac": "container (Docker)",
    "00:16:3e": "virtual machine (Xen)",
}


def _compile(groups):
    out = []
    for label, words in groups:
        pat = "|".join(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])" for w in words)
        out.append((label, re.compile(pat)))
    return out


_CONFIDENT = _compile(_RULES)
_MIXED = _compile(_AMBIGUOUS)


def guess(vendor: str, mac: str = "", is_gateway: bool = False) -> str:
    """A short device-type label, or "" when nothing sensible can be said."""
    if is_gateway:
        return "gateway / router"
    mac = (mac or "").lower()
    if mac[:8] in _VM_PREFIXES:
        return _VM_PREFIXES[mac[:8]]
    v = (vendor or "").lower()
    if not v:
        try:
            if int(mac[:2], 16) & 2:
                return "phone / laptop (random MAC)"
        except ValueError:
            pass
        return ""
    for label, rx in _CONFIDENT:
        if rx.search(v):
            return label
    for label, rx in _MIXED:
        if rx.search(v):
            return label
    return ""
