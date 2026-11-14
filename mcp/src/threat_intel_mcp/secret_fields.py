"""Credential header names shared by logging and cassette recording."""
SECRET_HEADERS = [
    "authorization",       # Intel 471, Censys (HTTP Basic)
    "x-apikey",            # VirusTotal
    "x-otx-api-key",       # AlienVault OTX
    "auth-key",            # abuse.ch (URLhaus, Feodo Tracker, ThreatFox)
    "key",                 # GreyNoise
    "x-api-key",           # generic
    "x-auth-token",        # generic
    "apikey",              # NVD (header form)
    "cookie",
    "set-cookie",
    "proxy-authorization",
]
