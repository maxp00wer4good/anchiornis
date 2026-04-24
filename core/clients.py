import os
from dotenv import load_dotenv

from connectors.virustotal import VirusTotalClient
from connectors.abuseipdb import AbuseIPDBClient
from connectors.urlscan import URLScanClient


def build_clients():
    load_dotenv()

    vt_api_key = os.getenv("VT_API_KEY")
    abuse_api_key = os.getenv("ABUSEIPDB_API_KEY")
    urlscan_api_key = os.getenv("URLSCAN_API_KEY")

    vt = VirusTotalClient(vt_api_key)
    abuse = AbuseIPDBClient(abuse_api_key)
    urlscan = URLScanClient(urlscan_api_key)

    return vt, abuse, urlscan