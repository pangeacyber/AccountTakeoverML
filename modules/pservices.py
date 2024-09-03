from datetime import datetime, timedelta

import pytz
from pangea.config import PangeaConfig
from pangea.response import PangeaResponse
from pangea.services import Audit, IpIntel, UserIntel, Vault
from pangea.services.audit.audit import SearchOutput

from vaultids import *


class pservices:

    def __init__(self, url, VAULT_TOKEN):
        self.ipintel = None
        self.userintel = None
        self.vault = Vault(VAULT_TOKEN, config=PangeaConfig(domain=url))
        self.audit_pangeaauth = None

    def audit_pangeaauth_init(self):
        audit_pangeaauth_token = self.vault.get(pangea_vault_audit_id).result.current_version.secret
        audit_pangeaauth_domain = "aws.us.pangea.cloud"
        config = PangeaConfig(domain=audit_pangeaauth_domain)
        self.audit_pangeaauth = Audit(audit_pangeaauth_token, config=config)

    def ip_intel_init(self):
        ipinteltoken = self.vault.get(pangea_vault_ipintel_id).result.current_version.secret
        ipinteldomain = "aws.us.pangea.cloud"
        self.ipintel = IpIntel(ipinteltoken, config=PangeaConfig(domain=ipinteldomain))

    def user_intel_init(self):
        userinteltoken = self.vault.get(pangea_vault_userintel_id).result.current_version.secret
        userinteldomain = "aws.us.pangea.cloud"
        self.userintel = UserIntel(userinteltoken, config=PangeaConfig(domain=userinteldomain))

    def get_user_intel(self, useremail: str) -> bool:
        if not self.userintel:
            self.user_intel_init()
        startday = "30d"
        endday = "0d"
        userintelresponse = self.userintel.user_breached(email=useremail, provider="spycloud", verbose=True, raw=False, start=startday, end=endday)

        return userintelresponse.result.data.found_in_breach

    def ip_intel(self, IPs):
        if not self.ipintel:
            self.ip_intel_init()
        print (f"checking IP {IPs} against IP intel")

        ipresponse = self.ipintel.reputation(ip=IPs, provider="crowdstrike", verbose=True, raw=True)
        proxyresponse = self.ipintel.is_proxy(ip=IPs,provider="digitalelement", verbose=True, raw=True)
        vpnresponse = self.ipintel.is_vpn(ip=IPs,provider="digitalelement", verbose=True, raw=True)
        georesponse = self.ipintel.geolocate(ip=IPs,provider="digitalelement", verbose=True, raw=True)

        ip_properties = {
            'ip': 'Malicious' if ipresponse.result.data.score > 1 else 'Safe',
            'proxy': 'Yes' if proxyresponse.result.data.is_proxy else 'No',
            'vpn': 'Yes' if vpnresponse.result.data.is_vpn else 'No',
            'geo_location': f"Country: {georesponse.result.data.country}, City: {georesponse.result.data.city}, Latitude: {georesponse.result.data.latitude}, Longitude: {georesponse.result.data.longitude}",
        }
        return ip_properties


    def get_PangeaAuthLogs(self, maxresults=1000):
        if not self.audit_pangeaauth:
            self.audit_pangeaauth_init()

        list=[]
        page_size = 100

        # Subtract 15 days from the current time
        ts_start = (datetime.now(pytz.utc) - timedelta(days=15)).isoformat()
        ts_end = datetime.now(pytz.utc).isoformat()

        search_res: PangeaResponse[SearchOutput] = self.audit_pangeaauth.search(query="service_name:AuthN AND action:login", verify_events=False , max_results=maxresults, order="desc", order_by="timestamp", verbose=False, limit=page_size, start=ts_start, end=ts_end)
        for event in search_res.result.events:
            envelope_event = event.envelope.event
            list.append(envelope_event)
        result_id = search_res.result.id
        count = search_res.result.count

        print(f"Search Request ID: {search_res.request_id}, Success: {search_res.status}, Results: {count}")
        offset = 0

        while offset < count:
            offset += page_size

            if offset < count:
                search_res = self.audit_pangeaauth.results(
                    id=result_id, limit=page_size, offset=offset
                )
                for event in search_res.result.events:
                    envelope_event = event.envelope.event
                    list.append(envelope_event)
        print(f"size of list: {len(list)}")
        return list
