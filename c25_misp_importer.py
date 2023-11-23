import argparse
import logging
import re
import sys
import uuid
from datetime import datetime, timedelta
from typing import Optional, List

import pycountry
import requests
from pymisp import MISPEvent, ExpandedPyMISP, MISPOrganisation, MISPObject, MISPGalaxy, MISPGalaxyCluster

import settings

C25_QUERY_LIMIT = 50000
TLPS = 4

logging.basicConfig(level=logging.INFO)

# mapping between the MISP attributes type and the compatible Cluster25 indicator types.
mapping_out = {
    'domain': {'type': 'domain', 'to_ids': True},
    'asn': {'type': 'AS', 'to_ids': True},
    'email': {'type': 'email', 'to_ids': True},
    'filename': {'type': 'filename', 'to_ids': True},
    'md5': {'type': 'md5', 'to_ids': True},
    'sha1': {'type': 'sha1', 'to_ids': True},
    'sha256': {'type': 'sha256', 'to_ids': True},
    'ipv4': {'type': 'domain|ip', 'to_ids': True},
    'ipv6': {'type': 'domain|ip', 'to_ids': True},
    'url': {'type': 'url', 'to_ids': True},
    'cve': {'type': 'vulnerability', 'to_ids': True},
    'btcaddress': {'type': 'btc', 'to_ids': True},
    'xmraddress': {'type': 'xmr', 'to_ids': True},
    'ja3': {'type': 'ja3-fingerprint-md5', 'to_ids': True},
}

"""
Cluster25 CTI API Client
Class responsible for interacting with C25 CTI API.

"""


class Cluster25Client:
    def __init__(
            self,
            customer_id: Optional[str] = None,
            customer_key: Optional[str] = None,
            base_url: Optional[str] = None
    ):
        self.client_id = customer_id
        self.client_secret = customer_key
        self.base_url = base_url
        self.current_token = self._get_cluster25_token()
        self.headers = {"Authorization": f"Bearer {self.current_token}"}

    def _get_cluster25_token(
            self
    ) -> List[dict]:
        payload = {"client_id": self.client_id, "client_secret": self.client_secret}
        r = requests.post(url=f"{self.base_url}/token", json=payload, headers={"Content-Type": "application/json"})
        if r.status_code != 200:
            raise Exception(f"Unable to retrieve the token from C25 platform, status {r.status_code}")
        return r.json()["data"]["token"]

    def get_sectors(
            self
    ) -> List[dict]:
        r = requests.get(url=f"{self.base_url}/sectors", headers=self.headers)
        if r.status_code != 200:
            raise Exception(f"Unable to retrieve sectors from C25 platform, status {r.status_code}")
        return r.json()["data"]

    def get_mitre_ttps(
            self
    ) -> List[dict]:
        r = requests.get(url=f"{self.base_url}/mitre_ttps", headers=self.headers)
        if r.status_code != 200:
            raise Exception(f"Unable to retrieve mitre ttps from C25 platform, status {r.status_code}")
        return r.json()["data"]

    def get_contents(
            self,
            start_date: Optional[str] = None
    ) -> List[dict]:
        params = {"include_indicators": True, "limit": C25_QUERY_LIMIT, "start": start_date}
        logging.info(f"Retrieve contents {self.base_url}/contents {params=}")
        r = requests.get(url=f"{self.base_url}/contents", params=params, headers=self.headers)
        if r.status_code != 200:
            raise Exception(f"Unable to retrieve reports from C25 platform, status {r.status_code}")
        return r.json()["data"]

    def get_indicators(
            self,
            start_date: Optional[str] = None
    ) -> List[dict]:
        params = {"start": start_date, "limit": C25_QUERY_LIMIT}
        logging.info(f"Retrieve indicators {self.base_url}/indicators {params=}")
        r = requests.get(url=f"{self.base_url}/indicators", params=params, headers=self.headers)
        if r.status_code != 200:
            raise Exception(f"Unable to retrieve indicators from C25 platform, status {r.status_code}")
        return r.json()["data"]

    def get_actors(
            self
    ) -> List[dict]:
        r = requests.get(url=f"{self.base_url}/actors", headers=self.headers)
        if r.status_code != 200:
            raise Exception(f"Unable to retrieve actors from C25 platform, status {r.status_code}")
        return r.json()["data"]


"""
Cluster25 MISP Handler
Class responsible for handling Cluster25 entities in MISP instance.
"""


class Cluster25MISPHandler:
    def __init__(
            self
    ):
        self.misp_instance_url = settings.misp_url
        self.misp_api_key = settings.misp_auth_key
        self.misp_org_uuid = settings.misp_org_uuid
        self.c25_api_client = Cluster25Client(
            settings.cluster25_api_id, settings.cluster25_api_key, settings.cluster25_api_url
        )
        self.misp_client = ExpandedPyMISP(self.misp_instance_url, self.misp_api_key, False, False)
        self.existing_c25_reports_events = {}
        self.existing_c25_indicators_events = {}
        self.existing_c25_actors_events = {}

        self.existing_c25_sectors = self.c25_api_client.get_sectors()
        self.existing_c25_ttps = self.c25_api_client.get_mitre_ttps()
        self.existing_c25_techniques = []
        for tactic in self.existing_c25_ttps:
            self.existing_c25_techniques.extend(tactic.get('techniques'))

        self.threat_actor_galaxy = self.get_misp_galaxy("Threat Actor")
        self.sector_galaxy = self.get_misp_galaxy("Sector")
        self.malware_galaxy = self.get_misp_galaxy("Malpedia")
        self.mitre_galaxy = self.get_misp_galaxy("Attack Pattern")
        self.country_galaxy = self.get_misp_galaxy("Country")

        org = MISPOrganisation()
        org.uuid = self.misp_org_uuid
        self.organization = self.misp_client.get_organisation(org, True)

        logging.info("C25 Importer: initialisation complete.")

    def __get_c25_reports_events_from_misp(
            self
    ):
        events = self.misp_client.search_index(tags=[settings.reports_unique_tag])
        for event in events:
            if event.get('info', ""):
                self.existing_c25_reports_events[event.get('info')] = event
            else:
                logging.warning(f"Event {event} missing info field.")

    def __get_c25_indicators_events_from_misp(
            self
    ):
        events = self.misp_client.search(tags=[settings.indicators_unique_tag], pythonify=True)
        for event in events:
            if event.get('info'):
                self.existing_c25_indicators_events[event.get('info')] = event
            else:
                logging.warning(f"Event {event} missing info field.")

    def __get_c25_actors_events_from_misp(
            self
    ):
        events = self.misp_client.search(tags=[settings.actors_unique_tag], pythonify=True)
        for event in events:
            if event.get('info'):
                self.existing_c25_actors_events[event.get('info')] = event
            else:
                logging.warning(f"Event {event} missing info field.")

    def get_misp_galaxy(
            self,
            name: str
    ) -> MISPGalaxy:
        galaxies = self.misp_client.search_galaxy(name)
        for galaxy in galaxies:
            if galaxy.get('Galaxy').get('name') == name:
                return galaxy

    def get_misp_galaxy_cluster(
            self,
            galaxy: MISPGalaxy,
            name: str
    ) -> MISPGalaxyCluster:
        galaxy_clusters = self.misp_client.search_galaxy_clusters(galaxy, 'all', name)
        for cluster in galaxy_clusters:
            cluster_value = re.sub('\W+', '', str(cluster.get('GalaxyCluster', {'value': ''}).get('value', "")).lower())
            entry_name = re.sub('\W+', '', name.lower())
            if cluster_value == entry_name:
                return cluster

    def generate_misp_country_object(
            self,
            data: List[dict],
            misp_event_clusters: List[MISPGalaxyCluster]
    ) -> MISPObject:
        country_object = MISPObject('victim')
        for country_code in data:
            country = pycountry.countries.get(alpha_2=country_code)
            if country:
                country_cluster = self.get_misp_galaxy_cluster(self.country_galaxy, country.name)
                if country_cluster:
                    misp_event_clusters.append(country_cluster)
                country_object.add_attribute('regions', country.name)
            else:
                logging.info(f"Unable to match country code: {country_code}.")
        return country_object

    def generate_misp_sectors_object(
            self,
            data: List[dict],
            misp_event_clusters: List[MISPGalaxyCluster]
    ) -> MISPObject:
        sectors_object = MISPObject('c25_sectors')
        sectors_object.template_uuid = uuid.uuid4()
        sectors_object.description = f"c25_actor_identity"
        setattr(sectors_object, 'meta-category', 'network')
        for sector in data:
            for sec in self.existing_c25_sectors:
                if sector == sec.get('uid'):
                    sector_cluster = self.get_misp_galaxy_cluster(self.sector_galaxy, sec.get('name'))
                    if sector_cluster:
                        misp_event_clusters.append(sector_cluster)
                    sectors_object.add_attribute("name", **{'type': 'text', 'value': sec.get('name')})
        return sectors_object

    def generate_misp_attack_pattern_object(
            self,
            data: List[dict],
            misp_event_clusters: List[MISPGalaxyCluster]
    ) -> MISPObject:
        attack_pattern_object = MISPObject('attack-pattern')
        for index, technique in enumerate(data):
            for tech in self.existing_c25_techniques:
                if technique == tech.get('uid'):
                    attack_pattern_cluster = self.get_misp_galaxy_cluster(
                        self.mitre_galaxy, f"{tech.get('name')} - {tech.get('mitre_code')}"
                    )
                    if attack_pattern_cluster:
                        misp_event_clusters.append(attack_pattern_cluster)
                    attack_pattern_object.add_attribute(
                        "name",
                        **{'type': 'text', 'value': f"{tech.get('name')} - {tech.get('mitre_code')}"}
                    )
        return attack_pattern_object

    def __push_reports_events_to_misp(
            self,
            reports: List[dict]
    ):
        for report in reports:
            logging.info(f"C25 Import repoort: {report['title']}")
            event = MISPEvent()
            event.analysis = 2
            event.orgc = self.organization
            event.info = report.get('text', None)
            if self.existing_c25_reports_events.get(event.info):
                logging.info('Report already exists in MISP.')
                continue
            tlp = report.get('tlp')
            tlp_tag = ""
            if tlp.get('tlp'):
                tlp_color = tlp.get('tlp')
                if tlp_color == 'white':
                    # tlp 2.0 replaces 'white' with 'clear'
                    tlp_color = 'clear'
                tlp_tag = f"tlp:{tlp_color}"
            # mapping tlp to distribution:
            # tlp -> distribution
            # 0 -> 3 white/clear
            # 1 -> 2 green
            # 2 -> 1 amber
            # 3 -> 0 red
            if tlp.get('id'):
                event.distribution = TLPS - int(tlp.get('id')) - 1
            general_info = False
            misp_object_g = MISPObject('c25_generic_info')
            misp_object_g.template_uuid = uuid.uuid4()
            misp_object_g.description = 'c25_generic_info'
            setattr(misp_object_g, 'meta-category', 'network')

            clusters = []
            if report.get('analysis_type'):
                misp_object_g.add_attribute(
                    'analysis_type',
                    **{'type': 'text', 'value': report.get('analysis_type')}
                )
                general_info = True

            if report.get('confidence'):
                misp_object_g.add_attribute(
                    'confidence',
                    **{'type': 'text', 'value': report.get('confidence')}
                )
                general_info = True
            if report.get('type'):
                misp_object_g.add_attribute(
                    'type',
                    **{'type': 'text', 'value': report.get('type')}
                )
                general_info = True
            if report.get('created_dt'):
                event.set_date(report.get('created_dt'))
                misp_object_g.add_attribute(
                    'created_dt',
                    **{'type': 'text', 'value': report.get('created_dt')}
                )
                general_info = True
            if report.get('modified_dt'):
                misp_object_g.add_attribute(
                    'modified_dt',
                    **{'type': 'text', 'value': report.get('modified_dt')}
                )
                general_info = True
            if report.get('references'):
                misp_object_g.add_attribute(
                    'references',
                    **{'type': 'text', 'value': report.get('references')}
                )
                general_info = True
            if report.get('title'):
                misp_object_g.add_attribute(
                    'title',
                    **{'type': 'text', 'value': report.get('title')}
                )
                general_info = True
            if report.get('uid'):
                misp_object_g.add_attribute(
                    'uid',
                    **{'type': 'text', 'value': report.get('uid')}
                )
                general_info = True
            if general_info:
                event.add_object(misp_object_g)

            if report.get('actors'):
                self.__get_c25_actors_events_from_misp()

                for actor in report.get('actors'):
                    threat_actor_galaxy_cluster = self.get_misp_galaxy_cluster(
                        self.threat_actor_galaxy, actor.get('name')
                    )
                    if threat_actor_galaxy_cluster:
                        clusters.append(threat_actor_galaxy_cluster)

                    identity_object = MISPObject('c25_identity')
                    identity_object.template_uuid = uuid.uuid4()
                    identity_object.description = f"c25_actor_identity"
                    setattr(identity_object, 'meta-category', 'network')

                    identity_object.add_attribute(
                        "name",
                        **{'type': 'text', 'value': f"{actor.get('name')}"}
                    )
                    if actor.get('aliases'):
                        identity_object.add_attribute(
                            "aliases",
                            **{'type': 'text', 'value': f"{', '.join(actor.get('aliases'))}"}
                        )
                    origin_country = actor.get('origin_country')
                    if origin_country:
                        country = pycountry.countries.get(alpha_2=origin_country)
                        identity_object.add_attribute(
                            "origin_country",
                            **{'type': 'text', 'value': f"{country.name}"}
                        )

                    if self.existing_c25_actors_events.get(actor.get('name')):
                        identity_object.add_reference(
                            self.existing_c25_actors_events.get(actor.get('name')).get('uid'),
                            'related-to'
                        )
                    event.add_object(identity_object)

            if report.get('indicators'):
                for indicator in report.get('indicators'):
                    if mapping_out.get(indicator.get('type')):
                        attr_type, attr_value = mapping_out[indicator.get('type')].get('type'), indicator.get('value')
                        if attr_type and attr_value:
                            event.add_attribute(attr_type, attr_value)

            if report.get('rules'):
                for rule in report.get('rules'):
                    rule_type = rule.get('type')
                    if rule_type == 'snort':
                        rule_type = 'suricata'
                    rule_object = MISPObject(rule_type)
                    rule_object.add_attribute(rule_type, rule.get('text'))
                    if rule_type in ['yara', 'sigma']:
                        rule_object.add_attribute(f"{rule_type}-rule-name", rule.get('title'))
                    event.add_object(rule_object)

            if report.get('targeted_countries'):
                country_object = self.generate_misp_country_object(report.get('targeted_countries'), clusters)
                event.add_object(country_object)
            else:
                logging.info(f"Targeted countries missing from report {report.get('uid')}.")

            if report.get('techniques'):
                attack_pattern_object = self.generate_misp_attack_pattern_object(report.get('techniques'), clusters)
                event.add_object(attack_pattern_object)

            if report.get('targeted_sectors'):
                sectors_object = self.generate_misp_sectors_object(report.get('targeted_sectors'), clusters)
                event.add_object(sectors_object)

            try:
                logging.info("Adding report event to MISP.")
                if event.get('info'):
                    self.misp_client.add_event(event, True)
                    for tag in settings.reports_tags:
                        self.misp_client.tag(event, tag)
                    for cluster in clusters:
                        self.misp_client.tag(event, cluster.get('GalaxyCluster').get('tag_name'))
                    if tlp_tag:
                        self.misp_client.tag(event, tlp_tag)
            except:
                logging.warning("Could not add or tag event {}.".format(event.info))

    def __push_indicators_to_misp(
            self,
            indicators: List[dict],
            start_date: str
    ):
        event = MISPEvent()
        event.analysis = 2
        event.orgc = self.organization
        event.info = f"C25_Indicators_from_{start_date}"
        # unverified threat level
        event.threat_level_id = 4
        if self.existing_c25_indicators_events.get(event.info):
            logging.warning(f"Event for date {start_date} already imported. Checking for new indicators.")
            existing_attrs = [
                attribute.get('value')
                for attribute in self.existing_c25_indicators_events.get(event.info, None).Attribute
            ]
            update_event = False
            for indicator in indicators:
                if indicator.get('value') not in existing_attrs:
                    if mapping_out.get(indicator.get('type')):
                        attr_type, attr_value = mapping_out[indicator.get('type')].get('type'), indicator.get('value')
                        if attr_type and attr_value:
                            self.existing_c25_indicators_events.get(event.info).add_attribute(attr_type, attr_value)
                        update_event = True

            if update_event:
                self.misp_client.update_event(self.existing_c25_indicators_events.get(event.info))
        else:
            for indicator in indicators:
                if mapping_out.get(indicator.get('type')):
                    attr_type, attr_value = mapping_out[indicator.get('type')].get('type'), indicator.get('value')
                    if attr_type and attr_value:
                        event.add_attribute(attr_type, attr_value)
            try:
                logging.info("Adding indicator event to MISP.")
                self.misp_client.add_event(event, True)
                for tag in settings.indicators_tags:
                    self.misp_client.tag(event, tag)
            except:
                logging.warning("Could not add or tag event {}.".format(event.info))

    def __push_actors_to_misp(
            self,
            actors: List[dict]
    ):
        for actor in actors:
            actor_name = actor.get('name')
            if actor_name:
                if self.existing_c25_actors_events.get(actor_name):
                    logging.info(
                        f"Actor event already existed for {actor_name}, will delete and recreate with  updated info."
                    )
                    self.existing_c25_actors_events.get(actor_name)['RelatedEvent'] = []
                    self.misp_client.delete_event(self.existing_c25_actors_events.get(actor_name))
            event = MISPEvent()
            event.analysis = 2
            event.orgc = self.organization
            event.info = actor_name
            # unverified threat level
            event.threat_level_id = 4
            clusters = []

            threat_actor_galaxy_cluster = self.get_misp_galaxy_cluster(self.threat_actor_galaxy, actor.get('name'))
            if threat_actor_galaxy_cluster:
                clusters.append(threat_actor_galaxy_cluster)

            if actor.get('aliases'):
                aliases = MISPObject('organization')
                for alias in actor.get('aliases'):
                    aliases.add_attribute('alias', alias)
                event.add_object(aliases)
            else:
                logging.info(f"Actor {actor.get('uid')} missing field aliases.")

            if actor.get('description'):
                event.add_attribute('comment', actor.get('description'))
            else:
                logging.info(f"Actor {actor.get('uid')} missing field description.")

            had_timestamp = False
            timestamp_object = MISPObject('timestamp')

            if actor.get('first_seen'):
                timestamp_object.add_attribute('first-seen', actor.get('first_seen'))
                had_timestamp = True
            else:
                logging.info(f"Actor {actor.get('uid')} missing field first_seen.")

            if actor.get('last_seen'):
                timestamp_object.add_attribute('last-seen', actor.get('last_seen'))
                had_timestamp = True
            else:
                logging.info("Actor {} missing field last_seen.".format(actor.get('uid')))

            if had_timestamp:
                event.add_object(timestamp_object)

            if actor.get('origin_country'):
                event.add_attribute('nationality', actor.get('origin_country'))

            if actor.get('targeted_countries'):
                country_object = self.generate_misp_country_object(actor.get('targeted_countries'), clusters)
                event.add_object(country_object)
            else:
                logging.info(f"Targeted countries missing from actor {actor.get('uid')}.")

            general_info = False
            misp_object_g = MISPObject('c25_generic_info')
            misp_object_g.template_uuid = uuid.uuid4()
            misp_object_g.description = 'c25_generic_info'
            setattr(misp_object_g, 'meta-category', 'network')

            if actor.get('state_sponsored'):
                misp_object_g.add_attribute(
                    'state_sponsored',
                    **{'type': 'text', 'value': actor.get('state_sponsored')}
                )
                general_info = True

            if actor.get('motivations'):
                misp_object_g.add_attribute(
                    'motivations',
                    **{'type': 'text', 'value': ', '.join(actor.get('motivations'))}
                )

                general_info = True

            if actor.get('associated_malwares'):
                for malware in actor.get('associated_malwares'):
                    malware_cluster = self.get_misp_galaxy_cluster(self.malware_galaxy, malware)
                    if malware_cluster:
                        clusters.append(malware_cluster)
                misp_object_g.add_attribute(
                    'associated_malwares',
                    **{'type': 'text', 'value': ', '.join(actor.get('associated_malwares'))}
                )
                general_info = True

            if general_info:
                event.add_object(misp_object_g)

            if actor.get('techniques'):
                attack_pattern_object = self.generate_misp_attack_pattern_object(actor.get('techniques'), clusters)
                event.add_object(attack_pattern_object)

            if actor.get('targeted_sectors'):
                sectors_object = self.generate_misp_sectors_object(actor.get('targeted_sectors'), clusters)
                event.add_object(sectors_object)

            try:
                logging.info("Adding actor event to MISP.")
                if event.get('info'):
                    self.misp_client.add_event(event, True)
                    for tag in settings.actor_tags:
                        self.misp_client.tag(event, tag)
                    for cluster in clusters:
                        self.misp_client.tag(event, cluster.get('GalaxyCluster').get('tag_name'))
            except:
                logging.warning("Could not add or tag event {}.".format(event.info))

    def process_indicators(
            self,
            start_date: str
    ):
        logging.info("Started getting indicators from Cluster25 Cyber Threat Intel API and pushing them in MISP.")
        indicators = self.c25_api_client.get_indicators(start_date=start_date)
        logging.info(f"Got {len(indicators)} indicators from the Cluster25 Cyber Threat Intel API.")

        if len(indicators) == 0:
            logging.warning("No indicators found.")
        else:
            self.__get_c25_indicators_events_from_misp()
            self.__push_indicators_to_misp(indicators, start_date)

        logging.info("Finished getting indicators from Cluster25 Cyber Threat Intel API and pushing them in MISP.")

    def process_reports(
            self,
            start_date: Optional[str] = None
    ):
        # demo user is limited to start date of 14 days ago.
        logging.info("Started getting reports from Cluster25 Cyber Threat Intel API and pushing them in MISP.")

        reports = self.c25_api_client.get_contents(start_date=start_date)
        logging.info(f"Got {len(reports)} reports from the Cluster25 Cyber Threat Intel API.")

        if len(reports) == 0:
            logging.warning("No reports found.")
        else:
            self.__get_c25_reports_events_from_misp()
            self.__push_reports_events_to_misp(reports)

        logging.info("Finished getting reports from Cluster25 Cyber Threat Intel API and pushing them in MISP.")

    def process_actors(
            self
    ):
        logging.info("Started getting actors from Cluster25 Cyber Threat Intel API and pushing them in MISP.")
        actors = self.c25_api_client.get_actors()
        logging.info(f"Got {len(actors)} actors from the Cluster25 Cyber Threat Intel API.")

        if len(actors) == 0:
            logging.warning("No actors found.")
        else:
            self.__get_c25_actors_events_from_misp()
            self.__push_actors_to_misp(actors)

        logging.info("Finished getting actors from Cluster25 Cyber Threat Intel API and pushing them in MISP.")

    def clean_c25_events(
            self,
            tags: List[str],
            max_age: Optional[int] = None
    ):
        if max_age:
            events = self.misp_client.search(tags=tags, date_from=(datetime.now() - timedelta(days=int(max_age))))
        else:
            events = self.misp_client.search(tags=tags)
        if events:
            logging.info(f"Will delete {len(events)} events with the following tags: {tags}")
        else:
            logging.info(f"No events to delete found with the following tags: {tags}")
        for event in events:
            self.misp_client.delete_event(event)

        logging.info("Finished cleaning up Cluster25 related events from MISP.")


def main():
    parser = argparse.ArgumentParser(
        description="Tool used to import reports, indicators and actors from Cluster25 CTI API into a MISP instance."
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Set this to import reports,  actors and indicators from C25 CTI"
    )
    parser.add_argument(
        "--reports",
        action="store_true",
        help="Set this to import only reports from C25 CTI"
    )
    parser.add_argument(
        "--reports-start-date",
        default=None,
        help="Set this to filter reports detected from a specified start date in format: dd/mm/yyyy hh:mm:ss. "
             "If not set if will look for reports from 1 month ago."
    )
    parser.add_argument(
        "--indicators",
        action="store_true",
        help="Set this to import only indicators from C25 CTI"
    )
    parser.add_argument(
        "--indicators-start-date",
        default=None,
        help="Set this to filter indicators detected from a specified start date in format: dd/mm/yyyy hh:mm:ss. "
             "If not set if will look for indicators from 1 week ago.")
    parser.add_argument(
        "--actors",
        action="store_true",
        help="Set this to import only actors from C25 CTI"
    )
    parser.add_argument(
        "--clean-all",
        action="store_true",
        help="Set this to delete reports, actors and indicators C25 events."
    )
    parser.add_argument(
        "--clean-reports",
        action="store_true",
        help="Set this to delete C25 reports events."
    )
    parser.add_argument(
        "--clean-actors",
        action="store_true",
        help="Set this to delete C25 actors events."
    )
    parser.add_argument(
        "--clean-indicators",
        action="store_true",
        help="Set this to delete C25 indicators events."
    )
    parser.add_argument(
        "--max-event-age",
        default=None,
        help="Max age of the events to delete, in days."
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Set this to enable info logging"
    )

    args = parser.parse_args()
    if args.info:
        logging.basicConfig(level=logging.INFO)

    c25_misp_importer = Cluster25MISPHandler()
    indicators_start_date = (datetime.now() - timedelta(days=7)).isoformat()
    reports_start_date = (datetime.now() - timedelta(days=30)).isoformat()

    try:
        if args.clean_all:
            tags = [settings.reports_unique_tag, settings.actors_unique_tag, settings.indicators_unique_tag]
            c25_misp_importer.clean_c25_events(tags, args.max_event_age)
        if args.clean_actors:
            tags = settings.actors_unique_tag
            c25_misp_importer.clean_c25_events(tags, args.max_event_age)
        if args.clean_indicators:
            tags = settings.indicators_unique_tag
            c25_misp_importer.clean_c25_events(tags, args.max_event_age)
        if args.clean_reports:
            tags = settings.reports_unique_tag
            c25_misp_importer.clean_c25_events(tags, args.max_event_age)

        if args.indicators_start_date:
            try:
                indicators_start_date = datetime.strptime(args.indicators_start_date, '%d/%m/%Y %H:%M:%S').isoformat()
            except ValueError:
                logging.error("Invalid date format")

        if args.reports_start_date:
            try:
                reports_start_date = datetime.strptime(args.reports_start_date, '%d/%m/%Y %H:%M:%S').isoformat()
            except ValueError:
                logging.error("Invalid date format")

        if args.all:
            c25_misp_importer.process_actors()
            c25_misp_importer.process_indicators(indicators_start_date)
            c25_misp_importer.process_reports(reports_start_date)
        else:
            if args.reports:
                c25_misp_importer.process_reports(reports_start_date)
            if args.actors:
                c25_misp_importer.process_actors()
            if args.indicators:
                c25_misp_importer.process_indicators(indicators_start_date)

    except Exception as e:
        logging.exception(e)
        sys.exit(1)


if __name__ == '__main__':
    main()
