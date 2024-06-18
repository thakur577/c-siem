import json
import stix2
from datetime import datetime
import uuid
import os
import configparser
import logging
import requests
import warnings
warnings.filterwarnings('ignore')

# Global list to store UUIDs with their types
uuid_list = []

CATEGORY_MAPPING = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted"
}

# Global variables for data
data = {}
indicator_data = {}
input_indicator_id = None
ioc_value = None

def check_data(data):
    return bool(data)

def get_current_time():
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

def load_config():
    script_dir = os.path.dirname(os.path.realpath(__file__))
    config_file_path = os.path.join(script_dir, 'stix.ini')
    
    if not os.path.exists(config_file_path) or os.path.getsize(config_file_path) == 0:
        error_message = f'Error ({datetime.now()}): Configuration file "stix.ini" not found or empty.'
        with open(os.path.join(script_dir, 'error.txt'), 'w') as error_file:
            error_file.write(error_message)
        logging.error(error_message)
        exit()
    
    config = configparser.ConfigParser()
    config.read(config_file_path)
    return config

def setup_logging(config):
    LOGGING_LEVEL = config['logging']['LOGGING_LEVEL']
    logging.basicConfig(filename=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'stix_siem.log'), 
                        level=getattr(logging, LOGGING_LEVEL.upper(), logging.INFO),  
                        format='%(asctime)s - %(levelname)s - %(message)s')
    logging.info('Configuration file loaded successfully.')

def fetch_json_data(api_url, api_key):
    global data
    headers = {'api_key': api_key} 
    logging.info(f"Fetching data from API: {api_url}")
    response = requests.get(api_url.strip('"'), headers=headers, verify=False)  
    
    if response.status_code == 200:
        data = response.json()
        logging.info('JSON data fetched successfully from API.')
    else:
        logging.error(f'Failed to fetch data from API. Status code: {response.status_code}')
        exit()

def create_indicator(data, cdacsiem_uuid, report_data):
    global ioc_value
    report = 0
    if report_data:
        report = report_data.get('overall_risk_score', 0) * 10
    
    if check_data(data):
        indicator_uuid = f"indicator--{uuid.uuid4()}"
        uuid_list.append(indicator_uuid)
        
        ioc_type = data.get('ioc_type')
        ioc_value = data.get('ioc_value')
        valid_from = data.get('valid_from')
        valid_until = data.get('valid_until')
        
        if ioc_type == "IP":
            ipv4_addr = create_ipv4_addr(ioc_value)
            if ipv4_addr:
                indicator = stix2.Indicator(
                    id=indicator_uuid,
                    created_by_ref=cdacsiem_uuid,
                    name=ioc_value,
                    pattern_type="stix",
                    pattern=f"[ipv4-addr:value = '{ioc_value}']",
                    description="This indicator indicates an attacker's IP captured on CDACSIEM.",
                    valid_from=valid_from,
                    confidence=report
                )
                logging.info(f'Created Indicator: {indicator}')
                return indicator, ipv4_addr

        indicator = stix2.Indicator(
            id=indicator_uuid,
            created_by_ref=cdacsiem_uuid,
            name=ioc_value,
            pattern_type="stix",
            pattern=f"[ipv4-addr:value = '{ioc_value}']",
            description="This indicator indicates an attacker's IP captured on CDACSIEM.",
            valid_from=valid_from,
            confidence=report
        )

        logging.info(f'Created Indicator: {indicator}')
        return indicator, None

def create_course_of_action(course_of_action_data, cdacsiem_uuid):
    global ioc_value
    actions = [
        stix2.CourseOfAction(
            id=f"course-of-action--{uuid.uuid4()}",
            created_by_ref=cdacsiem_uuid,
            name=f"{ioc_value}", 
            x_cdacsiem_alert=coa.get('alert'),
            description=coa.get('remediation'),
            allow_custom=True
        )
        for coa in course_of_action_data if check_data(coa) and coa.get('remediation')
    ]
    logging.info(f'Created {len(actions)} CourseOfAction objects')
    return actions

def create_identity(identity_data):
    identities = []

    # Always create the CDACSIEM identity first
    cdacsiem_uuid = f"identity--{uuid.uuid4()}"
    cdacsiem_identity = stix2.Identity(id=cdacsiem_uuid, name="CDACSIEM")
    logging.info(f'Created Identity: {cdacsiem_identity}')
    identities.append(cdacsiem_identity)

    for identity_name in identity_data:
        if check_data(identity_name):
            identity_uuid = f"identity--{uuid.uuid4()}"
            uuid_list.append(identity_uuid)
            identity = stix2.Identity(id=identity_uuid, name=identity_name)
            logging.info(f'Created Identity: {identity}')
            identities.append(identity)

    return identities, cdacsiem_uuid

def create_infrastructure(infrastructure_data, cdacsiem_uuid):
    infrastructures = []
    for infra in infrastructure_data:
        if check_data(infra):
            infra_uuid = f"infrastructure--{uuid.uuid4()}"
            uuid_list.append(infra_uuid)
            
            infrastructure_type = infra['destination_ip'] if infra['host_group'] is None else infra['host_group'].lower().replace(" ", "-")
            description = infra.get('dest_name', '')
            
            infrastructure = stix2.Infrastructure(
                id=infra_uuid,
                created_by_ref=cdacsiem_uuid,
                infrastructure_types=[infrastructure_type],
                name=infra['destination_ip'],
                description=description  
            )
            
            infrastructures.append(infrastructure)
            logging.info(f'Created Infrastructure: {infrastructure}')
    return infrastructures

def create_location(location_data, cdacsiem_uuid):
    global ioc_value
    if check_data(location_data):
        location_uuid = f"location--{uuid.uuid4()}"
        uuid_list.append(location_uuid)
        location = stix2.Location(
            id=location_uuid,
            created_by_ref=cdacsiem_uuid,
            name=location_data["country_name"],
            latitude=location_data['latitude'],
            longitude=location_data['longitude'],
            country=location_data['country_code2'],
            x_timezone=location_data['timezone'],
            x_country=location_data["country_name"],
            x_ioc_value=ioc_value,
            allow_custom=True
        )
        logging.info(f'Created Location: {location}')
        return location

def create_note(note_data, cdacsiem_uuid):
    if check_data(note_data):
        note_uuid = f"note--{uuid.uuid4()}"
        uuid_list.append(note_uuid)
        note = stix2.Note(
            id=note_uuid,
            created_by_ref=cdacsiem_uuid,
            content=note_data['content'],
            authors=note_data['authors'],
            object_refs=[input_indicator_id]
        )
        logging.info(f'Created Note: {note}')
        return note

def create_ipv4_addr(ip):
    if ip:
        ipv4_addr_uuid = f"ipv4-addr--{uuid.uuid4()}"
        ipv4_addr = stix2.IPv4Address(
            id=ipv4_addr_uuid,
            value=ip
        )
        logging.info(f'Created IPv4 Address: {ipv4_addr}')
        return ipv4_addr
    return None

def create_observed_data(observed_data_list, ipv4_addr, cdacsiem_uuid):
    observed_data_objects = []
    for observed_data in observed_data_list:
        if check_data(observed_data):
            observed_data_uuid = f"observed-data--{uuid.uuid4()}"
            uuid_list.append(observed_data_uuid)
            
            first_observed = observed_data.get('first_observed')
            last_observed = observed_data.get('last_observed')
            number_observed = observed_data.get('number_observed')
            alert = observed_data.get('alert')
            
            observed_data_object = stix2.ObservedData(
                id=observed_data_uuid,
                created_by_ref=cdacsiem_uuid,
                name=alert,
                first_observed=first_observed,
                last_observed=last_observed,
                number_observed=number_observed,
                object_refs=[ipv4_addr.id], 
                allow_custom=True
            )
            observed_data_objects.append(observed_data_object)
            logging.info(f'Created ObservedData: {observed_data_object}')
    return observed_data_objects

def create_report(report_data, cdacsiem_uuid):
    global ioc_value
    reports = []
    if check_data(report_data):
        reputation_data = report_data.get('reputation', {})
        abuse_ipdb_data = reputation_data.get('abuse_ipdb', {})
        bgp_circl = reputation_data.get('bgp_circl', {})
        maltiverse = reputation_data.get('maltiverse', {})
        virus_total = reputation_data.get('virus_total', {})
        alien_vault_otx = reputation_data.get('alien_vault_otx', {})
        cdac_honeypot = reputation_data.get('cdac_honeypot', {})
        cdac_honeypot_2 = reputation_data.get('cdac_honeypot_2',{})
       
        # Process each source of reputation data
        for source, rep_data in reputation_data.items():
            report_uuid = f"report--{uuid.uuid4()}"
            
            if source == 'abuse_ipdb':
                report_uuid = f"report--{uuid.uuid4()}"
                categories = [report.get('categories', []) for report in abuse_ipdb_data.get('reports', [])]
                unique_categories = {CATEGORY_MAPPING[cat] for sublist in categories for cat in sublist if cat in CATEGORY_MAPPING}

                report_stix = stix2.Report(
                    id=report_uuid,
                    created_by_ref=cdacsiem_uuid,
                    name="AbuseIPDB",
                    labels=list(unique_categories),
                    published=abuse_ipdb_data.get('last_analysis_date', get_current_time()),
                    object_refs=[input_indicator_id],
                    description="This is AbuseIPDB's report",
                    x_ioc_value=f"{ioc_value}",
                    custom_properties={
                        'x_abuse_ipdb_report': {
                            'ipAddress': abuse_ipdb_data['ipAddress'],
                            'isPublic': abuse_ipdb_data['isPublic'],
                            'ipVersion': abuse_ipdb_data['ipVersion'],
                            'isWhitelisted': abuse_ipdb_data['isWhitelisted'],
                            'abuseConfidenceScore': abuse_ipdb_data['abuseConfidenceScore'],
                            'countryCode': abuse_ipdb_data['countryCode'],
                            'usageType': abuse_ipdb_data['usageType'],
                            'isp': abuse_ipdb_data['isp'],
                            'domain': abuse_ipdb_data['domain'],
                            'hostnames': abuse_ipdb_data['hostnames'],
                            'isTor': abuse_ipdb_data['isTor'],
                            'countryName': abuse_ipdb_data['countryName'],
                            'totalReports': abuse_ipdb_data['totalReports'],
                            'numDistinctUsers': abuse_ipdb_data['numDistinctUsers'],
                            'lastReportedAt': abuse_ipdb_data['lastReportedAt']
                        }
                    },
                    allow_custom=True
                )
                logging.info(f'Created Report for abuse_ipdb: {report_stix}')
                reports.append(report_stix)
            
            elif source == 'alien_vault_otx':
                report_uuid = f"report--{uuid.uuid4()}"
                pulse_info = rep_data['general'].get('pulse_info', {})
                pulses = pulse_info.get('pulses', [])
                pulse_tags = [pulse.get('tags', []) for pulse in pulses]
                unique_pulse_tags = {tag for sublist in pulse_tags for tag in sublist}
                pulse_names = {pulse.get('name') for pulse in pulses}  # Ensure unique pulse names

                report_stix = stix2.Report(
                    id=report_uuid,
                    created_by_ref=cdacsiem_uuid,
                    name=f"AlienVault OTX",
                    labels=list(unique_pulse_tags),
                    published=alien_vault_otx.get('last_analysis_date', get_current_time()),
                    object_refs=[input_indicator_id],
                    description="This is AlienVault's report",
                    x_ioc_value=f"{ioc_value}",
                    custom_properties={
                        'x_alien_vault_otx_report': {
                            'general': {
                                'whois': rep_data['general'].get('whois'),
                                'reputation': rep_data['general'].get('reputation'),
                                'indicator': rep_data['general'].get('indicator'),
                                'type': rep_data['general'].get('type'),
                                'type_title': rep_data['general'].get('type_title'),
                                'base_indicator': rep_data['general'].get('base_indicator'),
                                'pulse_info': {
                                    'pulse_names': list(pulse_names)  # Ensure unique pulse names are a list
                                }
                            }
                        }
                    },
                    allow_custom=True
                )
                logging.info(f'Created Report for alien_vault_otx: {report_stix}')
                reports.append(report_stix)

            elif source == 'bgp_circl':
                report_uuid = f"report--{uuid.uuid4()}"
                report_stix = stix2.Report(
                    id=report_uuid,
                    created_by_ref=cdacsiem_uuid,
                    name=f"BGP Circle",
                    published=bgp_circl.get('last_analysis_date', get_current_time()),
                    object_refs=[input_indicator_id],
                    description="This is BGP Circle's report",
                    x_ioc_value=f"{ioc_value}",
                    custom_properties={
                        'x_bgp_circle':
                        { 
                            'finalRank': bgp_circl['finalRank'],
                            'last_analysis_date': bgp_circl['last_analysis_date']
                        }
                    },
                    allow_custom=True
                )
                logging.info(f'Created Report for bgp_circl: {report_stix}')
                reports.append(report_stix)

            elif source == 'maltiverse':
                report_uuid = f"report--{uuid.uuid4()}"
                
                address = maltiverse.get('address', '')
                as_name = maltiverse.get('as_name', '')
                as_number = maltiverse.get('as_number', '')
                asn_cidr = maltiverse.get('asn_cidr', '')
                asn_country_code = maltiverse.get('asn_country_code', '')
                asn_date = maltiverse.get('asn_date', '')
                asn_registry = maltiverse.get('asn_registry', '')
                city = maltiverse.get('city', '')
                classification = maltiverse.get('classification', '')
                country_code = maltiverse.get('country_code', '')
                ip_addr = maltiverse.get('ip_addr', '')
                
                tags = set(maltiverse.get('tag', []))
                blacklist = maltiverse.get('blacklist', [])
                for entry in blacklist:
                    labels = entry.get('labels', [])
                    for label in labels:
                        tags.add(label)

                # Convert set to list
                tags = list(tags)

                # Construct the STIX report object
                report_stix = stix2.Report(
                    id=report_uuid,
                    created_by_ref=cdacsiem_uuid,
                    name=f"Maltiverse",
                    labels=tags,
                    published=maltiverse.get('last_analysis_date', get_current_time()),
                    object_refs=[input_indicator_id],
                    description="This is Maltiverse's report",
                    x_ioc_value=f"{ioc_value}",
                    custom_properties={
                        'x_maltiverse_report': {
                            'x_address': address,
                            'x_as_name': as_name,
                            'x_as_number': as_number,
                            'x_asn_cidr': asn_cidr,
                            'x_asn_country_code': asn_country_code,
                            'x_asn_date': asn_date,
                            'x_asn_registry': asn_registry,
                            'x_city': city,
                            'x_classification': classification,
                            'x_country_code': country_code,
                            'x_ip_addr': ip_addr,
                            'x_is_cdn': maltiverse.get('is_cdn', False),
                            'x_is_cnc': maltiverse.get('is_cnc', False),
                            'x_is_distributing_malware': maltiverse.get('is_distributing_malware', False),
                            'x_is_hosting': maltiverse.get('is_hosting', False),
                            'x_is_iot_threat': maltiverse.get('is_iot_threat', False),
                            'x_is_known_attacker': maltiverse.get('is_known_attacker', False),
                            'x_is_known_scanner': maltiverse.get('is_known_scanner', False),
                            'x_is_mining_pool': maltiverse.get('is_mining_pool', False),
                            'x_is_open_proxy': maltiverse.get('is_open_proxy', False),
                            'x_is_sinkhole': maltiverse.get('is_sinkhole', False),
                            'x_is_tor_node': maltiverse.get('is_tor_node', False),
                            'x_is_vpn_node': maltiverse.get('is_vpn_node', False)
                        }
                    },
                    allow_custom=True
                )

                logging.info(f'Created Report for maltiverse: {report_stix}')
                reports.append(report_stix)

            elif source == 'virus_total':
                report_uuid = f"report--{uuid.uuid4()}"
                attributes = virus_total['attributes']
                last_analysis_stats = attributes['last_analysis_stats']
                tags = attributes.get('tags', [])

                # Construct the STIX report object
                report_stix = stix2.Report(
                    id=report_uuid,
                    created_by_ref=cdacsiem_uuid,
                    name=f"VirusTotal",
                    labels=tags,
                    published=virus_total.get('last_analysis_date', get_current_time()),
                    object_refs=[input_indicator_id],
                    description="This is VirusTotal's report",
                    x_ioc_value=f"{ioc_value}",
                    custom_properties={
                        'x_virus_total_report': {
                            'x_last_analysis_stats': last_analysis_stats
                        }
                    },
                    allow_custom=True
                )

                logging.info(f'Created Report for virus_total: {report_stix}')
                reports.append(report_stix)
            
            elif source == 'cdac_honeypot':
                report_uuid = f"report--{uuid.uuid4()}"
                reports_data = rep_data['reports']

                organization_sectors = {report['organization_sector'] for report in reports_data}
                event_labels = {report['event_label'] for report in reports_data}
                organizations = {report['organization'] for report in reports_data}

                report_stix = stix2.Report(
                    id=report_uuid,
                    created_by_ref=cdacsiem_uuid,
                    name=f"CDAC Honeypot 1",
                    labels=list(event_labels),
                    published=cdac_honeypot.get('last_analysis_date', get_current_time()),
                    object_refs=[input_indicator_id],
                    description="This is CDAC Honeypot-1's report",
                    x_ioc_value=f"{ioc_value}",
                    custom_properties={
                        'x_cdac_honeypot_report': {
                            'x_organization_sectors': list(organization_sectors),
                            'x_organizations': list(organizations)
                        }
                    },
                    allow_custom=True
                )

                logging.info(f'Created Report for cdac_honeypot: {report_stix}')
                reports.append(report_stix)

            elif source == 'cdac_honeypot_2':
                report_uuid = f"report--{uuid.uuid4()}"
                reports_data = rep_data['reports']

                organization_sectors = {report['organization_sector'] for report in reports_data}
                event_labels = {report['event_label'] for report in reports_data}
                organizations = {report['organization'] for report in reports_data}

                report_stix = stix2.Report(
                    id=report_uuid,
                    created_by_ref=cdacsiem_uuid,
                    name=f"CDAC Honepot 2",
                    labels=list(event_labels),
                    published=cdac_honeypot_2.get('last_analysis_date', get_current_time()),
                    object_refs=[input_indicator_id],
                    description="This is CDAC Honeypot-2's report",
                    x_ioc_value=f"{ioc_value}",
                    custom_properties={
                        'x_cdac_honeypot_2_report': {
                            'x_organization_sectors': list(organization_sectors),
                            'x_organizations': list(organizations)
                        }
                    },
                    allow_custom=True
                )

                logging.info(f'Created Report for cdac_honeypot: {report_stix}')
                reports.append(report_stix)

    return reports

def create_vulnerability(vulnerability_data, cdacsiem_uuid):
    if check_data(vulnerability_data) and vulnerability_data['cves']:
        vulnerability_uuid = f"vulnerability--{uuid.uuid4()}"
        uuid_list.append(vulnerability_uuid)
        vulnerability = stix2.Vulnerability(
            id=vulnerability_uuid, 
            created_by_ref=cdacsiem_uuid,
            name=vulnerability_data['cves'][0]
        )
        logging.info(f'Created Vulnerability: {vulnerability}')
        return vulnerability

def create_attack_pattern(attack_pattern_data, cdacsiem_uuid, indicator_id):
    attack_patterns = []
    relationships = []

    for ap in attack_pattern_data:
        ap_uuid = f"attack-pattern--{uuid.uuid4()}"
        uuid_list.append(ap_uuid)

        attack_pattern = stix2.AttackPattern(
            id=ap_uuid,
            created_by_ref=cdacsiem_uuid,
            name=ap['title'],
            description=ap['description'],
            x_mitre_tactic_id=ap['tacticID'],
            allow_custom=True,
            external_references=[{
                "source_name": "mitre-attack",
                "external_id": ap['tacticID'],
                "url": ap['reference_url']
            }]
        )
        attack_patterns.append(attack_pattern)
        logging.info(f'Created AttackPattern: {attack_pattern}')

        # Create relationship between the indicator and the attack pattern
        relationship_uuid = f"relationship--{uuid.uuid4()}"
        relationship = stix2.Relationship(
            id=relationship_uuid,
            relationship_type="indicates",
            source_ref=indicator_id,
            target_ref=ap_uuid,
            created_by_ref=cdacsiem_uuid
        )
        relationships.append(relationship)
        logging.info(f'Created Relationship: {relationship}')

        # Create attack patterns for techniques within each attack pattern
        for technique in ap['techniques']:
            technique_uuid = f"attack-pattern--{uuid.uuid4()}"
            uuid_list.append(technique_uuid)

            technique_ap = stix2.AttackPattern(
                id=technique_uuid,
                created_by_ref=cdacsiem_uuid,
                name=technique['title'],
                description=technique['description'],
                x_mitre_technique_id=technique['techniqueID'],
                allow_custom=True,
                external_references=[{
                    "source_name": "mitre-attack",
                    "external_id": technique['techniqueID'],
                    "url": technique['reference_url']
                }]
            )
            attack_patterns.append(technique_ap)
            logging.info(f'Created Technique AttackPattern: {technique_ap}')

            # Create relationship between the parent attack pattern and the technique
            technique_relationship_uuid = f"relationship--{uuid.uuid4()}"
            technique_relationship = stix2.Relationship(
                id=technique_relationship_uuid,
                relationship_type="uses",
                source_ref=ap_uuid,
                target_ref=technique_uuid,
                created_by_ref=cdacsiem_uuid
            )
            relationships.append(technique_relationship)
            logging.info(f'Created Technique Relationship: {technique_relationship}')

    return attack_patterns, relationships

def create_relationships(bundle_objects):
    relationships = []
    identity_id = None

    # Find the identity with the specified name
    for obj in bundle_objects:
        if isinstance(obj, stix2.Identity) and obj['name'] == 'APPLIED INFOSEC GROUP':
            identity_id = obj['id']
            break

    # If the identity is found, find all infrastructures and create relationships
    if identity_id:
        for obj in bundle_objects:
            if isinstance(obj, stix2.Infrastructure) and 'applied-infosec-group' in obj['infrastructure_types']:
                relationship = stix2.Relationship(
                    id=f"relationship--{uuid.uuid4()}",
                    relationship_type="related-to",
                    source_ref=identity_id,
                    target_ref=obj.id,
                    created_by_ref=identity_id
                )
                relationships.append(relationship)
                logging.info(f'Created Relationship: {relationship}')

    for obj in bundle_objects:
        if isinstance(obj, stix2.Indicator):
            for target_obj in bundle_objects:
                if isinstance(target_obj, (stix2.Infrastructure)):
                    relationship = stix2.Relationship(
                        id=f"relationship--{uuid.uuid4()}",
                        relationship_type="indicates",
                        source_ref=obj.id,
                        target_ref=target_obj.id,
                        created_by_ref=obj.created_by_ref
                    )
                    relationships.append(relationship)
                    logging.info(f'Created Relationship: {relationship}')

                elif isinstance(target_obj, (stix2.Location, stix2.Identity)) and target_obj['name'] == 'APPLIED INFOSEC GROUP':
                    relationship = stix2.Relationship(
                        id=f"relationship--{uuid.uuid4()}",
                        relationship_type="related-to",
                        source_ref=obj.id,
                        target_ref=target_obj.id,
                        created_by_ref=obj.created_by_ref
                    )
                    relationships.append(relationship)
                    logging.info(f'Created Relationship: {relationship}')

        elif isinstance(obj, stix2.CourseOfAction):
            for target_obj in bundle_objects:
                if isinstance(target_obj, stix2.Indicator):
                    relationship = stix2.Relationship(
                        id=f"relationship--{uuid.uuid4()}",
                        relationship_type="mitigates",
                        source_ref=obj.id,
                        target_ref=target_obj.id,
                        created_by_ref=obj.created_by_ref
                    )
                    relationships.append(relationship)
                    logging.info(f'Created Relationship: {relationship}')

    return relationships

def main():
    global data
    global indicator_data
    global input_indicator_id
    report_stix = 0
    indicator_stix= 0
    ipv4_addr= 0
    identities= 0
    infrastructure_stix= 0
    location_stix= 0
    note_stix= 0
    vulnerability_stix= 0
    observed_data_stix= 0
    attack_pattern_stix= 0
    attack_pattern_relationships= 0
    course_of_action_stix=0

    config = load_config()
    setup_logging(config)
    
    api_url = config['api']['API_URL']
    api_key = config['api']['API_KEY']
    
    fetch_json_data(api_url, api_key)

    # Create the CDACSIEM identity first
    identities, cdacsiem_uuid = create_identity(data['data'].get('identity'))
    report_data = data['data'].get('report')
    if report_data:
        indicator_stix, ipv4_addr = create_indicator(data['data'].get('indicator'), cdacsiem_uuid, report_data)
    else:
        indicator_stix, ipv4_addr = create_indicator(data['data'].get('indicator'), cdacsiem_uuid, 0)
    input_indicator_id = indicator_stix.get("id")
    indicator_data = data['data'].get('indicator')

    if data['data'].get('course_of_action'):
        course_of_action_stix = create_course_of_action(data['data'].get('course_of_action'), cdacsiem_uuid)
    if data['data'].get('infrastructure'):
        infrastructure_stix = create_infrastructure(data['data'].get('infrastructure'), cdacsiem_uuid)
    if data['data'].get('location'):    
        location_stix = create_location(data['data'].get('location'), cdacsiem_uuid)
    if data['data'].get('note'):
        note_stix = create_note(data['data'].get('note'), cdacsiem_uuid)
    if data['data'].get('report'):
        report_stix = create_report(data['data'].get('report'), cdacsiem_uuid)
    if data['data'].get('vulnerability'):
        vulnerability_stix = create_vulnerability(data['data'].get('vulnerability'), cdacsiem_uuid)
    if data['data'].get('observed_data'):
        observed_data_stix = create_observed_data(data['data'].get('observed_data'), ipv4_addr, cdacsiem_uuid)
    if data['data'].get('attack_pattern'):
        attack_pattern_stix, attack_pattern_relationships = create_attack_pattern(data['data'].get('attack_pattern'), cdacsiem_uuid, input_indicator_id)
    
    bundle_objects = []
    if course_of_action_stix: bundle_objects.extend(course_of_action_stix)
    if indicator_stix: bundle_objects.append(indicator_stix)
    if ipv4_addr: bundle_objects.append(ipv4_addr)
    if identities: bundle_objects.extend(identities)
    if infrastructure_stix: bundle_objects.extend(infrastructure_stix)
    if location_stix: bundle_objects.append(location_stix)
    if note_stix: bundle_objects.append(note_stix)
    if report_stix: bundle_objects.extend(report_stix)
    if vulnerability_stix: bundle_objects.append(vulnerability_stix)
    if observed_data_stix: bundle_objects.extend(observed_data_stix)
    if attack_pattern_stix: bundle_objects.extend(attack_pattern_stix)
    if attack_pattern_relationships: bundle_objects.extend(attack_pattern_relationships)
    
    relationships = create_relationships(bundle_objects)
    bundle_objects.extend(relationships)
    
    bundle = stix2.Bundle(objects=[obj for obj in bundle_objects if obj is not None], allow_custom=True)
    logging.info(f'Created Bundle with {len(bundle_objects)} objects')

    with open('stix_bundle.json', 'w', encoding='utf-8') as file:
        file.write(bundle.serialize(pretty=True))
    
    logging.info('STIX bundle created successfully.')

if __name__ == "__main__":
    main()
