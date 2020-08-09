import copy
import requests
import yaml
import argparse
import os
import sys
import logging
import logging.handlers
import re
import random
import CloudFlare
import xml.etree.ElementTree as ElementTree
from datetime import datetime, timedelta
from collections import namedtuple
from pathlib import Path
from slack import WebhookClient
from slack.errors import SlackApiError


start_time = datetime.now()
Pattern = namedtuple("Pattern", [
    "router_value",
    "validate_ip"
])

pattern = Pattern(
    re.compile(r"(^|\W?)Host\(`(.*?)`\)", re.IGNORECASE),
    re.compile(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"
               r"([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
               re.IGNORECASE)
)

config = None
storage = None
sl_msg = {'attachments': []}
cf = None
zone_id = None

__version__ = "1.0.0"
__author__ = "rxbn (2020)"


def parse_arguments():
    parser = argparse.ArgumentParser(
        formatter_class=(
            lambda prog: argparse.HelpFormatter(prog, max_help_position=26)),
        description="""
    This Python script creates and deletes Cloudflare DNS records according to Traefik v2.0 host definitions.
    It also updates the A record if your public IP changes.
    """)

    parser.add_argument("-v", "--version",
                        action="version",
                        version=f"cloudflaredyndns version "
                                f"{__version__}\nby {__author__}")
    parser.add_argument("-c",
                        default="config.yml",
                        dest="conf",
                        metavar="PATH",
                        help="path to configuration file "
                             "(default: %(default)s)")
    parser.add_argument("-p", "--print-config",
                        action="store_true",
                        default=None,
                        dest="printconfig",
                        help="Print loaded config")
    parser.add_argument("-f", "--force-sync",
                        action="store_true",
                        default=None,
                        dest="forcesync",
                        help="Force sync with Cloudflare")
    parser.add_argument("-d", "--debug",
                        action="store_true",
                        default=None,
                        dest="debug",
                        help="Set log level to debug")

    return parser.parse_args()


def load_config(args):
    global config
    if not os.path.exists(args.conf):
        raise FileNotFoundError("Config file not found")
    with open(args.conf) as stream:
        try:
            config = yaml.safe_load(stream)
            if args.printconfig:
                print(config)
        except yaml.YAMLError as e:
            print(f"Unable to load config: {e}")

    config['traefik']['ignoredHosts'] = config['traefik'].get('ignoredHosts', [])
    config['cloudflare']['ignoredHosts'] = config['cloudflare'].get('ignoredHosts', [])
    config['cloudflare']['requestTimeout'] = config['cloudflare'].get('requestTimeout', 5)
    config['cloudflare']['ttl'] = config['cloudflare']['ttl'] if not config['cloudflare']['proxied'] else 1


def load_storage():
    global storage
    if not os.path.exists(path=config['general']['storage']):
        logging.info(f"Storage file {config['general']['storage']} not found. Creating a new one...")
        try:
            Path(config['general']['storage']).touch()
        except Exception as e:
            raise Exception(f"Cannot create storage file {config['general']['storage']}: {e}")

    storage = {'ip': None, 'dnsRecords': [], 'lastUpdate': None}
    if os.path.getsize(config['general']['storage']) > 0:
        try:
            with open(file=config['general']['storage'], mode="r") as data:
                storage = yaml.safe_load(data)
        except Exception as e:
            raise Exception(f"Cannot read storage file {config['general']['storage']}: {e}")


def save_storage():
    try:
        with open(file=config['general']['storage'], mode="w") as file:
            yaml.safe_dump(storage, file, sort_keys=True)
            logging.debug(f"Updated storage file {config['general']['storage']}")
    except Exception as e:
        raise Exception(f"Cannot save storage file {config['general']['storage']}: {e}")


def setup_logger(args):
    default_format = logging.Formatter(
        "%(asctime)s [%(levelname)-7.7s] %(message)s")
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if config['general']['debug'] or args.debug else logging.INFO)
    console_logger = logging.StreamHandler(sys.stdout)
    console_logger.setFormatter(default_format)
    root_logger.addHandler(console_logger)


def get_ip():
    ip = None

    def _get_ip_fritzbox():
        url = f"http://{config['general']['fritzbox']['ip']}:49000/igdupnp/control/WANIPConn1"
        headers = {
            'User-agent': 'cfdyndns',
            'Content-Type': 'text/xml',
            'Soapaction': 'urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress'
        }
        data = '''<?xml version='1.0' encoding='utf-8'?> <s:Envelope 
        s:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/' 
        xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'> <s:Body> <u:GetExternalIPAddress 
        xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1" /> </s:Body> </s:Envelope> '''
        response = requests.post(url=url, data=data, headers=headers)

        tree = ElementTree.fromstring(response.content)

        current_ip = tree.findall(
            ".//{urn:schemas-upnp-org:service:WANIPConnection:1}GetExternalIPAddressResponse/NewExternalIPAddress")

        current_ip = current_ip[0].text

        if not pattern.validate_ip.match(string=current_ip):
            raise Exception(f"Unable to get current public IP from fritzbox {config['general']['fritzbox']['ip']}."
                            f" IP {current_ip} did not match")
        logging.debug(f"Got IP {current_ip} from fritzbox {config['general']['fritzbox']['ip']}")
        return current_ip

    def _get_ip_provider():
        random.shuffle(config['general']['ipProviders']['providers'])
        for provider in config['general']['ipProviders']['providers']:
            try:
                response = requests.get(url=provider)
            except Exception as e:
                logging.warning(f"Unable to get current public IP from {provider}: {e}")
                continue
            else:
                if response.status_code != 200:
                    logging.warning(f"Unable to get current public IP from {provider}: {response.status_code}")
                    continue
                current_ip = response.text.strip()
            if not pattern.validate_ip.match(string=current_ip):
                logging.warning(f"Unable to get current public IP from {provider}. IP {current_ip} did not match")
                continue
            logging.debug(f"Got IP {current_ip}, used provider {provider}")
            break
        else:
            raise Exception("Unable to get current public IP. Tried all providers but either "
                            "got no response or an invalid IP.")

        return current_ip

    if config['general']['fritzbox']['enabled']:
        try:
            ip = _get_ip_fritzbox()
        except Exception as e:
            logging.warning(f"Unable to get public IP using fritzbox: {e}")

    if config['general']['ipProviders']['enabled'] and ip is None:
        try:
            ip = _get_ip_provider()
        except Exception as e:
            logging.warning(f"Unable to get public IP using ipProviders: {e}")

    if ip is None:
        raise Exception(f"Unable to get current public IP.")

    if storage['ip'] != ip and storage['ip'] is not None or any(record for record in storage['dnsRecords'] if
                                                                record['content'] != ip and
                                                                record['type'].lower() == "a"):
        try:
            update_ip(new_ip=ip)
        except Exception as e:
            logging.error(f"Unable to update IP: {e}")
            if config['slack']['enabled']:
                slack_message(color='danger', message=f"Unable to update IP: {e}")
        else:
            storage['ip'] = ip

    if storage['ip'] is None:
        storage['ip'] = ip


def update_ip(new_ip):
    root_record = [record for record in storage['dnsRecords'] if record['type'].lower() == "a"]

    for record in root_record:
        try:
            cf.zones.dns_records.put(zone_id, record['id'],
                                     data={'type': 'A',
                                           'name': record['name'],
                                           'content': new_ip,
                                           'proxied': config['cloudflare']['proxied'],
                                           'ttl': config['cloudflare']['ttl']})
        except Exception as e:
            logging.error(e)
            if config['slack']['enabled']:
                slack_message(color='danger', message=e)
            continue
        else:
            record['content'] = new_ip

        logging.info(f"Updated IP ({new_ip}) of DNS record {record['name']}")
        if config['slack']['enabled']:
            slack_message(color='good', message=f"Updated IP ({new_ip}) of DNS record {record['name']}")


def get_cloudflare_zone_id():
    zones = cf.zones.get(params={'name': config['general']['rootDomain']})
    zone_id = zones[0]['id']
    return zone_id


def get_cloudflare_dns():
    previous_records = copy.deepcopy(storage['dnsRecords'])
    storage['dnsRecords'] = []

    try:
        records = cf.zones.dns_records.get(zone_id)
    except Exception as e:
        raise Exception(e)

    for record in records:
        if record['type'].lower() != "cname" and record['type'].lower() != "a":
            continue
        if any(domain in record['name'] for domain in config['cloudflare']['ignoredHosts']):
            logging.debug(f"Ignoring DNS record {record['name']}")
            continue

        for previous_record in previous_records:
            if previous_record['name'] != record['name']:
                continue

            if previous_record['skips'] == config['general']['deleteSkips']:
                continue

            record = {'name': record['name'], 'id': record['id'], 'type': record['type'],
                      'content': record['content'],
                      'skips': previous_record['skips']}
            break
        else:
            record = {'name': record['name'], 'id': record['id'], 'type': record['type'],
                      'content': record['content'],
                      'skips': config['general']['deleteSkips']}

        storage['dnsRecords'].append(record)

    storage['lastUpdate'] = datetime.now().strftime('%Y-%m-%d %H:%M')


def get_treafik_dns():
    traefik_url = f"{config['traefik']['url']}/api/http/routers"
    traefik_hosts = []

    try:
        response = requests.get(url=traefik_url)
    except Exception as e:
        raise Exception(f"Unable to get Traefik DNS records: {e}")
    else:
        if response.status_code != 200:
            raise Exception(f"Unable to get Traefik DNS records: Status code is {response.status_code}")

    dns_records = response.json()

    for host in dns_records:
        router_rules = pattern.router_value.finditer(string=host['rule'])
        for _rule in router_rules:
            rule_name = _rule.group(_rule.lastindex)
            if any(domain in rule_name for domain in config['traefik']['ignoredHosts']):
                logging.debug(f"Ignoring host {rule_name}")
                continue
            traefik_hosts.append(rule_name)

    return traefik_hosts


def add_dns_record(traefik_hosts):
    for record in traefik_hosts:
        if not any(r for r in storage['dnsRecords'] if r['type'].lower() == config['cloudflare']['recordType'].lower()
                   and r['name'] == record):
            try:
                dns_record = cf.zones.dns_records.post(zone_id,
                                                       data={'name': record,
                                                             'content': config['general']['rootDomain']
                                                             if config['cloudflare']['recordType'].lower() == "cname"
                                                             else storage['ip'],
                                                             'type': config['cloudflare']['recordType'],
                                                             'proxied': config['cloudflare']['proxied'],
                                                             'ttl': config['cloudflare']['ttl']})
            except Exception as e:
                logging.error(e)
                if config['slack']['enabled']:
                    slack_message(color='danger', message=e)
                continue

            dns_record = {'name': dns_record['name'], 'id': dns_record['id'], 'type': dns_record['type'],
                          'skips': config['general']['deleteSkips'], 'content': dns_record['content']}

            storage['dnsRecords'].append(dns_record)
            logging.info(f"Created DNS record {record}")
            if config['slack']['enabled']:
                slack_message(color='good', message=f"Created DNS record {record}")


def remove_dns_record(traefik_hosts):
    records = [record for record in storage['dnsRecords'] if record['type'].lower() ==
               config['cloudflare']['recordType'].lower() and record['name'] != config['general']['rootDomain']]
    for record in reversed(records):
        for host in traefik_hosts:
            if record['name'] != host:
                continue
            if record['skips'] != config['general']['deleteSkips']:
                logging.info(f"Host {record['name']} is alive again")
                record['skips'] = config['general']['deleteSkips']
            break
        else:
            if record['skips'] > 0:
                record['skips'] -= 1
                logging.info(f"Skip deleting DNS record {record['name']}. "
                             f"Skip {config['general']['deleteSkips'] - record['skips']}/"
                             f"{config['general']['deleteSkips']}")
                continue

            try:
                cf.zones.dns_records.delete(zone_id, record['id'])
            except Exception as e:
                logging.error(e)
                if config['slack']['enabled']:
                    slack_message(color='danger', message=e)
                continue

            storage['dnsRecords'].remove(record)
            logging.info(f"Removed DNS record {record['name']}")
            if config['slack']['enabled']:
                slack_message(color='good', message=f"Removed DNS record {record['name']}")


def slack_message(color, message):
    sl_msg['attachments'].append({'text': str(message), 'color': color})


def send_slack():

    try:
        slack_client = WebhookClient(url=config['slack']['webhook'])
        slack_client.send_dict(sl_msg)
    except SlackApiError as e:
        logging.critical(f"unable to send slack notification. {e.response['error']}")
        sys.exit(1)


def main():
    try:
        args = parse_arguments()
    except Exception as e:
        sys.stderr.write(f"Error while parsing arguments: {e}")
        sys.exit(1)

    try:
        load_config(args)
    except Exception as e:
        sys.stderr.write(f"Unable to load confg: {e}")
        sys.exit(1)

    try:
        setup_logger(args)
    except Exception as e:
        sys.stderr.write(f"Unexpected exception while setting up logging: {e}")
        sys.exit(1)

    logging.info(f"Running script... Version {__version__}. Created by {__author__}.")

    global cf
    cf = CloudFlare.CloudFlare(email=config['cloudflare']['email'], token=config['cloudflare']['apiKey'])
    global zone_id
    zone_id = get_cloudflare_zone_id()

    global sl_msg

    try:
        load_storage()
    except Exception as e:
        logging.error(e)
        if config['slack']['enabled']:
            slack_message(color='danger', message=e)
            send_slack()
        sys.exit(1)

    if (storage['lastUpdate'] is None or
            datetime.strptime(storage['lastUpdate'], '%Y-%m-%d %H:%M') < datetime.now()
            - timedelta(minutes=config['cloudflare']['syncInterval']) or args.forcesync):
        logging.info("Syncing with Cloudflare" if not storage['lastUpdate'] else "Manually triggered Cloudflare sync"
                     if args.forcesync else f"Last sync with Cloudflare longer than "
                                            f"{config['cloudflare']['syncInterval']} "
                                            f"minutes ago. Syncing now...")
        try:
            get_cloudflare_dns()
        except Exception as e:
            logging.error(e)
            if config['slack']['enabled']:
                slack_message(color='danger', message=e)
                send_slack()
            sys.exit(1)

    try:
        traefik_hosts = get_treafik_dns()
    except Exception as e:
        logging.error(f"Unable to get Traefik hosts: {e}")
        if config['slack']['enabled']:
            slack_message(color='danger', message=f"Unable to get Traefik hosts: {e}")
            send_slack()
        sys.exit(1)

    try:
        get_ip()
    except Exception as e:
        logging.error(e)
        if config['slack']['enabled']:
            slack_message(color='danger', message=e)
            send_slack()
        sys.exit(1)

    if not any(record for record in storage['dnsRecords'] if record['name'] == config['general']['rootDomain']):
        try:
            dns_record = cf.zones.dns_records.post(zone_id,
                                                   data={'name': config['general']['rootDomain'],
                                                         'content': storage['ip'],
                                                         'type': 'A',
                                                         'proxied': config['cloudflare']['proxied'],
                                                         'ttl': config['cloudflare']['ttl']})

        except Exception as e:
            logging.error(f"Unable to create root DNS record: {e}")
            if config['slack']['enabled']:
                slack_message(color='danger', message=f"Unable to create root DNS record: {e}")
        else:
            record = {'name': dns_record['name'], 'id': dns_record['id'], 'type': dns_record['type'],
                      'content': dns_record['content'],
                      'skips': config['general']['deleteSkips']}
            logging.info(f"Created root DNS record {config['general']['rootDomain']}")
            if config['slack']['enabled']:
                slack_message(color='good', message=f"Created root DNS record {config['general']['rootDomain']}")
            storage['dnsRecords'].append(record)

    try:
        add_dns_record(traefik_hosts)
    except Exception as e:
        logging.error(e)

    if config['general']['enableDelete']:
        try:
            remove_dns_record(traefik_hosts)
        except Exception as e:
            logging.error(e)

    try:
        save_storage()
    except Exception as e:
        logging.error(e)
        if config['slack']['enabled']:
            slack_message(color='danger', message=e)
        sys.exit(1)

    if config['slack']['enabled'] and sl_msg['attachments'] != []:
        send_slack()

    logging.info(f"Done! Took {datetime.now() - start_time}.")


if __name__ == '__main__':
    main()
