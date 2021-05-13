import abc
import datetime
import logging
import pathlib
import socket
import subprocess
import re
import os

import requests
import dns.rdatatype
import psutil
from collections import defaultdict

LAST_RUN = "last-check"
CHECK_TIMEOUT_S = 5
CHECK_ERROR_S = float(0.0)


def merge_dict(a: dict, b: dict):
    """Helper to merge_dict two dicts prior to python 3.9+"""
    c = a.copy()
    c.update(b)
    return c


class Check:
    """Abstract base for a check

    A check tests a certain criteria and produces one or more
    output results each yielding one or more values.

    Results are a list of dictionaries in the form
        {
            'host': 'example.com',
            'name': 'ping',
            'time': '2015-08-18T00:00:00Z'
            'values: [
                {
                    'field': 'min',
                    'value': 2.33,
                    'unit': 'ms'
                },
                {
                    'field': 'max',
                    'value': 4.55,
                    'unit': 'ms'
                }
            ]
        }
    """

    CONFIG = {
        'host': 'str: Name of the host for which the checks apply',
        'interval': 'seconds: Minimum interval between runs of the check. Default: 0',
        'min': 'float: Minimum below which a measurement is considered as failed',
        'max': 'float: Maximum above which a measurement is considered as failed'
    }

    class Result:
        """Keys in a result dictionary"""
        HOST = 'host'  # the name of the targeted host
        DEVICE = 'device'  # the device on the targeted host
        NAME = 'name'  # the name of the implemented check
        TIME = 'time'  # the UTC time at which check was run
        FIELDS = 'fields'  # the list of measured values

    class Field:
        """Keys in a field dictionary"""
        NAME = 'field'  # the name of the measured field
        VALUE = 'value'  # the value measured for the field
        UNIT = 'unit'  # the unit in which value is provided
        MIN = 'min'  # the value below which the measurement failed
        MAX = 'max'  # the value above which the measurement failed

    DEFAULT_DEVICE = ''

    def _reset(self):
        self.results = []
        self.field_values = defaultdict(list)

    def __init__(self, name: str, config: dict, default_interval: int = None):
        """Constructs a new Check instance

        Implementations may check one or more values on host

        :param name: The name of the check implementation
        :param config: The check configuration
        :param default_interval: The default interval at which to perform the check
        """
        import logging
        self.logger = logging.getLogger(f"aggregator.check.{name}")
        self.name = name
        self.host = config['host']
        self.logger.info(f"New instance monitoring '{self.host}'")
        self.logger = logging.getLogger(f"aggregator.check.{name}({self.host})")
        self.interval = config.get('interval', default_interval)
        self.host = config['host']
        self.last_state = {}
        self._reset()

    @abc.abstractmethod
    def on_run(self):
        """Implement this in a base class to run the actual check

        Test results need to be reported using either self.add_result(..)
        or by adding to self.results directly, see the Check class
        documentation for expected dictionary contents.

        The check interval will be honored automatically.
        """
        pass

    def add_field_value(self, field: str, value: float, unit: str = None, device: str = DEFAULT_DEVICE):
        """Add a field value for a check

        :param field: The field for which the check produced a result
        :param value: The value measured for the check
        :param unit: The unit in which value is measured
        :param device: The subdevice of the host which was measured
        """
        r = {
            Check.Field.NAME: field,
            Check.Field.VALUE: value,
        }
        if unit:
            r[Check.Field.UNIT] = unit
        self.field_values[device].append(r)

    def run(self):
        """Executes the checks implemented by this class"""
        self._reset()
        now = datetime.datetime.utcnow()
        if self.interval:
            last = self.last_state.get(LAST_RUN, None)
            if last:
                due = last + datetime.timedelta(seconds=self.interval)
                if due > now:
                    self.logger.debug(f'Next check due in {due - now}')
                    return self.results
                else:
                    self.logger.debug(f'Run check - expired {now - due} ago')
            else:
                self.logger.debug('Run check - never executed before')
        else:
            self.logger.debug('Run check - no interval configured')
        self.on_run()
        self.logger.debug(f'Check completed in {(datetime.datetime.utcnow() - now)}')
        self.last_state[LAST_RUN] = now
        for device, values in self.field_values.items():
            self.results.append({
                Check.Result.NAME: self.name,
                Check.Result.HOST: self.host,
                Check.Result.TIME: now,
                Check.Result.FIELDS: values
            })
            if device != Check.DEFAULT_DEVICE:
                self.results[-1][Check.Result.DEVICE] = device
        return self.results


class CheckFritzBox(Check):
    """Fetch status from an AVM Fritz!Box"""
    CONFIG = merge_dict(Check.CONFIG, {
        'username': 'str: Name of the Fritz!Box user to use for login',
        'password': 'str: Password of the Fritz!Box user to use for login',
        'timeout': f'seconds: Timeout after which a connection attempt is aborted. Default: {CHECK_TIMEOUT_S}',
    })

    def __init__(self, config: dict):
        """Constructor"""
        super().__init__(name='fritzbox', config=config)
        self.username = config['username']
        self.password = config['password']
        self.timeout = config.get('timeout', CHECK_TIMEOUT_S)
        from fritzconnection import FritzConnection
        self.connection = FritzConnection(address=self.host, user=self.username,
                                          password=self.password, timeout=self.timeout)

    def report_wifi(self, service, band):
        from fritzconnection.core.exceptions import FritzServiceError
        try:
            status = self.connection.call_action(f'WLANConfiguration{service.service}', 'GetInfo')
            self.add_field_value('active', True if 'Up' == status['NewStatus'] else False, device=band)
        except FritzServiceError:
            pass
        try:
            stats = self.connection.call_action(f'WLANConfiguration{service.service}', 'GetPacketStatistics')
            self.add_field_value('sent', stats['NewTotalPacketsSent'], 'packets', device=band)
            self.add_field_value('recv', stats['NewTotalPacketsReceived'], 'packets', device=band)
        except FritzServiceError:
            pass
        active_clients = len([c for c in service.get_hosts_info() if c['status']])
        self.add_field_value('clients', active_clients, device=band)

    def on_run(self):
        from fritzconnection.lib.fritzstatus import FritzStatus
        status = FritzStatus(fc=self.connection)
        internet_device = 'wan'
        self.add_field_value('online', status.is_connected, device=internet_device)
        links = status.max_linked_bit_rate
        self.add_field_value('link_upload', links[0], unit='bits/sec', device=internet_device)
        self.add_field_value('link_download', links[1], unit='bits/sec', device=internet_device)
        rates = status.transmission_rate
        self.add_field_value('upload', rates[0], unit='bytes/sec', device=internet_device)
        self.add_field_value('download', rates[1], unit='bytes/sec', device=internet_device)
        self.add_field_value('recv', status.bytes_received, unit='bytes', device=internet_device)
        self.add_field_value('sent', status.bytes_sent, unit='bytes', device=internet_device)
        self.add_field_value('uptime', status.uptime, unit='seconds')

        from fritzconnection.lib.fritzwlan import FritzWLAN
        self.report_wifi(FritzWLAN(fc=self.connection, service=1), "wifi '2.4ghz'")
        self.report_wifi(FritzWLAN(fc=self.connection, service=2), "wifi '5ghz'")
        self.report_wifi(FritzWLAN(fc=self.connection, service=3), "wifi 'guest'")


class CheckPing(Check):
    """Try to ping a host using both IPv4 and IPv6"""
    CONFIG = merge_dict(Check.CONFIG, {
        'timeout': f'seconds: Maximum time to wait for the host to respond to the ping. Default {CHECK_TIMEOUT_S}',
        'ip': 'str: IP address to ping instead of resolving the configured host'
    })
    RE_TIME = r'time=([0-9]+\.[0-9]+)'

    def __init__(self, config: dict):
        """Constructor"""
        super().__init__(name='ping', config=config)
        self.timeout = config.get('timeout', CHECK_TIMEOUT_S)
        self.address = config.get('ip', config['host'])

    def ping(self, command='ping', check='ping'):
        try:
            out = subprocess.check_output([command, '-c', '1', self.address], stderr=subprocess.STDOUT,
                                          encoding='utf-8', timeout=self.timeout)
            time = float(re.search(CheckPing.RE_TIME, out)[1])
            self.add_field_value(field='duration', value=time, unit='ms', device=check)
        except subprocess.CalledProcessError:
            self.add_field_value(field='duration', value=CHECK_ERROR_S, unit='ms', device=check)
        except subprocess.TimeoutExpired:
            self.add_field_value(field='duration', value=CHECK_ERROR_S, unit='ms', device=check)

    def on_run(self):
        self.ping(command='ping', check='ipv4')
        self.ping(command='ping6', check='ipv6')


class CheckDns(Check):
    """Verify host is providing DNS services. Tested by querying A and AAAA records for a domain."""
    CONFIG = merge_dict(Check.CONFIG, {
        'domain': 'str: The domain to fetch A and AAAA records for',
        'timeout': f'seconds: Maximum time to wait for the host to resolve the domain. Default {CHECK_TIMEOUT_S}'
    })

    def __init__(self, config: dict):
        """Constructor"""
        super().__init__(name='dns', config=config)
        self.domain = config.get('domain', 'strato.de')
        self.timeout = config.get('timeout', CHECK_TIMEOUT_S)

        import dns.resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [self.host]

    def measure_record_type(self, record='A'):
        device = f"record '{record}'"
        try:
            start = datetime.datetime.now()
            r = self.resolver.resolve(self.domain, record, search=True)
            end = datetime.datetime.now()
            answers = [a.to_text() for a in r.response.answer]
            self.logger.debug(f"Response is {answers}")
            if answers:
                self.add_field_value("duration", (end - start).total_seconds() * 1000.0, "ms", device=device)
            else:
                self.add_field_value("duration", CHECK_ERROR_S, "ms", device=device)
        except dns.rdatatype.UnknownRdatatype:
            self.add_field_value("duration", CHECK_ERROR_S, "ms", device=device)
        except dns.resolver.NoNameservers:
            self.add_field_value("duration", CHECK_ERROR_S, "ms", device=device)
        except dns.exception.Timeout:
            self.add_field_value("duration", CHECK_ERROR_S, "ms", device=device)

    def on_run(self):
        self.measure_record_type('A')
        self.measure_record_type('AAAA')


class CheckPihole(CheckDns):
    """Verify pihole host is providing DNS services"""
    CONFIG = merge_dict(CheckDns.CONFIG, {
        'pihole': 'str: API url to query current statistics from a pihole instance. Default is to skip.'
    })

    def __init__(self, config: dict):
        super().__init__(config=config)
        self.pihole = config.get('pihole', None)

    def on_run(self):
        super().on_run()
        if self.pihole:
            r = requests.get(self.pihole, timeout=CHECK_TIMEOUT_S)
            if 200 == r.status_code:
                status = r.json()

                def status_value(name):
                    return int(status.get(name, "0").replace(',', ''))

                self.add_field_value('domains_being_blocked', status_value('domains_being_blocked'))
                self.add_field_value('dns_queries_today', status_value('dns_queries_today'))
                self.add_field_value('queries_forwarded', status_value('queries_forwarded'))
                self.add_field_value('ads_blocked_today', status_value('ads_blocked_today'))


class CheckHttp(Check):
    """Verify a http host is reachable and has a valid certificate"""
    CONFIG = merge_dict(Check.CONFIG, {
        'timeout': f'seconds: Time to wait for the request to complete before aborting. Default {CHECK_TIMEOUT_S}',
        'verify_tls': 'bool: Controls if certificates are verified. Default: True',
        'match': 'str: Optional string to match the response contents against. Default: None',
        'cname': 'str: Actual hostname to connect for making the request. The request itself will still request '
                 'contents for the url selected in "host". Use this to verify a vhost configuration. Default: None',
        'expect_status': 'int: Response code to consider a successful request. Default 200'
    })

    def __init__(self, config: dict):
        super().__init__(name='http', config=config)
        self.timeout = config.get('timeout', CHECK_TIMEOUT_S)
        self.verify_tls = config.get('verify_tls', True)
        self.match = config.get('match', None)
        self.cname = config.get('cname', None)
        self.expect_status = config.get('expect_status', 200)

    def on_run(self):
        host = self.host
        if not host.startswith('https:'):
            host = 'https://' + host
        if self.cname:
            device = self.cname
        else:
            device = Check.DEFAULT_DEVICE
        start = datetime.datetime.now()
        orig_getaddrinfo = socket.getaddrinfo

        def force_address_getaddrinfo(original_host, original_port, original_family=0,
                                      original_type=0, original_proto=0, original_flags=0):
            self.logger.debug(f"Forcing connection to {original_host} via {self.cname}")
            ret = orig_getaddrinfo(self.cname, original_port, original_family,
                                   original_type, original_proto, original_flags)
            self.logger.debug(f"{self.cname} resolves to {ret}")
            return ret

        try:
            if self.cname:
                socket.getaddrinfo = force_address_getaddrinfo
            r = requests.get(host, timeout=self.timeout, verify=self.verify_tls)
            socket.getaddrinfo = orig_getaddrinfo
        except requests.exceptions.ConnectionError as e:
            socket.getaddrinfo = orig_getaddrinfo
            self.add_field_value('duration', CHECK_ERROR_S, 'ms', device=device)
            self.logger.debug(f"Request failed: {e}")
            return
        end = datetime.datetime.now()
        duration = (end - start).total_seconds() * 1000.0
        self.add_field_value('status_code', r.status_code, device=device)
        self.logger.debug(f"Request completed: {r.status_code}")
        if self.expect_status == r.status_code:
            if self.match and self.match not in r.text:
                self.add_field_value('duration', CHECK_ERROR_S, 'ms', device=device)
                return
            self.add_field_value('duration', duration, 'ms', device=device)
        else:
            self.logger.warning(f"Expected {self.expect_status} but got {r.status_code}")
            self.add_field_value('duration', CHECK_ERROR_S, 'ms', device=device)


class CheckCpu(Check):
    """Measure system resources"""

    def __init__(self, config: dict):
        super().__init__(name='cpu', config=config)

    def on_run(self):
        cpu_count = psutil.cpu_count()
        times = psutil.cpu_times(percpu=False)
        self.add_field_value('user', times.user / cpu_count, 'seconds')
        self.add_field_value('system', times.system / cpu_count, 'seconds')
        self.add_field_value('idle', times.idle / cpu_count, 'seconds')
        try:
            self.add_field_value('iowait', times.iowait / cpu_count, 'seconds')
        except AttributeError:
            pass
        try:
            self.add_field_value('irq', (times.irq + times.softirq) / cpu_count, 'seconds')
        except AttributeError:
            pass

        avg = [x / cpu_count * 100 for x in psutil.getloadavg()]
        self.add_field_value('avg_1min', avg[0], '%')
        self.add_field_value('avg_5min', avg[1], '%')
        self.add_field_value('avg_15min', avg[2], '%')


class CheckMemory(Check):
    """Measure system resources"""

    def __init__(self, config: dict):
        super().__init__(name='memory', config=config)

    def on_run(self):
        memory = psutil.virtual_memory()
        self.add_field_value('total', memory.total, 'bytes')
        self.add_field_value('used', memory.used, 'bytes')
        self.add_field_value('available', memory.available, 'bytes')
        try:
            self.add_field_value('active', memory.active, 'bytes')
            self.add_field_value('inactive', memory.inactive, 'bytes')
        except AttributeError:
            pass


class CheckSensors(Check):
    """Measure system resources"""

    def __init__(self, config: dict):
        super().__init__(name='sensors', config=config)

    def on_run(self):
        if hasattr(psutil, 'sensors_temperatures'):
            temps = psutil.sensors_temperatures()
            if temps:
                for name, entries in temps.items():
                    for entry in entries:
                        self.add_field_value(f"{name}_{entry.label or ''}", entry.current, "°C")
            else:
                self.logger.debug("No temperatures detected")
        else:
            self.logger.debug("Temperatures not supported on this system")

        if hasattr(psutil, 'sensors_fans'):
            fans = psutil.sensors_fans()
            if fans:
                for name, entries in fans.items():
                    for entry in entries:
                        self.add_field_value(f"{name}_{entry.label or ''}", entry.current, "rpm")
            else:
                self.logger.debug("No fans detected")
        else:
            self.logger.debug("Fans not supported on this system")


class CheckNetwork(Check):
    """Measure system resources"""
    CONFIG = merge_dict(Check.CONFIG, {
        'interfaces': 'str[]: List of interface names to limit the checks to. Defaults to all interfaces.'
    })

    def __init__(self, config: dict):
        super().__init__(name='network', config=config)
        self.interfaces = config.get('interfaces', [])

    def report_interface(self, name, counts):
        self.add_field_value('sent', counts.bytes_sent, 'bytes', device=name)
        self.add_field_value('recv', counts.bytes_recv, 'bytes', device=name)
        self.add_field_value('errin', counts.errin, 'errors', device=name)
        self.add_field_value('errout', counts.errout, 'errors', device=name)
        self.add_field_value('dropin', counts.dropin, 'packets', device=name)
        self.add_field_value('dropout', counts.dropout, 'packets', device=name)

    def on_run(self):
        counters = psutil.net_io_counters(pernic=True)
        if self.interfaces:
            for iface in self.interfaces:
                counts = counters.get(iface)
                if counts:
                    self.report_interface(iface, counts)
                else:
                    self.logger.warning(f"No such interface: '{iface}'")
        else:
            for iface, counts in counters.items():
                self.report_interface(iface, counts)


class CheckDisks(Check):
    """Measure system resources"""
    CONFIG = merge_dict(Check.CONFIG, {
        'devices': 'str[]: List of disk names to be reported. Defaults to all'
    })

    def __init__(self, config: dict):
        super().__init__(name='disks', config=config)
        self.devices = config.get('devices', None)
        if self.devices:
            resolved = dict()
            for p in self.devices:
                base = pathlib.Path(p)
                if base.is_symlink():
                    actual = pathlib.Path(os.readlink(base))
                else:
                    actual = base
                resolved[actual.name] = base.name
            self.devices = resolved
            self.logger.debug(f"Tracking {self.devices}")

    def on_run(self):
        counters = psutil.disk_io_counters(perdisk=True)
        for p, c in counters.items():
            device = p
            if self.devices:
                if p not in self.devices:
                    self.logger.debug(f"Skipping {p}")
                    continue
                else:
                    device = self.devices[p]
            self.add_field_value('read', c.read_bytes, 'bytes', device=device)
            self.add_field_value('write', c.write_bytes, 'bytes', device=device)


class CheckMounts(Check):
    """Measure system resources"""
    CONFIG = merge_dict(Check.CONFIG, {
        'mounts': 'str[]: Array of mount points to have their usage reported.'
    })

    def __init__(self, config: dict):
        super().__init__(name='mounts', config=config)
        self.mounts = config['mounts']

    def report_mountpoint(self, mount):
        try:
            usage = psutil.disk_usage(mount)
            device = f"mountpoint '{mount}'"
            self.add_field_value('total', usage.total, 'bytes', device=device)
            self.add_field_value('used', usage.used, 'bytes', device=device)
            self.add_field_value('free', usage.free, 'bytes', device=device)
        except OSError:
            self.logger.warning(f"No such mount: {mount}")

    def on_run(self):
        for m in self.mounts:
            self.report_mountpoint(m)


class CheckDiskSpindown(Check):
    """Measure spindown status of disks"""
    CONFIG = merge_dict(Check.CONFIG, {
        'disks': 'str[]: List of disk entries below /dev to check the spindown status for',
        'smartctl': 'str: Path to the smartctl utility. Default /sbin/smartctl',
        'timeout': f'seconds: Time after which to abort the smartctl run. Default {CHECK_TIMEOUT_S}'
    })

    def __init__(self, config: dict):
        super().__init__(name='spindown', config=config)
        self.disks = config['disks']
        self.smartctl = config.get('smartctl', '/sbin/smartctl')
        self.timeout = config.get('timeout', CHECK_TIMEOUT_S)

    def report_disk(self, disk):
        name = pathlib.Path(disk).name
        try:
            out = subprocess.check_output([self.smartctl, '-i', '-n', 'standby', disk],
                                          stderr=subprocess.STDOUT,
                                          encoding='utf-8', timeout=self.timeout)
            if 'STANDBY mode' in out:
                # just a double net, we should get a returncode of 2 and end up below
                self.add_field_value(field='standby', value=1, device=name)
            else:
                self.add_field_value(field='standby', value=0, device=name)
        except subprocess.CalledProcessError as error:
            if 2 == error.returncode:
                self.add_field_value(field='standby', value=1, device=name)
            else:
                raise

    def on_run(self):
        for d in self.disks:
            self.report_disk(d)


class CheckNetgearGS108E(Check):
    """Gather statistics from a NSDP enabled switch such as GS108E

    Requires client built from https://github.com/AlbanBedel/libnsdp
    """
    CONFIG = merge_dict(Check.CONFIG, {
        'source': 'str: MAC address of the network interface to send from',
        'switch': 'str: MAC address of the switch to be queried',
        'nsdp_client': 'str: Path to the nsdp_client build from https://github.com/AlbanBedel/libnsdp'
    })

    # https://github.com/AlbanBedel/libnsdp/blob/master/nsdp_properties.h
    PROPERTY_MODEL = '0x0001'
    PROPERTY_HOSTNAME = '0x0003'
    PROPERTY_PORT_STATUS = '0x0C00'
    PROPERTY_PORT_STATISTICS = '0x1000'

    def __init__(self, config: dict):
        super().__init__(name='gs108e', config=config)
        self.source_mac = config['source']
        self.switch_mac = config['switch']
        self.client = config['nsdp_client']
        self.re_port_status = re.compile(r'Status: ([0-9]+):(\w+)$', re.MULTILINE)
        self.re_port_statistic = re.compile(r'Statistics: ([0-9]+):rx=([0-9]+),tx=([0-9]+)$', re.MULTILINE)

    def read_property(self, prop):
        try:
            out = subprocess.check_output([self.client, '-m', self.source_mac, 'read', self.switch_mac, prop],
                                          stderr=subprocess.STDOUT, encoding='utf-8')
            return out.strip()
        except subprocess.CalledProcessError:
            return None

    def get_port_states(self):
        """Port Status: 1:Disconnected"""
        values = self.read_property(CheckNetgearGS108E.PROPERTY_PORT_STATUS)
        connected_ports = set()
        for p in self.re_port_status.findall(values):
            device = f'port{p[0]}'
            if 'Disconnected' == p[1]:
                self.add_field_value('link', 0, unit='mbit', device=device)
            else:
                self.add_field_value('link', int(p[1][:-1]), unit='mbit', device=device)
                connected_ports.add(device)
        return connected_ports

    def get_port_statistics(self, connected_ports):
        """Port Statistics: 1:rx=0,tx=0"""
        values = self.read_property(CheckNetgearGS108E.PROPERTY_PORT_STATISTICS)
        for p in self.re_port_statistic.findall(values):
            device = f'port{p[0]}'
            if device in connected_ports:
                self.add_field_value('recv', int(p[1]), unit='bytes', device=device)
                self.add_field_value('sent', int(p[2]), unit='bytes', device=device)

    def on_run(self):
        if self.logger.isEnabledFor(logging.DEBUG):
            model = self.read_property(CheckNetgearGS108E.PROPERTY_MODEL)
            host = self.read_property(CheckNetgearGS108E.PROPERTY_HOSTNAME)
            self.logger.debug(f"Status for:\n\t{host}\n\t{model}")
        connected = self.get_port_states()
        self.get_port_statistics(connected)


class CheckNetgearGS108Ev2(Check):
    """Gather statistics from a NSDP enabled switch such as GS108E

    Uses python implementation of NSDP from https://github.com/Z3po/ProSafeLinux
    """
    CONFIG = merge_dict(Check.CONFIG, {
        'interface': 'str: Name of the network interface to send from',
        'switch': 'str: MAC address of the switch to be queried',
        'timeout': f'seconds: Timeout after which a query is aborted. Default {CHECK_TIMEOUT_S}',
        'ports': 'int[]: Index of ports to report stats for starting at 1. Defaults to all',
        'names': 'str[]: Array of strings to assign to ports, the first entry defines port 1 etc.'
                 + 'Defaults to "port1", "port2",...'
    })

    def __init__(self, config: dict):
        super().__init__(name='gs108e', config=config)
        self.interface = config['interface']
        self.switch_mac = config['switch']
        self.timeout = config.get('timeout', CHECK_TIMEOUT_S)
        self.ports = config.get('ports', None)
        self.names = config.get('names', [])

    def device_name(self, port):
        if port <= len(self.names):
            return self.names[port - 1]
        else:
            return f"port{port}"

    def on_run(self):
        from .psl_class import ProSafeLinux
        from .psl_typ import PslTypSpeedStat
        switch = ProSafeLinux()
        switch.set_timeout(self.timeout)
        switch.bind(self.interface)
        queries = [ProSafeLinux.CMD_MODEL, ProSafeLinux.CMD_NAME,
                   ProSafeLinux.CMD_PORT_STAT, ProSafeLinux.CMD_SPEED_STAT]
        response = switch.query(queries, self.switch_mac)
        response = {r.get_name(): v for r, v in response.items()}
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug("Status for:"
                              + f"\n\t host: {response.get('name', None)}"
                              + f"\n\tmodel: {response.get('model', None)}"
                              + f"\n\t{response}")
        connected_ports = set()
        for p in response['speed_stat']:
            port = int(p['port'])
            device = self.device_name(port)
            if self.ports and port not in self.ports:
                continue
            speed = p['speed']
            if speed == PslTypSpeedStat.SPEED_1G:
                self.add_field_value('link', 1000, unit='mbit', device=device)
                connected_ports.add(port)
            elif speed == PslTypSpeedStat.SPEED_100MH or speed == PslTypSpeedStat.SPEED_100ML:
                self.add_field_value('link', 100, unit='mbit', device=device)
                connected_ports.add(port)
            elif speed == PslTypSpeedStat.SPEED_10MH or speed == PslTypSpeedStat.SPEED_10ML:
                self.add_field_value('link', 10, unit='mbit', device=device)
                connected_ports.add(port)
            else:
                self.add_field_value('link', 0, unit='mbit', device=device)
        for p in response['port_stat']:
            port = int(p['port'])
            device = self.device_name(port)
            if port in connected_ports:
                self.add_field_value('recv', int(p['rec']), unit='bytes', device=device)
                self.add_field_value('sent', int(p['send']), unit='bytes', device=device)
                self.add_field_value('errors', int(p['error']), device=device)


class CheckUPS(Check):
    """Check a UPS using NUT"""
    CONFIG = merge_dict(Check.CONFIG, {
        'ups': 'str: Name of the ups as reported by NUT',
        'username': 'str: Username to connect to NUT',
        'password': 'str: Password to connect to NUT'
    })

    def __init__(self, config: dict):
        """Constructor"""
        super().__init__(name='ups', config=config)
        from nut2 import PyNUTClient
        self.ups = config['ups']
        self.username = config['username']
        self.password = config['password']
        self.client_class = PyNUTClient

    def on_run(self):
        client = self.client_class(host=self.host, login=self.username,
                                   password=self.password)
        if self.logger.isEnabledFor(logging.DEBUG):
            devices = client.list_ups()
            self.logger.debug(f"devices={devices}")
        # https://networkupstools.org/docs/developer-guide.chunked/apas01.html
        ups_vars = client.list_vars(self.ups)
        self.add_field_value('charge', int(ups_vars['battery.charge']), '%')
        self.add_field_value('runtime', int(ups_vars['battery.runtime']), 'seconds')
        self.add_field_value('input', float(ups_vars['input.voltage']), 'V')
        self.add_field_value('load', float(ups_vars['ups.load']) / 100.0 * int(ups_vars['ups.realpower.nominal']), 'W')
        status = ups_vars['ups.status']
        if 'OL' == status:
            status = 'online'
        elif 'OL CHRG' == status:
            status = 'charging'
        elif 'OB' == status:
            status = 'battery'
        elif 'LB' == status:
            status = 'low battery'
        self.add_field_value('status', status)


class CheckDocker(Check):
    """Check load of docker containers"""
    CONFIG = merge_dict(Check.CONFIG, {
        'url': 'str: Url to use for connecting to the docker daemon. Default is derived from env automatically'
    })

    def __init__(self, config: dict):
        """Constructor"""
        super().__init__(name='docker', config=config)
        self.url = config.get('url', None)
        import docker
        self.docker_client = docker.DockerClient
        self.docker_from_env = docker.from_env

    def _graceful_chain_get(self, data, *args, default=None):
        # credit to sen
        # https://github.com/TomasTomecek/sen/blob/master/sen/util.py#L158
        node = data
        for a in args:
            try:
                node = node[a]
            except (KeyError, ValueError, TypeError, AttributeError):
                self.logger.warning("can't get %r from %s", a, node)
                return default
        return node

    @staticmethod
    def _calculate_cpu_seconds(data):
        """Return CPU usage as user, system in seconds"""
        # credit to sen
        # https://github.com/TomasTomecek/sen/blob/master/sen/util.py#L158
        # also see https://docs.docker.com/engine/api/v1.21/
        ns_per_second = 1000000.0
        user = float(data["cpu_stats"]["cpu_usage"]["usage_in_usermode"]) / ns_per_second
        system = (float(data["cpu_stats"]["cpu_usage"]["total_usage"]) - user) / ns_per_second
        return user, system

    def _calculate_blkio_bytes(self, data):
        """Return disk I/O as (read,written) in bytes"""
        # credit to sen
        # https://github.com/TomasTomecek/sen/blob/master/sen/util.py#L158
        bytes_stats = self._graceful_chain_get(data, "blkio_stats", "io_service_bytes_recursive")
        if not bytes_stats:
            return 0, 0
        read = 0
        written = 0
        for s in bytes_stats:
            if s["op"] == "Read":
                read += s["value"]
            elif s["op"] == "Write":
                written += s["value"]
        return read, written

    def _calculate_network_bytes(self, data):
        """Return network I/O as (recv,sent) in bytes"""
        # credit to sen
        # https://github.com/TomasTomecek/sen/blob/master/sen/util.py#L158
        networks = self._graceful_chain_get(data, "networks")
        if not networks:
            return 0, 0
        recv = 0
        sent = 0
        for if_name, data in networks.items():
            recv += data["rx_bytes"]
            sent += data["tx_bytes"]
        return recv, sent

    def on_run(self):
        if self.url:
            client = self.docker_client(base_url=self.url, use_ssh_client=True)
        else:
            client = self.docker_from_env()

        containers = client.containers.list(sparse=False)
        for container in containers:
            name = f"container '{container.name}'"
            self.add_field_value('status', container.status, device=name)
            stats = container.stats(stream=False)
            user, system = self._calculate_cpu_seconds(stats)
            self.add_field_value('cpu', user + system, 'seconds', device=name)
            recv, sent = self._calculate_network_bytes(stats)
            self.add_field_value('sent', sent, 'bytes', device=name)
            self.add_field_value('recv', recv, 'bytes', device=name)
            read, written = self._calculate_blkio_bytes(stats)
            self.add_field_value('read', read, 'bytes', device=name)
            self.add_field_value('written', written, 'bytes', device=name)


class CheckDockerV2(Check):
    """Check load of docker containers

    Optimized for performance when comparing to V1
    """
    CONFIG = merge_dict(Check.CONFIG, {
        'url': 'str: Url to use for connecting to the docker daemon. Default is derived from env automatically'
    })

    def __init__(self, config: dict):
        """Constructor"""
        super().__init__(name='docker', config=config)
        self.url = config.get('url', None)
        import docker
        self.docker_client = docker.DockerClient
        self.docker_from_env = docker.from_env
        self._fetch_containers()
        self.cpu_count = psutil.cpu_count()

    def _fetch_containers(self):
        if self.url:
            client = self.docker_client(base_url=self.url, use_ssh_client=True)
        else:
            client = self.docker_from_env()

        class Container:
            """Efficient storage of a running container"""

            def __init__(self, api_container):
                self.name = api_container.name
                self.id = api_container.id

        self.containers = [Container(c) for c in client.containers.list(sparse=False)]

    def read_sysfs_node(self, path, key_index=0):
        """Returns a dict with values of the sysfs node at path"""
        try:
            values = {}
            with open(path) as node:
                for line in node.readlines():
                    line_parts = line.strip().split(' ')
                    values[line_parts[key_index]] = ' '.join(line_parts[key_index + 1:])
            # self.logger.debug(f"{path} yields {values}")
            return values
        except IOError:
            self.logger.warning(f"Failed to read {path}")
            return None

    def read_net_dev_node(self, pid):
        """Returns a dict with (recv, sent) tuples for interfaces used by pid"""
        sysfs_traffic = self.read_sysfs_node(f"/proc/{pid}/net/dev")
        if sysfs_traffic:
            values = {}
            for interface, raw_values in sysfs_traffic.items():
                interface_values = [s for s in raw_values.split(' ') if s.strip()]
                if interface.startswith('eth'):
                    values[interface.strip(':')] = (interface_values[0], interface_values[8])
            # self.logger.debug(f"/proc/{pid}/net/dev yields {values}")
            return values
        self.logger.warning(f"Failed to read /proc/{pid}/net/dev")
        return None

    def on_run(self):
        for container in self.containers:
            name = f"container '{container.name}'"
            # see https://crate.io/a/analyzing-docker-container-performance-native-tools/
            sysfs_memory = self.read_sysfs_node(f"/sys/fs/cgroup/memory/docker/{container.id}/memory.stat")
            if sysfs_memory:
                self.add_field_value('memory', int(sysfs_memory['total_rss']), 'bytes', device=name)
            sysfs_cpu = self.read_sysfs_node(f"/sys/fs/cgroup/cpuacct/docker/{container.id}/cpuacct.stat")
            if sysfs_cpu:
                userhz_2_s = 1.0 / 100.0
                cpu_total_userhz = float(sysfs_cpu['user']) + float(sysfs_cpu['system'])
                self.add_field_value('cpu', cpu_total_userhz * userhz_2_s / self.cpu_count, 'seconds', device=name)
            sysfs_io_bytes = self.read_sysfs_node(
                f"/sys/fs/cgroup/blkio/docker/{container.id}/blkio.throttle.io_service_bytes", key_index=1)
            if sysfs_io_bytes:
                self.add_field_value('read', float(sysfs_io_bytes['Read']), 'bytes', device=name)
                self.add_field_value('written', float(sysfs_io_bytes['Write']), 'bytes', device=name)
            sysfs_tasks = self.read_sysfs_node(
                f"/sys/fs/cgroup/devices/docker/{container.id}/tasks")
            if sysfs_tasks:
                sysfs_pid = list(sysfs_tasks.keys())[0]
                proc_traffic = self.read_net_dev_node(sysfs_pid)
                if proc_traffic:
                    recv = 0
                    sent = 0
                    for iface, values in proc_traffic.items():
                        recv += int(values[0])
                        sent += int(values[1])
                    self.add_field_value('recv', recv, 'bytes', device=name)
                    self.add_field_value('sent', sent, 'bytes', device=name)


class CheckAge(Check):
    """Check time elapsed since a timestamp

    Formatting is controlled as in https://docs.python.org/3/library/datetime.html#strftime-strptime-behavior
    """
    CONFIG = merge_dict(Check.CONFIG, {
        'path': 'str: Path to a file containing a string which can be parsed by datetime.strptime',
        'format': 'str: Format to use for parsing the datestring in file. Defaults to the format used by CheckAge.touch'
    })
    DEFAULT_FORMAT = '%H:%M:%S %d.%m.%Y'

    def __init__(self, config: dict):
        """Constructor"""
        super().__init__(name='age', config=config)
        self.file = pathlib.Path(config['path'])
        self.formatstr = config.get('format', CheckAge.DEFAULT_FORMAT)

    @staticmethod
    def touch(file, formatstr=DEFAULT_FORMAT):
        now = datetime.datetime.now()
        file = pathlib.Path(file)
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(now.strftime(formatstr))

    def on_run(self):
        if self.file.exists():
            time = datetime.datetime.strptime(self.file.read_text().strip(), self.formatstr)
            now = datetime.datetime.now()
            self.add_field_value('age', (now - time).total_seconds(), 'seconds', device=self.file.name)
        else:
            self.add_field_value('age', CHECK_ERROR_S, 'seconds', device=self.file.name)


class CheckSystem(Check):
    """Data on the system like uptime and active users"""

    def __init__(self, config: dict):
        """Constructor"""
        super().__init__(name='system', config=config)

    def on_run(self):
        boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
        now = datetime.datetime.now()
        self.add_field_value('uptime', (now - boot_time).total_seconds(), 'seconds')
        self.add_field_value('active_users', len(psutil.users()))


class CheckKostalSCB(Check):
    """Fetches load data for the Kostal SCB Plenticore Plus Hybrid Solar controller"""

    DEVICES_LOCAL = {
        "HomePv_P": {
            'unit': 'W',
            'device': 'Bezug Haus PV'
        },
        "HomeBat_P": {
            'unit': 'W',
            'device': 'Bezug Haus Batterie'
        },
        "HomeGrid_P": {
            'unit': 'W',
            'device': 'Bezug Haus Netz'
        },
        "Grid_P": {
            'unit': 'W',
            'device': 'Energiefluss Netz'
        },
        "Dc_P": {
            'unit': 'W',
            'device': 'Energiefluss PV'
        },
    }

    STATISTICS = {
        "Statistic:CO2Saving:Total": {
            'unit': 'g',
            'device': 'co2 savings'
        },
        "Statistic:EnergyHome:Total": {
            'unit': 'kWh',
            'device': 'Verbrauch Haus Gesamt'
        },
        "Statistic:EnergyHomePv:Total": {
            'unit': 'kWh',
            'device': 'Verbrauch Haus PV'
        },
        "Statistic:EnergyHomeGrid:Total": {
            'unit': 'kWh',
            'device': 'Verbrauch Haus Netz'
        },
        "Statistic:EnergyHomeBat:Total": {
            'unit': 'kWh',
            'device': 'Verbrauch Haus Batterie'
        },
        "Statistic:Autarky:Total": {
            'unit': '%',
            'device': 'Autarkiegrad'
        },
    }
    BATTERY = {
        "SoC": {
            'unit': '%',
            'device': 'Ladezustand'
        },
        "Cycles": {
            'unit': None,
            'device': 'Ladezyklen'
        },
        "P": {
            'unit': 'W',
            'device': 'Energiefluss Batterie'
        },
    }

    def __init__(self, config: dict):
        """Constructor"""
        super().__init__(name='system', config=config)
        import kostalplenticore
        self.plenticore_connect = kostalplenticore.connect
        self.ip = config['ip']
        self.password = config['password']
        self.connection = kostalplenticore.connect(self.ip, self.password)

    def fetch_processdata(self, field, moduleid, description):
        devices = self.connection.getProcessdata(moduleid, list(description.keys()))
        for d in devices:
            d_id = d['id']
            desc = description.get(d_id, None)
            if desc:
                self.add_field_value(desc['device'], d['value'], unit=desc['unit'], device=field)

    def on_run(self):
        try:
            self.connection.getInfo()
        except Exception:
            self.connection.login()

        self.fetch_processdata("load", "devices:local", CheckKostalSCB.DEVICES_LOCAL)
        self.fetch_processdata("statistics", "scb:statistic:EnergyFlow", CheckKostalSCB.STATISTICS)
        self.fetch_processdata("battery", "devices:local:battery", CheckKostalSCB.BATTERY)


CHECKS = {
    'dns': CheckPihole,
    'fritzbox': CheckFritzBox,
    'ping': CheckPing,
    'http': CheckHttp,
    'https': CheckHttp,
    'cpu': CheckCpu,
    'memory': CheckMemory,
    'sensors': CheckSensors,
    'network': CheckNetwork,
    'disks': CheckDisks,
    'mounts': CheckMounts,
    'gs108e': CheckNetgearGS108Ev2,
    'ups': CheckUPS,
    'docker': CheckDockerV2,
    'spindown': CheckDiskSpindown,
    'age': CheckAge,
    'system': CheckSystem,
    'kostal': CheckKostalSCB
}
