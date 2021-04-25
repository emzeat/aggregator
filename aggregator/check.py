import abc
import datetime
import logging
import socket
import subprocess
import re
import requests
import dns.rdatatype
import psutil
from collections import defaultdict

LAST_RUN = "last-check"
CHECK_TIMEOUT_S = 5


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

    class Result:
        """Keys in a result dictionary"""
        HOST = 'host'  # the name of the targeted host
        DEVICE = 'device' # the device on the targeted host
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

    class Config:
        """Fields in a config dictionary"""
        INTERVAL = 'interval'
        TYPE = 'type'
        HOST = 'host'

    DEFAULT_DEVICE = ''

    def __init__(self, name: str, config: dict, default_interval: datetime.timedelta = None):
        """Constructs a new Check instance

        Implementations may check one or more values on host

        :param name: The name of the check implementation
        :param config: The check configuration
        :param default_interval: The default interval at which to perform the check
        """
        import logging
        self.logger = logging.getLogger(f"{name}")
        self.name = name
        self.host = config['host']
        self.logger.info(f"New instance monitoring '{self.host}'")
        self.logger = logging.getLogger(f"{name}({self.host})")
        self.interval = config.get(Check.Config.INTERVAL, default_interval)
        self.host = config[Check.Config.HOST]
        self.last_state = {}
        self.results = []
        self.field_values = defaultdict(list)

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
        now = datetime.datetime.utcnow()
        if self.interval:
            last = self.last_state.get(LAST_RUN, None)
            if last and last + self.interval < now:
                self.logger.debug(f'Next check due at {now + self.interval}')
                return self.results
            elif last:
                self.logger.debug(f'Run check - expired at {last + self.interval}')
            else:
                self.logger.debug(f'Run check - never executed before')
        else:
            self.logger.debug('Run check - no interval configured')
        self.on_run()
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
        active_clients = len([c for c in service.get_hosts_info() if c['status']])
        self.add_field_value('clients', active_clients, device=band)

    def on_run(self):
        from fritzconnection.lib.fritzstatus import FritzStatus
        status = FritzStatus(fc=self.connection)
        self.add_field_value('online', status.is_connected)
        links = status.max_linked_bit_rate
        self.add_field_value('link_upload', links[0], unit='bits/sec')
        self.add_field_value('link_download', links[1], unit='bits/sec')
        rates = status.transmission_rate
        self.add_field_value('upload', rates[0], unit='bytes/sec')
        self.add_field_value('download', rates[1], unit='bytes/sec')
        self.add_field_value('recv', status.bytes_received, unit='bytes')
        self.add_field_value('sent', status.bytes_sent, unit='bytes')
        self.add_field_value('uptime', status.uptime, unit='seconds')

        from fritzconnection.lib.fritzwlan import FritzWLAN
        self.report_wifi(FritzWLAN(fc=self.connection, service=1), "wifi '2.4ghz'")
        self.report_wifi(FritzWLAN(fc=self.connection, service=2), "wifi '5ghz'")
        self.report_wifi(FritzWLAN(fc=self.connection, service=3), "wifi 'guest'")


RE_TIME = r'time=([0-9]+\.[0-9]+)'


class CheckPing(Check):
    """Try to ping a host using both IPv4 and IPv6"""

    def __init__(self, config: dict):
        """Constructor"""
        super().__init__(name='ping', config=config)

    def ping(self, command='ping', check='ping'):
        try:
            out = subprocess.check_output([command, '-c', '1', self.host], stderr=subprocess.STDOUT, encoding='utf-8')
            time = float(re.search(RE_TIME, out)[1])
            self.add_field_value(field='duration', value=time, unit='ms', device=check)
        except subprocess.CalledProcessError:
            self.add_field_value(field='duration', value=0.0, unit='ms', device=check)

    def on_run(self):
        self.ping(command='ping', check='ping-ipv4')
        self.ping(command='ping6', check='ping-ipv6')


class CheckDns(Check):
    """Verify host is providing DNS services"""

    def __init__(self, config: dict):
        """Constructor"""
        super().__init__(name='dns', config=config)
        self.domain = config.get('domain', 'strato.de')
        self.timeout = config.get('timeout', CHECK_TIMEOUT_S)

        import dns.name
        import dns.resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [self.host]

    def measure_record_type(self, record='A'):
        try:
            start = datetime.datetime.now()
            r = self.resolver.resolve(self.domain, record, search=True)
            end = datetime.datetime.now()
            answers = [a.to_text() for a in r.response.answer]
            self.logger.debug(f"Response is {answers}")
            if answers:
                self.add_field_value("duration", (end - start).total_seconds() * 1000.0, "ms", device=record)
            else:
                elf.add_field_value("duration", 0.0, "ms", device=record)
        except dns.rdatatype.UnknownRdatatype:
            self.add_field_value("duration", 0.0, "ms", device=record)
        except dns.resolver.NoNameservers:
            self.add_field_value("duration", 0.0, "ms", device=record)
        except dns.exception.Timeout:
            self.add_field_value("duration", 0.0, "ms", device=record)

    def on_run(self):
        self.measure_record_type('A')
        self.measure_record_type('AAAA')


class CheckPihole(CheckDns):
    """Verify pihole host is providing DNS services"""

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

    def __init__(self, config: dict):
        super().__init__(name='http', config=config)
        self.timeout = config.get('timeout', CHECK_TIMEOUT_S)
        self.verify = config.get('verify', True)
        self.match = config.get('match', None)
        self.cname = config.get('cname', None)

    def on_run(self):
        host = self.host
        if not host.startswith('https:'):
            host = 'https://' + host
        start = datetime.datetime.now()
        orig_getaddrinfo = socket.getaddrinfo

        def force_address_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            self.logger.debug(f"Forcing connection to {host} via {self.cname}")
            ret = orig_getaddrinfo(self.cname, port, family, type, proto, flags)
            self.logger.debug(f"{self.cname} resolves to {ret}")
            return ret

        try:
            if self.cname:
                socket.getaddrinfo = force_address_getaddrinfo
            r = requests.get(host, timeout=self.timeout, verify=self.verify)
            socket.getaddrinfo = orig_getaddrinfo
        except requests.exceptions.ConnectionError as e:
            socket.getaddrinfo = orig_getaddrinfo
            self.add_field_value('duration', 0, 'ms')
            self.logger.debug(f"Request failed: {e}")
            return
        end = datetime.datetime.now()
        duration = (end - start).total_seconds() * 1000.0
        self.add_field_value('status_code', r.status_code)
        self.logger.debug(f"Request completed: {r.status_code}")
        if 200 == r.status_code:
            if self.match and self.match not in r.text:
                self.add_field_value('duration', 0, 'ms')
                return
            self.add_field_value('duration', duration, 'ms')
        else:
            self.add_field_value('duration', 0, 'ms')


class CheckCpu(Check):
    """Measure system resources"""

    def __init__(self, config: dict):
        super().__init__(name='cpu', config=config)

    def on_run(self):
        times = psutil.cpu_times()
        self.add_field_value('user', times.user, 'seconds')
        self.add_field_value('system', times.system, 'seconds')
        self.add_field_value('idle', times.idle, 'seconds')
        try:
            self.add_field_value('iowait', times.iowait, 'seconds')
        except AttributeError:
            pass
        try:
            self.add_field_value('irq', times.irq + times.softirq, 'seconds')
        except AttributeError:
            pass

        avg = [x / psutil.cpu_count() * 100 for x in psutil.getloadavg()]
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

    def __init__(self, config: dict):
        super().__init__(name='disks', config=config)
        self.mounts = config.get('mounts', [])

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
        counters = psutil.disk_io_counters()
        self.add_field_value('read', counters.read_bytes, 'bytes')
        self.add_field_value('write', counters.write_bytes, 'bytes')
        for m in self.mounts:
            self.report_mountpoint(m)


class CheckNetgearGS108E(Check):
    """Gather statistics from a NSDP enabled switch such as GS108E

    Requires client built from https://github.com/AlbanBedel/libnsdp
    """

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
        for p in self.re_port_status.findall(values):
            device=f'port{p[0]}'
            if 'Disconnected' == p[1]:
                self.add_field_value('link', 0, unit='mbit', device=device)
            else:
                self.add_field_value('link', int(p[1][:-1]), unit='mbit', device=device)

    def get_port_statistics(self):
        """Port Statistics: 1:rx=0,tx=0"""
        values = self.read_property(CheckNetgearGS108E.PROPERTY_PORT_STATISTICS)
        for p in self.re_port_statistic.findall(values):
            device=f'port{p[0]}'
            self.add_field_value('recv', int(p[1]), unit='bytes', device=device)
            self.add_field_value('sent', int(p[2]), unit='bytes', device=device)

    def on_run(self):
        if self.logger.isEnabledFor(logging.DEBUG):
            model = self.read_property(CheckNetgearGS108E.PROPERTY_MODEL)
            host = self.read_property(CheckNetgearGS108E.PROPERTY_HOSTNAME)
        self.logger.debug(f"Status for:\n\t{host}\n\t{model}")
        self.get_port_states()
        self.get_port_statistics()


class CheckUPS(Check):
    """Check a UPS using NUT"""

    def __init__(self, config: dict):
        """Constructor"""
        super().__init__(name='ups', config=config)
        from nut2 import PyNUTClient
        self.ups = config['ups']
        self.client = PyNUTClient(host=self.host, login=config['username'],
                                  password=config['username'], debug=True)

    def on_run(self):
        if self.logger.isEnabledFor(logging.DEBUG):
            devices = self.client.list_ups()
            self.logger.debug(f"devices={devices}")
        # https://networkupstools.org/docs/developer-guide.chunked/apas01.html
        ups_vars = self.client.list_vars(self.ups)
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

    def __init__(self, config: dict):
        """Constructor"""
        super().__init__(name='docker', config=config)
        import docker
        #self.client = docker.from_env()
        self.client = docker.DockerClient(base_url='ssh://heimdall.mlba-team.de:22', use_ssh_client=True)

    def on_run(self):
        def graceful_chain_get(d, *args, default=None):
            # credit to sen
            # https://github.com/TomasTomecek/sen/blob/master/sen/util.py#L158
            t = d
            for a in args:
                try:
                    t = t[a]
                except (KeyError, ValueError, TypeError, AttributeError):
                    self.logger.warning("can't get %r from %s", a, t)
                    return default
            return t

        def calculate_cpu_percent(d):
            # credit to sen
            # https://github.com/TomasTomecek/sen/blob/master/sen/util.py#L158
            cpu_count = len(d["cpu_stats"]["cpu_usage"]["percpu_usage"])
            cpu_percent = 0.0
            cpu_delta = float(d["cpu_stats"]["cpu_usage"]["total_usage"]) - \
                        float(d["precpu_stats"]["cpu_usage"]["total_usage"])
            system_delta = float(d["cpu_stats"]["system_cpu_usage"]) - \
                           float(d["precpu_stats"]["system_cpu_usage"])
            if system_delta > 0.0:
                cpu_percent = cpu_delta / system_delta * 100.0 * cpu_count
            return cpu_percent

        def calculate_blkio_bytes(d):
            # credit to sen
            # https://github.com/TomasTomecek/sen/blob/master/sen/util.py#L158
            bytes_stats = graceful_chain_get(d, "blkio_stats", "io_service_bytes_recursive")
            if not bytes_stats:
                return 0, 0
            r = 0
            w = 0
            for s in bytes_stats:
                if s["op"] == "Read":
                    r += s["value"]
                elif s["op"] == "Write":
                    w += s["value"]
            return r, w

        def calculate_network_bytes(d):
            # credit to sen
            # https://github.com/TomasTomecek/sen/blob/master/sen/util.py#L158
            networks = graceful_chain_get(d, "networks")
            if not networks:
                return 0, 0
            r = 0
            t = 0
            for if_name, data in networks.items():
                r += data["rx_bytes"]
                t += data["tx_bytes"]
            return r, t

        containers = self.client.containers.list()
        for c in containers:
            name = f"container '{c.name}'"
            self.add_field_value('status', c.status, device=name)
            stats = c.stats(stream=False)
            self.add_field_value('cpu', 100.0 * calculate_cpu_percent(stats), '%', device=name)
            r, t = calculate_network_bytes(stats)
            self.add_field_value('sent', t, 'bytes', device=name)
            self.add_field_value('recv', r, 'bytes', device=name)
            r, w = calculate_blkio_bytes(stats)
            self.add_field_value('read', r, 'bytes', device=name)
            self.add_field_value('written', w, 'bytes', device=name)


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
    'gs108e': CheckNetgearGS108E,
    'ups': CheckUPS,
    'docker': CheckDocker
}
