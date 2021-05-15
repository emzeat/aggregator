import abc
import json
import logging

from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

from .check import Check, merge_dict


class Output:
    CONFIG = {}

    @abc.abstractmethod
    def write(self, results: list):
        pass


class OutputStdout(Output):
    """Write check results to stdout"""

    def __init__(self, config):
        pass

    def write(self, results: list):
        for r in results:
            entry = r
            entry[Check.Result.TIME] = str(r[Check.Result.TIME])
            print(json.dumps(entry, indent='  '))


class OutputInfluxDb(Output):
    CONFIG = merge_dict(Output.CONFIG, {
        'token': 'str: Token to authenticate with the influxdb instance',
        'org': 'str: Organization to use in the influxdb instance',
        'bucket': 'str: Bucket to store the check results in',
        'url': 'str: Url to connect to the influxdb instance'
    })
    """Send check results to an influxdb instance"""

    def __init__(self, config):
        self.logger = logging.getLogger("aggregator.output.influxdb")
        self.token = config['token']
        self.org = config['org']
        self.bucket = config['bucket']
        self.url = config['url']

        self.client = InfluxDBClient(url=self.url, token=self.token)
        self.write_api = self.client.write_api(write_options=SYNCHRONOUS)

    def write(self, results):
        points = []
        for result in results:
            point = Point(result[Check.Result.NAME]) \
                .tag("host", result[Check.Result.HOST]) \
                .time(result[Check.Result.TIME].isoformat())
            if Check.Result.DEVICE in result:
                point = point.tag("device", result[Check.Result.DEVICE])
            for field in result[Check.Result.FIELDS]:
                point = point.field(field[Check.Field.NAME], field[Check.Field.VALUE])
                if Check.Field.UNIT in field:
                    point = point.field(f"{field[Check.Field.NAME]}_unit", field[Check.Field.UNIT])
            points.append(point)
        self.write_api.write(self.bucket, self.org, points)


OUTPUTS = {
    'stdout': OutputStdout,
    'influx': OutputInfluxDb
}
