import abc
import json
import logging

from influxdb_client import InfluxDBClient
from influxdb_client.client.write_api import SYNCHRONOUS

from .check import Check


class Output:
    @abc.abstractmethod
    def write(self, results: dict):
        pass


class OutputStdout(Output):
    def __init__(self, config):
        pass

    def write(self, results: dict):
        for r in results:
            entry = r
            entry[Check.Result.TIME] = str(r[Check.Result.TIME])
            print(json.dumps(entry, indent='  '))


class OutputInfluxDb(Output):

    def __init__(self, config):
        self.logger = logging.getLogger("aggregator.output.influxdb")
        self.token = config['token']
        self.org = config['org']
        self.bucket = config['bucket']

        self.client = InfluxDBClient(url="https://influx.heimdall.mlba-team.de", token=self.token)
        self.write_api = self.client.write_api(write_options=SYNCHRONOUS)

    def write(self, results):
        points = []
        for result in results:
            point = {
                "measurement": result[Check.Result.NAME],
                "tags": {
                    "host": result[Check.Result.HOST]
                },
                "time": result[Check.Result.TIME].isoformat(),
                "fields": {}
            }
            if Check.Result.DEVICE in result:
                point["tags"]["device"] = result[Check.Result.DEVICE]
            for field in result[Check.Result.FIELDS]:
                point['fields'][field[Check.Field.NAME]] = field[Check.Field.VALUE]
                if Check.Field.UNIT in field:
                    point['fields'][f"{field[Check.Field.NAME]}_unit"] = field[Check.Field.UNIT]

            points.append(point)
        self.logger.debug(json.dumps(points, indent='  '))
        self.write_api.write(self.bucket, self.org, points)


OUTPUTS = {
    'stdout': OutputStdout,
    'influx': OutputInfluxDb
}