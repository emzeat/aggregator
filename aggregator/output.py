"""
 output.py

 Copyright (c) 2021 - 2022 Marius Zwicker
 All rights reserved.

 SPDX-License-Identifier: GPL-2.0-or-later

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Library General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
"""

import abc
from copy import deepcopy
import json
import logging

from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

from .check import Check, merge_dict


class Output:
    CONFIG = {}

    def __init__(self, name: str, config: dict):
        """Constructs a new Output instance

        :param name: The name of the output implementation
        :param config: The output configuration
        """
        import logging
        self.logger = logging.getLogger(f"aggregator.output.{name}")

    @abc.abstractmethod
    def write(self, results: list):
        pass


class OutputStdout(Output):
    """Write check results to stdout"""

    def __init__(self, config):
        super(OutputStdout, self).__init__('stdout', config)

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
        super(OutputInfluxDb, self).__init__('influxdb', config)
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
                field_point = deepcopy(point)
                field_point.field(
                    field[Check.Field.NAME], field[Check.Field.VALUE])
                if Check.Field.UNIT in field:
                    field_point.tag("unit", field[Check.Field.UNIT])
                points.append(field_point)
        self.write_api.write(self.bucket, self.org, points)


OUTPUTS = {
    'stdout': OutputStdout,
    'influx': OutputInfluxDb
}
