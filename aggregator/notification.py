"""
 notification.py

 Copyright (c) 2021 Marius Zwicker
 All rights reserved.

 SPDX-License-Identifier: AGPL-3.0-only

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import datetime
from smtplib import SMTP, SMTP_SSL
import abc
import jinja2

from .output import Output
from .check import Check


class Notification(Output):

    TEMPLATE = """
        <table>
            <tr>
                <td><b style="color:red; text-align:right;">{{ failed | length }}</b></td>
                <td>Failures</td>
            </tr>
            <tr>
                <td><b style="color:green; text-align:right;">{{ passed | length }}</b></td>
                <td>Passes</td>
            </tr>
        </table>
    {%- macro render_check(check) %}
        <hr style="border: 1px solid black;" />
        {%- if check[keys.STATUS] %}
        <h3 style="color:green;">
        {%- else %}
        <h3 style="color:red;">
        {%- endif %}
            {{ check[keys.NAME] | upper }} {{ check.get(keys.DEVICE, '') }}
        </h3>
        <table>
            <tr>
                <td style="text-align:right;"><b>host</b></td>
                <td colspan="2">{{ check[keys.HOST] }}</td>
            </tr>
            <tr>
                <td style="text-align:right;"><b>last run</b></td>
                <td colspan="2">{{ check[keys.TIME].strftime('%d.%m.%Y %H:%M:%S') }}</td>
            </tr>
        {%- for field in check[keys.FIELDS] %}
            <tr>
                <td style="text-align:right;"><b>{{ field[fields.NAME] }}</b></td>
                <td>{{ field[fields.VALUE] }}</td>
                <td>{{ field[fields.UNIT] }}</td>
            </tr>
        {%- endfor %}
        </table>
    {%- endmacro %}
    {%- for check in failed %}
        {{ render_check(check) }}
    {%- endfor %}
    {%- for check in passed %}
        {{ render_check(check) }}
    {%- endfor %}
    """
    MESSAGE_INTERVAL = datetime.timedelta(minutes=30)

    def __init__(self, name: str, config: dict):
        """Constructs a new Notification instance

        :param name: The name of the output implementation
        :param config: The output configuration
        """
        super(Notification, self).__init__(name, config)
        import logging
        self.logger = logging.getLogger(f"aggregator.notification.{name}")
        self.last_failure_message = None
        self.checked = {}
        self.failed = {}
        self.passed = {}
        self.last_len_failed = -1
        self.last_len_passed = -1

    @abc.abstractmethod
    def send_message(self, subject, contents):
        pass

    @staticmethod
    def make_key(check):
        """Creates a key out of the given check entry"""
        return f"{check[Check.Result.HOST]}/{check[Check.Result.NAME]}/{check.get(Check.Result.DEVICE, 'nodevice')}"

    def write(self, results: list):
        for c in [r for r in results if r.get(Check.Result.STATUS, None) is not None]:
            self.checked[Notification.make_key(c)] = c
        checked = self.checked.values()
        for f in [r for r in checked if not r.get(Check.Result.STATUS)]:
            self.failed[Notification.make_key(f)] = f
            try:
                del self.passed[Notification.make_key(f)]
            except Exception:
                pass
        failed = self.failed.values()
        for p in [r for r in results if r.get(Check.Result.STATUS)]:
            self.passed[Notification.make_key(p)] = p
            try:
                del self.failed[Notification.make_key(p)]
            except Exception:
                pass
        passed = self.passed.values()
        keys = Check.Result
        fields = Check.Field
        template = jinja2.Template(Notification.TEMPLATE)
        if 0 == len(passed) or 0 != len(failed):
            now = datetime.datetime.now()
            if self.last_failure_message:
                time_to_next_message = Notification.MESSAGE_INTERVAL - \
                    (now - self.last_failure_message)
            else:
                time_to_next_message = datetime.timedelta(seconds=-1)
            # send a message on a change of passes, failures or when MESSAGE_INTERVAL has passed
            if time_to_next_message.total_seconds() < 0 \
                    or self.last_len_failed != len(failed) \
                    or self.last_len_passed != len(passed):
                self.send_message('Aggregator found failure',
                                  template.render(locals()))
                self.last_failure_message = now
                self.last_len_failed = len(failed)
                self.last_len_passed = len(passed)
                self.logger.warning("Found failure, sent notification")
            else:
                self.logger.warning(
                    f"Found failure, delaying notification for {time_to_next_message}")

        elif self.last_failure_message:
            self.send_message('Aggregator checks passed',
                              template.render(locals()))
            self.logger.info("Failure is gone")
            self.last_failure_message = None


class MailNotification(Notification):

    def __init__(self, config):
        super().__init__('mail', config)
        self.server = config['server']
        self.port = config.get('port', 0)
        self.recipient = config['recipient']
        self.user = config.get('user', None)
        self.password = config.get('password', None)
        self.use_tls = config.get('use_tls', False)
        self.use_ssl = config.get('use_ssl', False)
        self.from_address = config.get(
            'from_address', 'noreply@aggregator.local')
        self.from_sender = config.get('from_sender', 'aggregator')

    def send_message(self, subject, contents):
        msg = f'''Subject: {subject}
Content-Type: text/html; charset=utf-8
To: {self.recipient}
From: "{self.from_sender}" <{self.from_address}>
<body>
    <html style="background: #fff; font-family: helvetica, sans, tahoma; font-size: 11pt;">
        {contents}
    </html>
</body>
'''
        if self.use_ssl:
            conn = SMTP_SSL(self.server, self.port)
        else:
            conn = SMTP(self.server, self.port)
            if self.use_tls:
                conn.starttls()
        conn.set_debuglevel(False)
        if self.user and self.password:
            conn.login(self.user, self.password)
        try:
            conn.sendmail(self.from_address, self.recipient, msg)
        finally:
            conn.close()


class NullNotification(Notification):

    def __init__(self):
        super().__init__('null', {})

    def send_message(self, subject, contents):
        pass

    def write(self, results: list):
        pass
