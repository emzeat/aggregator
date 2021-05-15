import datetime
from smtplib import SMTP, SMTP_SSL
import abc
import jinja2

from .output import Output
from .check import Check


class Notification(Output):

    TEMPLATE = """
        <h2>Aggregator</h2>
        {{ failed | length }} Failures<br/>
        {{ passed | length }} Passes
    {%- for check in checked %}
        <hr style="border: 1px solid black;" />
        {%- if check[keys.STATUS] %}
        <h3 style="color:green;">
        {%- else %}
        <h3 style="color:red;">
        {%- endif %}
            {{ check[keys.NAME] | upper }} {{ check.get(keys.DEVICE, '') }}
        </h3>
        <p>Host: {{ check[keys.HOST] }}</p>
        <table>
        {%- for field in check[keys.FIELDS] %}
            <tr>
                <td>{{ field[fields.NAME] }}</td>
                <td>{{ field[fields.VALUE] }}</td>
                <td>{{ field[fields.UNIT] }}</td>
            </tr>
        {%- endfor %}
        </table>
    {%- endfor %}
    """
    MESSAGE_INTERVAL = datetime.timedelta(minutes=30)

    def __init__(self):
        import logging
        self.logger = logging.getLogger(f"aggregator.notification")
        self.last_failure_message = None

    @abc.abstractmethod
    def send_message(self, subject, contents):
        pass

    def write(self, results: list):
        checked = [r for r in results if r.get(Check.Result.STATUS, None) is not None]
        failed = [r for r in checked if not r.get(Check.Result.STATUS)]
        passed = [r for r in results if r.get(Check.Result.STATUS)]
        template = jinja2.Template(Notification.TEMPLATE)
        keys = Check.Result
        fields = Check.Field
        if 0 == len(passed) or 0 != len(failed):
            now = datetime.datetime.now()
            if self.last_failure_message:
                time_to_next_message = Notification.MESSAGE_INTERVAL - (now - self.last_failure_message)
            else:
                time_to_next_message = datetime.timedelta(seconds=-1)
            if time_to_next_message.total_seconds() < 0:
                self.send_message('Aggregator found failure', template.render(locals()))
                self.last_failure_message = now
                self.logger.warning("Found failure, sent notification")
            else:
                self.logger.warning(f"Found failure, delaying notification for {time_to_next_message}")

        elif self.last_failure_message:
            self.send_message('Aggregator checks passed', template.render(locals()))
            self.logger.info("Failure is gone")
            self.last_failure_message = None


class MailNotification(Notification):

    def __init__(self, config):
        super().__init__()
        self.server = config['server']
        self.port = config.get('port', 0)
        self.recipient = config['recipient']
        self.user = config.get('user', None)
        self.password = config.get('password', None)
        self.use_tls = config.get('use_tls', False)
        self.use_ssl = config.get('use_ssl', False)
        self.from_address = config.get('from_address', 'noreply@aggregator.local')
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

    def send_message(self, subject, contents):
        pass
