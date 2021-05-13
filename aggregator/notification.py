from smtplib import SMTP, SMTP_SSL
import abc


class Notification:

    @abc.abstractmethod
    def send_message(self, subject, contents):
        pass


class MailNotification(Notification):

    def __init__(self, config):
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
