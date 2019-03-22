
from email.mime.text import MIMEText
from subprocess import Popen, PIPE

email = "vsmahidhar@gmail.com"
msg = MIMEText("Here is the body of my message")
msg["From"] = email
msg["To"] = email

msg["Subject"] = "This is the subject."
p = Popen(["/usr/sbin/sendmail", "-t", "-oi"], stdin=PIPE)
p.communicate(msg.as_string().encode())