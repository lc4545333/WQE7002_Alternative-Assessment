import smtplib
import re
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import datetime
import os
import time


# addr check
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

MAIL_STORE_DIR = 'stored_mails'
if not os.path.exists(MAIL_STORE_DIR):
    os.makedirs(MAIL_STORE_DIR)


def validate_email(email):
    return bool(EMAIL_REGEX.match(email))


def save_email_to_file(email_data):
    filename = os.path.join(MAIL_STORE_DIR, f'mail_{int(time.time())}.json')
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(email_data, f, ensure_ascii=False, indent=2)
    return filename


def send_email(sender, recipients, subject, content, smtp_server, smtp_port, username, password,is_html=True):
    domain_groups = {}
    for recipient in recipients:
        domain = recipient.split('@')[1]
        if domain not in domain_groups:
            domain_groups[domain] = []
        domain_groups[domain].append(recipient)

    results = []

    # 对每个域发送邮件
    for domain, domain_recipients in domain_groups.items():
        try:
            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = ', '.join(domain_recipients)
            msg['Subject'] = subject
            if is_html:
                print(1)
                msg.attach(MIMEText(content, 'html', 'utf-8'))
            else:
                msg.attach(MIMEText(content, 'plain', 'utf-8'))


            # 连接SMTP服务器
            with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
                #server.starttls() 163邮箱不支持这玩意儿
                server.login(username, password)
                server.set_debuglevel(1)
                # 发送邮件
                server.send_message(msg)

                results.append({
                    'domain': domain,
                    'status': 'success',
                    'recipients': domain_recipients
                })

        except smtplib.SMTPRecipientsRefused as e:
            results.append({
                'domain': domain,
                'status': 'error',
                'message': '收件人地址无效',
                'error_code': str(e)
            })
        except smtplib.SMTPAuthenticationError:
            results.append({
                'domain': domain,
                'status': 'error',
                'message': 'SMTP认证失败'
            })
        except Exception as e:
            results.append({
                'domain': domain,
                'status': 'error',
                'message': str(e)
            })

    return results


def handle_send(content=None):
    sender = '15009461387@163.com'
    recipients = ['23099506@siswa.um.edu.my']
    now = datetime.datetime.now()
    formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")
    subject = 'Vulnerability Statistics ' + formatted_time
    # 验证发件人地址
    if not validate_email(sender):
        return 'Error - Sender E-Mail address incorrect'

    # 验证收件人地址
    recipients = [r.strip() for r in recipients]
    invalid_recipients = [r for r in recipients if not validate_email(r)]

    if invalid_recipients:
        return f'Error - Recipient E-Mail address incorrect: {invalid_recipients}'

    if not content:
        return 'Error - Email content is empty'
    # 保存邮件
    saved_file = save_email_to_file({
        'sender': sender,
        'recipients': recipients,
        'subject': subject,
        'content': content
    })


    # 发送邮件
    results = send_email(
        sender,
        recipients,
        subject,
        content,
        'smtp.163.com',
        465,
        '15009461387@163.com',
        'RTgKTJLkGX8U59hz',
        True
    )

    return {
        'status': 'success',
        'saved_file': saved_file,
        'send_results': results
    }

def send_report_email():
    html_path = 'vulnerability_report_email.html'
    try:
        with open(html_path, 'r', encoding='utf-8') as file:
            html_content = file.read()
        result = handle_send(content=html_content)
        return result
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Failed to send report email: {str(e)}'
        }
