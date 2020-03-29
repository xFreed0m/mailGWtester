# Python 3 script to test SMTP server for spoofing vulnerabilities
# made by @x_Freed0m

import sys
import argparse
import logging
from colorlog import ColoredFormatter
import os.path
from smtplib import SMTP, SMTPRecipientsRefused, SMTPSenderRefused

# import email, smtplib, ssl

from email import encoders
# from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from email.mime.application import MIMEApplication
from pathlib import Path


def args_parse():
    data = "This email is part of a security testing approved by the Security department. Thank " \
           "you for your cooperation, Please forward this email to \n"
    args_parser = argparse.ArgumentParser()
    args_parser.add_argument('--targets', help="SMTP target server address or file containing "
                                               "SMTP servers list", required=True)
    args_parser.add_argument('-p', '--port', help="SMTP target server port to use (default is 25)",
                             type=int, default=25)
    # args_parser.add_argument('--tester', help="Pentester email address", required=True)
    args_parser.add_argument('-t', '--toaddr', help="The recipient address (To)")
    args_parser.add_argument('-f', '--fromaddr', help="the sender address (From)")
    args_parser.add_argument('-d', '--data', help="The email content (data)", default=data)
    args_parser.add_argument('-a', '--address', help="Addresses to use with VRFY, can be single "
                                                     "or a file")
    args_parser.add_argument('-s', '--subject', help="the Subject to use in the email, default is "
                                                     '"SMTP Pentest"', default="SMTP server "
                                                                               "Pentest")
    args_parser.add_argument('-x', '--attachments', help="a file you wish to attach to the email", default=None)
    args_parser.add_argument('--debug', help="debug mode switch - to print all the server "
                                             "commands and output to stdout", action="store_true")
    return args_parser.parse_args()


def configure_logger():
    """
        This function is responsible to configure logging object.
    """

    global LOGGER
    LOGGER = logging.getLogger("SMTPTester")
    # Set logging level
    LOGGER.setLevel(logging.INFO)

    # Create console handler
    log_colors = {
        'DEBUG': 'bold_red',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red',
    }
    formatter = "%(log_color)s[%(asctime)s] - %(message)s%(reset)s"
    formatter = ColoredFormatter(formatter, datefmt='%d-%m-%Y %H:%M', log_colors=log_colors)
    ch = logging.StreamHandler(sys.stdout)  # Handler to print the logs to stdout
    ch.setFormatter(formatter)
    LOGGER.addHandler(ch)
    fh = logging.FileHandler("SMTPTester.log")  # Handler to print the logs to a file in append mode
    fh.setFormatter(formatter)
    LOGGER.addHandler(fh)


def excptn(e):
    LOGGER.critical("[!] Exception: " + str(e))
    exit(1)


def banner():
    print("""
     #####  #     # ####### ######  #######                                   
    #     # ##   ##    #    #     #    #    ######  ####  ##### ###### #####  
    #       # # # #    #    #     #    #    #      #        #   #      #    # 
     #####  #  #  #    #    ######     #    #####   ####    #   #####  #    # 
          # #     #    #    #          #    #           #   #   #      #####  
    #     # #     #    #    #          #    #      #    #   #   #      #   #  
     #####  #     #    #    #          #    ######  ####    #   ###### #    #
    \nMade by @x_Freed0m
    """)


def mail_test(smtp_targets, port, fromaddr, recipient, data, subject, debug, attachment_list):
    for target in smtp_targets:
        LOGGER.info("[*] Checking host " + target + ':' + str(port))
        LOGGER.info("[*] Testing for mail relaying (external)")
        try:
            if fromaddr and recipient:  # checking we have both to and from addresses
                with SMTP(target, port) as current_target:
                    if debug:
                        current_target.set_debuglevel(1)
                    current_target.ehlo_or_helo_if_needed()
                    # msg = MIMEText(data)
                    # msg['Subject'] = subject
                    # msg['From'] = fromaddr
                    # msg['To'] = recipient
################
                    # Create a multipart message and set headers
                    message = MIMEMultipart()
                    message["From"] = fromaddr
                    message["To"] = recipient
                    message["Subject"] = subject
                    # message["Bcc"] = receiver_email  # Recommended for mass emails

                    # Add body to email
                    message.attach(MIMEText(data, "plain"))

                    # filename = attachment  # In same directory as script

                    # Open PDF file in binary mode
                    # with open(attachment, "rb") as attached:
                    #     # Add file as application/octet-stream
                    #     # Email client can usually download this automatically as attachment
                    #     part = MIMEBase("application", "octet-stream")
                    #     part.set_payload(attached.read())

                    for folder in attachment_list:
                        for file in Path(folder).iterdir():
                            attachment = MIMEApplication(file.read_bytes())

                    # Encode file in ASCII characters to send by email
                    encoders.encode_base64(attachment)

                    # Add header as key/value pair to attachment part
                    attachment.add_header(
                        "Content-Disposition",
                        "attachment; filename= {attachment}",)

                    # Add attachment to message and convert message to string
                    message.attach(attachment)
                    text = message.as_string()
##############

                    current_target.sendmail(fromaddr, recipient, text)
                    LOGGER.critical("[+] Mail sent FROM: %s TO: %s", target, fromaddr, recipient)
            else:
                LOGGER.critical("[!] Problem with FROM and/or TO address!")
                exit(1)
        except (SMTPRecipientsRefused, SMTPSenderRefused) as e:
            LOGGER.critical("[!] SMTP Error: %s\n[-] SMTP refuse!", str(e), target)
        except ConnectionRefusedError:
            LOGGER.critical("[!] Connection refused by host %s", target)
        except KeyboardInterrupt:
            LOGGER.critical("[!] [CTRL+C] Stopping...")
            exit(1)
        except Exception as e:
            excptn(e)


def main():
    args = args_parse()
    configure_logger()
    banner()
    if os.path.exists(args.targets):  # checking if the switch is single entry or a file
        smtp_targets = open(args.targets).read().splitlines()
    else:
        smtp_targets = [args.targets]
    if os.path.exists(args.attachment):  # checking if the switch is single entry or a file
        attachment_list = open(args.attachment).read().splitlines()
    else:
        attachment_list = [args.attachments]
    mail_test(smtp_targets, args.port, args.fromaddr, args.tester, args.data, args.subject, args.debug, attachment_list)


if __name__ == '__main__':
    main()
