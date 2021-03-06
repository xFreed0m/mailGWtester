# Python 3 script to test mail GW servers for malicious files
# made by @x_Freed0m

import sys
import argparse
import os.path
from random import randint
import time

import logging
from colorlog import ColoredFormatter

from smtplib import SMTP, SMTPRecipientsRefused, SMTPSenderRefused
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import uuid


def args_parse():
    data = "This email is part of a security testing approved by the Security department. Thank " \
           "you for your cooperation.\n"
    args_parser = argparse.ArgumentParser()
    input_group = args_parser.add_mutually_exclusive_group(
        required=True)  # get at least file or folder
    sleep_group = args_parser.add_mutually_exclusive_group(required=False)
    args_parser.add_argument('--targets', help="SMTP target server address or file containing "
                                               "SMTP servers list", required=True)
    args_parser.add_argument('-p', '--port', help="SMTP target server port to use (default is 25)",
                             type=int, default=25)
    args_parser.add_argument('-t', '--toaddr', help="The recipient address (To)")
    args_parser.add_argument('-fa', '--fromaddr', help="the sender address (From)")
    args_parser.add_argument('-d', '--data', help="The email body content (data)", default=data)
    args_parser.add_argument('-s', '--subject', help="the Subject to use in the email, default is "
                                                     '"SMTP Pentest"', default="SMTP server "
                                                                               "Pentest")
    args_parser.add_argument('--debug', help="debug mode switch - to print all the server "
                                             "commands and output to stdout", action="store_true")
    input_group.add_argument('-F', '--folder',
                             help="Folder containing multiple files to attach (one per mail)")
    input_group.add_argument('-f', '--file', help="Single file to attach")
    sleep_group.add_argument('-sl', '--sleep', type=int,
                             help="Throttle the attempts to one attempt every # seconds, "
                                  "can be randomized by passing the value 'random' - default is 0",
                             default=0)
    sleep_group.add_argument('-r', '--random', nargs=2, type=int, metavar=(
        'minimum_sleep', 'maximum_sleep'), help="Randomize the time between each authentication "
                                                "attempt. Please provide minimum and maximum "
                                                "values in seconds")
    return args_parser.parse_args()


def configure_logger():
    """
        This function is responsible to configure logging object.
    """

    global LOGGER
    LOGGER = logging.getLogger("mailGWtester")
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
    fh = logging.FileHandler("mailGWtester.log")  # Handler to print the logs to a file in append mode
    fh.setFormatter(formatter)
    LOGGER.addHandler(fh)


def excptn(e):
    LOGGER.critical("[!] Exception: " + str(e))
    sys.exit(1)


def banner():
    print("""
                      _ _  _______          ___            _            
                     (_) |/ ____\ \        / / |          | |           
      _ __ ___   __ _ _| | |  __ \ \  /\  / /| |_ ___  ___| |_ ___ _ __ 
     | '_ ` _ \ / _` | | | | |_ | \ \/  \/ / | __/ _ \/ __| __/ _ \ '__|
     | | | | | | (_| | | | |__| |  \  /\  /  | ||  __/\__ \ ||  __/ |   
     |_| |_| |_|\__,_|_|_|\_____|   \/  \/    \__\___||___/\__\___|_|   
                                                                        
                                                                        
    \nMade by @x_Freed0m
    """)


def mail_test(smtp_targets, port, fromaddr, toaddr, data, subject, debug, attachment):
    for target in smtp_targets:
        LOGGER.info("[*] Checking host " + target + ':' + str(port))
        try:
            if fromaddr and toaddr:  # checking we have both to and from addresses
                with SMTP(target, port) as current_target:
                    if debug:
                        current_target.set_debuglevel(1)
                    current_target.ehlo_or_helo_if_needed()

                    # Create a multipart message and set headers
                    message = MIMEMultipart()
                    message["From"] = fromaddr
                    message["To"] = toaddr
                    message["Subject"] = subject
                    # message["Bcc"] = receiver_email  # Recommended for mass emails

                    # Add UUID to body of the email
                    generated_uid = gen_uid()
                    message.attach(MIMEText(data + str(generated_uid), "plain"))

                    filename = os.path.basename(attachment)
                    # file = open(Path(str(attachment)), "rb")
                    file = open(attachment, "rb")
                    p = MIMEBase('application', 'octet-stream')
                    p.set_payload(file.read())
                    encoders.encode_base64(p)
                    p.add_header('Content-Disposition', "attachment; filename= %s" % filename)

                    message.attach(p)
                    text = message.as_string()

                    current_target.sendmail(fromaddr, toaddr, text)
                    LOGGER.info("[+] Mail sent FROM: %s TO: %s, msg UUID: %s, attachment: %s \n" %
                                (str(fromaddr), str(toaddr), str(generated_uid), str(attachment)))
            else:
                LOGGER.critical("[!] Problem with FROM and/or TO address!")
                sys.exit(1)
        except (SMTPRecipientsRefused, SMTPSenderRefused) as e:
            LOGGER.critical("[!] SMTP Error: %s\n[-] SMTP refuse!", str(e))
        except ConnectionRefusedError:
            LOGGER.critical("[!] Connection refused by host %s", target)
        except KeyboardInterrupt:
            LOGGER.critical("[!] [CTRL+C] Stopping...")
            sys.exit(1)
        except Exception as e:
            excptn(e)


def folder(path):
    return [os.path.join(path, f) for f in os.listdir(path)]


def random_time(minimum, maximum):
    sleep_amount = randint(minimum, maximum)
    return sleep_amount


def gen_uid():
    generated_uid = uuid.uuid4()
    return generated_uid


def main():
    args = args_parse()
    configure_logger()
    banner()
    min_sleep, max_sleep = 0, 0
    random = False
    sleep_time = 0
    if args.random:
        random = True
        min_sleep = args.random[0]
        max_sleep = args.random[1]
    if os.path.exists(args.targets):  # checking if the switch is single entry or a file
        smtp_targets = open(args.targets).read().splitlines()
    else:
        smtp_targets = [args.targets]
    try:
        if args.file:
            attachment = args.file
            mail_test(smtp_targets, args.port, args.fromaddr, args.toaddr, args.data, args.subject, args.debug,
                      attachment)
        elif args.folder:
            if not os.path.exists(args.folder):
                LOGGER.error("Path doesn't exist, please recheck")
            attachment_list = folder(args.folder)
            for attachment in attachment_list:
                mail_test(smtp_targets, args.port, args.fromaddr, args.toaddr, args.data, args.subject, args.debug,
                          attachment)
                if random is True:
                    sleep_time = random_time(min_sleep, max_sleep)
                    time.sleep(float(sleep_time))
                else:
                    time.sleep(float(sleep_time))
        else:
            LOGGER.warning('Could not find it! Did you specify existing file or folder?')
    except KeyboardInterrupt:
        LOGGER.critical("[CTRL+C] Stopping the tool")
        sys.exit(1)
    except Exception as e:
        excptn(e)


if __name__ == '__main__':
    main()

# TODO:
# fix UUID bug
# Code cleanup
# Improve logging
# add more SMTP errors
#

# v: 0.00011
