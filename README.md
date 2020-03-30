# mailGWtester

mailGWtester is a python3 tool to test email GW for filtering malicious files.

## How to use it
First, install the needed dependencies:
```
pip3 install -r requirments.txt
```
Second, run the tool with the needed flags:
```
python3 mailGWtest.py --targets [mail GW IP or file containing multiple IPs]
 -t [TO address] -fa [FROM address] -f/-F [file or folder with malicious attachments]
``` 

### Issues, bugs and other code-issues
Yeah, I know, this code isn't the best. I'm fine with it as I'm not a developer and this is part of my learning process.
If there is an option to do some of it better, please, let me know.

_Not how many, but where._
