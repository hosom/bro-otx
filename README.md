# bro-otx
Integrate Bro with Alienvault OTX

Installation
------------

Unzip the project into your equivalent to /opt/bro/share/bro/site/

Add the following to your local.bro: @load site/otx

Add your api key to the bro-otx.conf configuration file. 

Add the bro-otx.py script into the crontab of a user with the ability to write to your bro scripts directories.
