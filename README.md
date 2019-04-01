# bro-otx

Integrate Zeek with AlienVault OTX. 

## Manual Installation

* Unzip the project.
* Move the **scripts** directory to your Zeek **site** directory and rename it to **otx**.
* Create a virtual environment for the **zeek_otx.py** script to run in.
    * `virtualenv -p python3 .venv` inside of the **otx** directory.
* Install dependencies `pip install -r requirements.txt`
* Add your **api_key** to **zeek_otx.conf**.
* Run **zeek_otx.py** for the first time.
* Verify that **otx.dat** has been created.
* Add `@load site/otx` to your **local.bro**
* **Optional**: Add **zeek_otx.py** to your crontab for regular pulse sync.