# home_nmap

**Home NMAP** is a small collection of scripts to make it easier to NMAP to identify services on your home network (see scripts directory):

* nmap_scan_rpt.py: Will parse the results of a nmap run with -oX and correlate the results with advisories from NDIS
* home_scan.py: Will scan your home network automatically and show services, correlated with advisories from NDIS.
* generate_diagrams.py: A script used to generate the diagrams on the tutorial directory.

The Nmap scanner can be run as a web service (after installation):

```shell
uvicorn home_nmap.main:app --host 0.0.0.0 --port 8000 --reload
```

And on a different terminal (example testing with curl):
```shell
curl --fail --silent http://127.0.0.1:8000/docs#
```

To see what is available

# Installation

## Developer mode
```shell
python3 -m venv ~/virtualenv/home_nmap/
. ~/virtualenv/home_nmap/bin/activate
python setup.py develop --uninstall
```

## Wheel
```shell
python3 -m venv ~/virtualenv/home_nmap/
. ~/virtualenv/home_nmap/bin/activate
python setup.py bdist_wheel
pip install dist/home_nmap-0.0.1-py3-none-any.whl
```

Once installed you can run any of the following scripts:
* generate_diagrams.py
* home_nmap_confgen.py
* home_scan.py
* nmap_scan_rpt.py

# Running the web application

If you have your self-signed certificates then you can run the web application like this (see the included tutorial):
```shell
uvicorn home_nmap.main:app \
--host $HOSTNAME \
--port 8443 \
--ssl-keyfile=/etc/pki/ca-trust/source/anchors/$host-server-key.pem \
--ssl-certfile=/etc/pki/ca-trust/source/anchors/$host-server.pem
```

Or the alternative:

```shell
uvicorn home_nmap.main:app \
--host $HOSTNAME \
--port 8000
```

# Tutorial
You can read the tutorial/README.md file from your terminal like this (without installing all the software):

```shell
python3 -m venv ~/virtualenv/home_nmap
. ~/virtualenv/home_nmap/bin/activate
python -m pip install --upgrade pip rich
python -m rich.markdown tutorial/README.md
```
