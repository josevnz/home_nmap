# Installation

First create your virtual environment
```shell
python3 -m venv ~/virtualenv/home_nmap
. ~/virtualenv/home_nmap/bin/activate
python -m pip install --upgrade pip
```

Then clone the code from GitHub:

```shell
git clone git@github.com:josevnz/nmap_home.git
```

After that compile your wheel and install it

```shell
python setup.py bdist_wheel
pip install home_nmap-0.0.1-py3-none-any.whl
```

Or deploy it in 'developer' mode

```shell
python setup.py develop
```

# Generating network diagrams

Some diagrams for this article where generated with 'diagrams'. You can install just diagram and then run the scripts:

If you install the project as explained above you should be able to run the 'generate_diagrams.py' script.

# Running the webservice

Assuming that you installed the application in your virtual environment: 

```shell
. ~/virtualenv/home_nmap/bin/activate
uvicorn home_nmap:main:app --reload
```
Then use a browser and go to [localhost](http://127.0.0.1:8000/docs#/)
