shocftp v0.2
========================================================

Crawl (anonymous) accessible FTP server for files

Features
--------

- Use builtin Shodan search
- Multiprocessing
- Define own user/password combination
- Define level of crawling depth
- Auto generate download links for files

Installation
------------

Install the shodan library

.. code-block:: bash

    $ sudo python3 -m pip install shodan

You are ready to go

.. code-block:: bash

    $ ./crawler.py --help
