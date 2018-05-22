#!/usr/bin/env python

import shodan
import sys
import argparse
import ftplib
import multiprocessing

# CONFIG
USER = 'anonymous'
PASSWORD = 'anonymous@'
VERBOSE = False
FILENAME = ''
TIMEOUT = 5
LEVEL = 0
WORKER = 1

def CrawlPath(ftp, host_adress, path='', level=0):
        if LEVEL-level==-1:
                return
        print level
        # List dir, if perm error just continue
        try:
                if path:
                        ftp.cwd(path)
                        print path
                else:
                        print '/'
                files = ftp.nlst()
        except ftplib.all_errors, e:
                if(e==ftplib.error_perm):
                        print '    '+'Permission denied'
                else:
                        print path
                        print '    '+'Error %s' %e
                        print
                return

        # Print every line
        for index, line in enumerate(files):
                print '    '+str(line)
        print

        # Check every line
        for index, line in enumerate(files):        
                # If it has a dot its possibly a file
                if not '.' in line:
                        CrawlPath(ftp, host_adress, path+'/'+line, level+1)
                else:
                         # Check for search match
                        if FILENAME:
                                if FILENAME in line:
                                        print '=> Found a match: '+'ftp://'+USER+':'+PASSWORD+'@'+host_adress+'/'+path+FILENAME


def CrawlHost(result):
        print '------------------------------------'
        
        # Parse Shodan result
        
        host_adress = result['ip_str']
        host_name = result['hostnames']
        host_os = result['os']
        host_data = result['data']

        print ''
        print 'Host: '+host_adress

        if host_name:
                print 'Name: '+host_name[0]
        else:
                print 'Name: not available'

        if VERBOSE:
                print 'Fingerprint:'
                print host_data

        try:
                # Open connection
                ftp = ftplib.FTP(host_adress, USER, PASSWORD,'',TIMEOUT)
        except ftplib.all_errors, e:
                print '=> Error while connecting: %s' % e
                return
        
        # Crawl Path
        CrawlPath(ftp, host_adress)

def StartWorker(index,q):
        try:
                while not q.empty():
                        print 'Worker %i getting a new job...' %index
                        myresult = q.get(0)
                        CrawlHost(myresult)
                        print 'Worker %i has finished!' %index
        except KeyboardInterrupt, IOError:
                print('Ok. Bye!')

def StartShodanSearch(api_key, count_until):
        # Initialize Shodan api
        api = shodan.Shodan(api_key)
        # Wrap the request
        try:
                # Search Shodan for ftp (21) that sends 230, which is User logged in
                results = api.search('230',0)
                #results = api.search('port:21 230',page)
                search_results = results['total']

                #print 'Shodan query worked! %s Results found on page %i' % (search_results, page)
                print '=> Investigating %i results' %count_until

                # Query information about every individual FTP server
                q = multiprocessing.Queue()
                for r in results['matches'][0:count_until]:
                        q.put(r)

                # Start worker
                for i in range(WORKER):
                        p = multiprocessing.Process(target=StartWorker, args=(i,q))
                        p.start()


        except shodan.APIError, e:
                print '=> Error: %s' % e

def main():
        # Globals
        global VERBOSE, USER, PASSWORD, FILENAME, LEVEL, TIMEOUT, WORKER

        # Instantiate the parser
        parser = argparse.ArgumentParser(description='Crawl anonymous accessible FTP server for files. It has a built in shodan search function.')

        # Require Count
        parser.add_argument('-r','--results', type=int, help='The number of results you want to crawl')

        # Require Api Key
        parser.add_argument('-a','--api_key', help='Your Shodan API key')

        # File to search for
        parser.add_argument('-f','--file_name', help='File name you want to crawl for')

        # Define User
        parser.add_argument('-u','--user', help='Define a specific user, standard is anonymous')

        # Define Password
        parser.add_argument('-p','--password', help='Define a specific password, standard is anonymous')

        # Verbose
        parser.add_argument('-v','--verbose', action='store_true', help='More output')

        # Level
        parser.add_argument('-l','--level', type=int, help='How deep you will crawl')

        # Timeout
        parser.add_argument('-t','--timeout', type=int, help='How many seconds until connection timeout')

        # Process
        parser.add_argument('-w','--worker', type=int, help='Number of Workers')


        args = parser.parse_args()

        if not args.results:
                parser.error('No result number provided.')
        if not args.api_key:
                parser.error('No API key provided.')
        if args.user:
                USER = args.user
        if args.password:
                PASSWORD = args.password
        if args.level:
                LEVEL = args.level
        if args.timeout:
                TIMEOUT = args.timeout
        if args.worker:
                WORKER = args.worker
        VERBOSE = args.verbose
        FILENAME = str(args.file_name)
        

        print '~ shocftp v0.1 ~\n'
        if VERBOSE:
                print 'Verbose Mode enabled!'
        if FILENAME:
                print '=> Looking for '+FILENAME
        if LEVEL != 0:
                print '=> Searching %i levels deep' %LEVEL
        if WORKER != 1:
                print '=> Using %i workers' %WORKER
        print '=> Timeout is %i seconds' %TIMEOUT
        print '=> Try to login with %s:%s' %(USER, PASSWORD)
        print '------------------------------------\n'
        StartShodanSearch(args.api_key, args.results)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('Ok. Bye!')