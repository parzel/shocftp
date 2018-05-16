#!/usr/bin/env python

import shodan
import sys
import argparse
import ftplib

# CONFIG
USER = "anonymous"
PASSWORD = "anonymous@nosite.com"
VERBOSE = False
FILENAME = ''

def indent(text, amount, ch=' '):
        padding = amount * ch
        return ''.join(padding+line for line in text.splitlines(True))

def CrawlAddress(host_adress):
        print '    '+'Try to login with %s:%s' %(USER, PASSWORD)
        try:
                # Open connection
                ftp = ftplib.FTP(host_adress, USER, PASSWORD)

                # List dir
                file_list = str(ftp.dir())
                #print indent(file_list,4) 
        except ftplib.all_errors, e:
                print 'Error: %s' % e
                return
        if FILENAME:
                if FILENAME in str(file_list):
                        print '    '+'=> Found a match'


def StartShodanSearch(api_key, count_until):
        # Initialize Shodan api
        api = shodan.Shodan(api_key)
        # Wrap the request
        try:
                page = 0

                while True:
                        # Search Shodan for ftp (21) that sends 230, which is User logged in
                        results = api.search('port:21 230',page)
                        page+=1
                        search_results = results['total']

                        print 'Shodan query worked! %s Results found on page %i' % (search_results, page)
                        print '=> Investigating %i results' %count_until

                        # Query information about every individual FTP server
                        for result in results['matches']:

                                count_until-=1
                                if(count_until <0):
                                        return

                                host_adress = result['ip_str']
                                host_name = result['hostnames']
                                host_os = result['os']
                                host_data = result['data']

                                print ''
                                print 'host: '+host_adress

                                if host_name:
                                        print 'name: '+host_name[0]
                                else:
                                        print 'name: not available'

                                if VERBOSE:
                                        print 'fingerprint:'
                                        print host_data

                                CrawlAddress(host_adress)

        except shodan.APIError, e:
                print 'Error: %s' % e

def main():
        # Globals
        global VERBOSE, USER, PASSWORD, FILENAME

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

        args = parser.parse_args()

        if not args.results:
                parser.error('No result number provided.')
        if not args.api_key:
                parser.error('No API key provided.')
        if args.user:
                USER = args.user
        if args.password:
                PASSWORD = args.password
        VERBOSE = args.verbose
        FILENAME = str(args.file_name)
        

        print("~ shocftp v0.1 ~")
        if VERBOSE:
                print 'Verbose Mode enabled!'
        if FILENAME:
                print 'Looking for '+FILENAME
        StartShodanSearch(args.api_key, args.results)


if __name__ == "__main__":
    main()