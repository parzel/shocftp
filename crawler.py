#!/usr/bin/env python3

import shodan
import sys
import argparse
import ftplib
import multiprocessing
import logging
import datetime

# CONFIG
USER = 'anonymous'
PASSWORD = 'anonymous@'
VERBOSE = False
FILENAME = ''
TIMEOUT = 5
LEVEL = 0
WORKER = 1

def CrawlPath(ftp, host_adress, path='', level=0):
        output = ''
        if LEVEL-level==-1:
                return output
        #output += level
        # List dir, if perm error handle
        try:
                if path:
                        ftp.cwd(path)
                        output += str(path) + '\n'
                else:
                        output += '/\n'
                files = ftp.nlst()

        except ftplib.all_errors as e:               
                # Maybe is a file
                if '550' in str(e):          
                        if FILENAME:
                                if FILENAME in path:
                                        output += 'Found a match: '+'ftp://'+USER+':'+PASSWORD+'@'+host_adress+'/'+path+'\n'
                        
                # Some other error
                else:
                    output += path+': Error '+str(e)+'\n'    

                return output

        # output += every line
        for index, line in enumerate(files):
                output += '    '+str(line)+'\n'

        # Check every line
        for index, line in enumerate(files):        
                        
                #Try to crawl anyway
                if line != '.' and line != '..':
                        output += CrawlPath(ftp, host_adress, path+'/'+line, level+1)
        
        return output                             


def CrawlHost(result):
        output = '------------------------------------\n\n'
        
        # Parse Shodan result  
        host_adress = result['ip_str']
        host_name = result['hostnames']
        host_os = result['os']
        host_data = result['data']

        output += 'Host: '+host_adress+'\n'

        if host_name:
                output += 'Name: '+host_name[0]+'\n'
        else:
                output += 'Name: Not available'+'\n'

        if VERBOSE:
                output += 'Fingerprint:'+'\n'
                output += host_data+'\n'

        try:
                # Open connection
                ftp = ftplib.FTP(host_adress, USER, PASSWORD,'',TIMEOUT)
        except ftplib.all_errors as e:
                output += '=> Error while connecting: '+str(e)+'\n'
                return output
        
        # Crawl Path
        output += CrawlPath(ftp, host_adress)
        print(output)

def StartShodanSearch(api_key, count_until):
        # Initialize Shodan api
        api = shodan.Shodan(api_key)
        # Wrap the request
        try:
                # Search Shodan for ftp (21) that sends 230, which is User logged in
                results = api.search('230',0)
                #results = api.search('port:21 230',page)
                search_results = results['total']

        except shodan.APIError as e:
                print('=> Error: '+str(e))
                return
        
        #print 'Shodan query worked! %s Results found on page %i' % (search_results, page)
        print('=> Investigating '+str(count_until)+' results\n')

        # Query information about every individual FTP server
        q = multiprocessing.Queue()
        for r in results['matches'][0:count_until]:
                q.put(r)

        # Start worker
        try:
                pool = multiprocessing.Pool(processes=WORKER)           
                pool.map(CrawlHost, results['matches'][0:count_until])
                pool.close()
                pool.join()
                
        except (KeyboardInterrupt, IOError):
                print('\nCaught KeyboardInterrupt, terminating workers\n')
                pool.terminate()
                sys.exit()
                
        else:
                print('Queue is empty. Exiting...')
                
                
                                

def main():
        # Globals
        global VERBOSE, USER, PASSWORD, FILENAME, LEVEL, TIMEOUT, WORKER

        # Instantiate the parser
        parser = argparse.ArgumentParser(description='Crawl FTP server for files. It has a built in Shodan search function.')

        # Require Count
        parser.add_argument('-r','--results', type=int, help='The number of results you want to crawl')

        # Require Api Key
        parser.add_argument('-a','--api_key', help='Your Shodan API key')

        # File to search for
        parser.add_argument('-f','--file_name', help='File name you want to generate download links for')

        # Define User
        parser.add_argument('-u','--user', help='Define a specific user, standard is anonymous')

        # Define Password
        parser.add_argument('-p','--password', help='Define a specific password, standard is anonymous@')

        # Verbose
        parser.add_argument('-v','--verbose', action='store_true', help='More Shodan information about each ftp server')

        # Level
        parser.add_argument('-l','--level', type=int, help='How deep the crawler searches')

        # Timeout
        parser.add_argument('-t','--timeout', type=int, help='How many seconds until connection timeout')

        # Process
        parser.add_argument('-w','--worker', type=int, help='Number of Workers')

        # Output
        parser.add_argument('-o','--output', help='Output file for logging. Standard is stdout')


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
        if args.file_name:
                FILENAME = str(args.file_name)

        if args.output:
                #redirect stdout
                old_stdout = sys.stdout
                log_file = open(args.output,"w")
                sys.stdout = log_file
                

        print('~ shocftp v0.2 ~\n')
        if VERBOSE:
                print('Verbose Mode enabled!')
        if FILENAME:
                print('=> Looking for '+FILENAME)
        if LEVEL != 0:
                print('=> Searching '+str(LEVEL)+' levels deep')
        if WORKER != 1:
                print('=> Using '+str(WORKER)+' workers')
        print('=> Timeout is '+str(TIMEOUT)+' seconds')
        print('=> Try to login with '+USER+':'+PASSWORD)

        StartShodanSearch(args.api_key, args.results)

        if args.output:
                log_file.close()


if __name__ == "__main__":
        main()