#!/usr/bin/python3 -u

import shodan
import json
import math

class ShodanInterface():

    def __init__(self, api_key = None):
        if not api_key:
            with open("api.key", "r") as key_file:
                api_key = key_file.read()
        self.api = shodan.Shodan(api_key)

    def dump_query_results(self, pages = 1):
        pages = math.ceil(pages / 100.0)+1
        
        results = []
        for i in range (1, pages):
            try:
                # Search Shodan for ftp (21) that sends 230, which is User logged in
                results += self.api.search("230",i)["matches"]
                print(f"Processed page number {i}")

            except shodan.APIError as e:
                print("=> Error: "+str(e))
            
        print("=> Succesfull for "+str(len(results))+" results and "+str(pages))

        with open(f"hostsdb.json", "w") as db:
            json.dump(results, db, indent=4)

    def load_query_from_db(self):
        with open(f"hostsdb.json", "r") as db:
            results = json.load(db)
        for item in results:
            host_adress = item["ip_str"]
            host_name = item["hostnames"]
            host_os = item["os"]
            host_data = item["data"]
            print(host_adress)

if __name__ == "__main__":
    inter = ShodanInterface()
    inter.load_query_from_db()
