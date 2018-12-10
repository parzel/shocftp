#!/usr/bin/python3  -u

import ftplib
import json

class FTPCrawler():

    def __init__(self, host, user="anonymous", password="anonymous@", level_limit=3, timeout=3, target_list=[]):
        # Open connection
        try:
            ftp = ftplib.FTP(host, user, password,"",timeout)
        except ftplib.all_errors as e:
            print(e)
        self.host = host
        self.user = user
        self.password = password
        self.level = level_limit
        self.target_list = target_list
        self.crawl(ftp)

    def crawl(self, ftp, path_list=["/"]):
        processed_paths = set()
        level_skipped_paths = set()

        while len(path_list) > 0:
            path = path_list.pop()
            cur_level = path.count("/")
            if cur_level >= self.level:
                level_skipped_paths.add(path)
                print(f"Skipping {path} because of level")
                continue
            files = ""
            try:
                if path:
                    ftp.cwd(path)
                    print(path)
                files = ftp.nlst()
            except ftplib.all_errors as e:
                # file heuristica
                if "550" in str(e):      
                    for target in self.target_list:
                        if target in path:
                            print(f"Found a match: ftp://{self.user}:{self.password}@{self.host}/{path}")
                else:
                    print(path+": Error "+str(e))
            # it is processed now
            processed_paths.add(path)

            for index, line in enumerate(files):
                if line != "." and line != "..":
                    if line not in processed_paths:
                        path_list.append(f"{path}/{line}")

        # save log file
        with open(f"results/{self.host}.json", "w") as storage_json:
            json.dump({"processed_paths":list(processed_paths),"level_skipped_paths":list(level_skipped_paths)}, storage_json, indent=4)


if __name__ == "__main__":
    crawler = FTPCrawler("5.149.255.143")