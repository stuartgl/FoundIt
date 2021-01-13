#!/usr/bin/python3
import sys, getopt
import hashlib
import sqlite3
import json
import argparse

spacer = "================================"


def dbConnect(dbName):
    conn = sqlite3.connect(dbName)
    return conn

def setupDatabase(findings_json):
    print(spacer)
    print("FoundIt - The local pentest findings repository")
    #Create sqlite connection
    conn = dbConnect('findings_db.sqlite')
    c = conn.cursor()
    #Destroy and setup table structure
    c.execute('DROP TABLE IF EXISTS findings')
    c.execute('''CREATE TABLE findings( 
                        title TEXT NOT NULL, 
                        cvss REAL, 
                        category TEXT,                    
                        overview TEXT NOT NULL, 
                        description TEXT NOT NULL,                     
                        impact TEXT NOT NULL, 
                        recommendation TEXT NOT NULL, 
                        refs TEXT NOT NULL,
                        dated TEXT NOT NULL, 
                        md5 TEXT NOT NULL
                    )
                ''')#TODO: make date correct type

    print(spacer)

    #Read contents of json into dd
    with open(findings_json, "r") as json_file:
        data = json.load(json_file)
        print("Populating database using: "+findings_json+" "+"("+str(len(data['findings']))+" findings)")
        for record in data['findings']:

            #MD5 of the finding to avoid dupes on the id in the JSON. Not used ATM, but seems like a good idea.
            #Yes it's only MD5: It's a checksum, deal with it.
            finding_hash = (hashlib.md5(str(record['title']+record['category']).encode())).hexdigest()

            c.execute('''INSERT INTO findings(
                                title, 
                                cvss, 
                                category, 
                                overview, 
                                description, 
                                impact, 
                                recommendation, 
                                refs,
                                dated,
                                md5
                            ) 
                        VALUES (?,?,?,?,?,?,?,?,?,?)''',
                          (
                                record['title'],
                                record['cvss'],
                                record['category'],
                                record['overview'],
                                record['description'],
                                record['impact'],
                                record['recommendation'],
                                record['references'],
                                record['dated'],
                                finding_hash,
                          )
                      )
            conn.commit()
        print(spacer)
        print("Database built")
        print(spacer)
    conn.close()

    usageInstructions()

def usageInstructions():
    print("Usage:")
    print("When the script is running, type a keyword to search the DB, which is populated by the JSON file.\n")
    print("Field names:\n"
          "id|title|cvss|category|overview|description|impact|recommendation|refs|MD5#(title + category + dated)\n")
    print("Examples:")
    print("Python: SSL (return)")
    print("SQLite: sqlite3 findings_db.sqlite \"select * from findings where title like '%ssl%'\"")
    print("GUI: python -m SimpleHTTPServer 8090 | firefox http://localhost:8090\n")

#Todo: add a one shot mode, to search for a keyword via argument
def searchFor(keyword):
    conn = dbConnect('findings_db.sqlite')
    c = conn.cursor()

    name = '%'
    name += keyword
    name += '%'

    c.execute("SELECT * FROM findings WHERE title LIKE ?", (name,))
    rows = c.fetchall()
    if (len(rows) >= 1):
        for row in rows:
            print(spacer)
            print (row)
            print(spacer)
    else:
        print ("Nothing found. You should probably write it and add it to the repo.")

def interactiveUser():
    print("")
    interactiveKeyword = '%'
    interactiveKeyword += input("Keyword: ")
    interactiveKeyword += '%'
    searchFor(interactiveKeyword)
    interactiveUser()

def main(argv):

    findings_json = "findings_db.json"

    parser = argparse.ArgumentParser()
    parser.add_argument("-V", "--version", help="Show program version and usage info", action="store_true")
    parser.add_argument("-k", "--keyword", help="Supply a search keyword")
    parser.add_argument("-i", "--input", help="Supply a JSON file to build the database")
    parser.add_argument("-c", "--interactive", help="Enter interactive mode", action='store_true')
    # Read arguments from the command line
    args = parser.parse_args()

    if args.version:
        print("This is version 0.1")
        usageInstructions()
    elif args.input:
        print("Thanks for the input file")
        findings_json = args.input
        try:
            f = open(findings_json, 'r')
        except OSError:
            print("Unable to open, are you sure this is the JSON file you're looking for? : ", findings_json)
            sys.exit()
        print("Using " + findings_json)
        setupDatabase(findings_json)
    elif args.keyword:
        print ("Searching for: ", args.keyword)
        searchFor(args.keyword)
    elif args.interactive:
        print ("Entering interactive mode (CTRL+C to escape)")
        interactiveUser()





if __name__ == "__main__":
   main(sys.argv[1:])