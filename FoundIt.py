#!/usr/bin/python3
import sys, getopt
import hashlib
import sqlite3
import json

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
                        id INT NOT NULL, 
                        title TEXT NOT NULL, 
                        cvss REAL, 
                        category TEXT,                    
                        overview TEXT NOT NULL, 
                        description TEXT NOT NULL,                     
                        impact TEXT NOT NULL, 
                        recommendation TEXT NOT NULL, 
                        refs TEXT NOT NULL,
                        md5 TEXT NOT NULL
                    )
                ''')

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
                                id, 
                                title, 
                                cvss, 
                                category, 
                                overview, 
                                description, 
                                impact, 
                                recommendation, 
                                refs,
                                md5
                            ) 
                        VALUES (?,?,?,?,?,?,?,?,?,?)''',
                          (
                                record['id'],
                                record['title'],
                                record['cvss'],
                                record['category'],
                                record['overview'],
                                record['description'],
                                record['impact'],
                                record['recommendation'],
                                record['references'],
                                finding_hash,
                          )
                      )
            conn.commit()
        print(spacer)
        print("Database built")
        print(spacer)
    conn.close()

def usageInstructions():
    print("When the script is running, type a keyword to search the DB, which is populated by the JSON file.")
    print("")
    print("Field names: id|title|cvss|category|overview|description|impact|recommendation|refs|MD5#(title + category)")
    print("")
    print("Examples:")
    print("Python: SSL (return)")
    print("SQLite: sqlite3 findings_db.sqlite \"select * from findings where title like '%ssl%'\"")
    print("GUI: python -m SimpleHTTPServer 8090 | firefox http://localhost:8090")

def interactiveUser():
    conn = dbConnect('findings_db.sqlite')
    c = conn.cursor()
    print("")
    name = '%'
    name += input("Keyword: ")
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

    interactiveUser()

def main(argv):
    findings_json = "findings_db.json"
    inputfile = ''
    outputfile = ''
    try:
        opts, args = getopt.getopt(argv, "hi:o:", ["ifile=", "ofile="])
    except getopt.GetoptError:
        print('test.py -i <inputfile> -o <outputfile>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            usageInstructions()
            sys.exit()
        elif opt in ("-i", "--ifile"):
            try:
                f = open(arg, 'r')
            except OSError:
                print("Unable to open, are you sure this is the JSON file you're looking for? :", arg)
                sys.exit()
            findings_json = arg
            print ("Using "+findings_json)
        elif opt in ("-o", "--ofile"):
            print ("Thanks for the output file, but this function is not yet supported. Ask again later.")
            sys.exit()

    setupDatabase(findings_json)
    usageInstructions()
    interactiveUser()


if __name__ == "__main__":
   main(sys.argv[1:])