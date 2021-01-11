# -*- coding: utf-8 -*-
import sqlite3
import json

spacer = "================================"

def dbConnect(dbName):
    conn = sqlite3.connect(dbName)
    return conn

def setupDatabase():
    print(spacer)
    print("Welcome to FoundIt - Your local pentest findings repo!")
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
                        refs TEXT NOT NULL
                    )
                ''')

    #Read contents of json into dd
    #TODO: make this an argument
    findings_json = "findings_db.json"
    print(spacer)
    with open(findings_json, "r") as json_file:
        data = json.load(json_file)
        print("Populating database using: "+findings_json+" "+"("+str(len(data['findings']))+" findings)")
        for record in data['findings']:
            c.execute('''INSERT INTO findings(
                                id, 
                                title, 
                                cvss, 
                                category, 
                                overview, 
                                description, 
                                impact, 
                                recommendation, 
                                refs
                            ) 
                        VALUES (?,?,?,?,?,?,?,?,?)''',
                          (
                                record['id'],
                                record['title'],
                                record['cvss'],
                                record['category'],
                                record['overview'],
                                record['description'],
                                record['impact'],
                                record['recommendation'],
                                record['references']
                          )
                      )
            conn.commit()
        print(spacer)
        print("Database built")
        print(spacer)
    conn.close()

def usageInstructions():
    print("Type your search term below as a keyword or use a browser to interact with the database.")
    print("")
    print("Field names: id|title|cvss|category|overview|description|impact|recommendation|refs")
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

    for row in rows:
        print(spacer)
        print (row)
        print(spacer)

    interactiveUser()

def main():
    setupDatabase()
    usageInstructions()
    interactiveUser()




if __name__ == "__main__":
    main()