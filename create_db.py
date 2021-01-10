# -*- coding: utf-8 -*-
import sqlite3
import json


def setupDatabase():
    #Create sqlite connection
    conn = sqlite3.connect('findings_db.sqlite')
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
                    refs TEXT NOT NULL)
                ''')

    #Read contents of json into db
    findings_json = "findings_db.json"
    with open(findings_json, "r") as json_file:
        data = json.load(json_file)
        print("Populating database using: "+findings_json+" "+"("+str(len(data['findings']))+" findings)")
        for record in data['findings']:
            c.execute('INSERT INTO findings (id, title, cvss, category, overview, description, impact, recommendation, refs) VALUES (?,?,?,?,?,?,?,?,?)',
                      (record['id'], record['title'], record['cvss'], record['category'], record['overview'], record['description'], record['impact'],record['recommendation'],record['references']))
            conn.commit()
        print("Database built")
    conn.close()


def main():
    setupDatabase()


if __name__ == "__main__":
    main()