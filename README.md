# FoundIt

FoundIt is a local pentest findings search engine.

## Description

The use case for FoundIt is something along the lines of:
* Pentester is sent onsite to perform security assessment in a location:
    * without internet connectivity; and
    * with strict confidentiality requirements (read: laptop and test data stay on prem)
* Testing is completed and issues are found.
* Consultant now potentially has the fun of: 
    * Jumping through hoops to get the template findings from the company wiki/findings DB into the test machine so they can write the report. 
    * Jumping through even more hoops to get the ~REDACTED~ list of findings out to a machine where they can access the company findings DB and run M$ Word to write the ~REDACTED~ report there instead.
    * Writing the report findings from memory there and then (likely without QA if they are testing alone) so they client can receive their typo laden report immediately.  
    * Copy+Pasta of the findings from a VA tool and remember to amend: "~Nessus~ CompanyName detected CGI Generic SQL Injection".
    
Or
* Do the work upfront of parsing an existing company findings database into JSON.
* Clone this/your forked repo and drop that JSON file on to the test machine just before going dark.
* Search the findings locally without having to spin up your own docker datacenter to run a clone of the company findings wiki (or just ctrl+f the JSON file that I forced you to make)

__NB: At present this repository is not shipping with template findings beyond those which demonstrate rudimentary functionaility.__

You will need to fork to your own repo and parse your own findings into it. If you don't have a company findings DB then I feel your pain, get in touch and I can help.

If anybody knows where I can find a list of open source findings or wants to help in turning this into a full on report generator, please drop me a note.**
 
## Installation & Usage

```
git clone https://github.com/stuartgl/FoundIt
```

To search via keyword or phrase (-k keyword):

```python
$ python3 FoundIt.py -k xss
================================
Searching for:  xss
================================
Found 2 result(s):
================================
('Reflected XSS', 1.1, '=Web=', 'The Javascript, it runs.', 'An attacker could do things detrimental to the other things.', 'Attackers win.', 'Escape is the only way.', '', '', '4d66958358fbb1f51fd5bc3e0e697ed3')
('Stored XSS', 1.1, '=Web=', 'The Javascript, it is saved.', "An attacker could leave the bad code for the innocents to run. <script>alert('If you see this as a popup, enjoy the irony -FoundIt');</script>", 'Attackers win\nBad times.', 'Escape is the only way.', '', '', 'a7ef274c72f9de212a47cec5a4f809cd')


$ chmod 755 FoundIt.py 
$ ./FoundIt.py -k "stored xss"
================================
Searching for:  stored xss
================================
Found 1 result(s):
================================
('Stored XSS', 1.1, '=Web=', 'The Javascript, it is saved.', "An attacker could leave the bad code for the innocents to run. <script>alert('If you see this as a popup, enjoy the irony -FoundIt');</script>", 'Attackers win\nBad times.', 'Escape is the only way.', '', '', 'a7ef274c72f9de212a47cec5a4f809cd')
```

To specify your own findings JSON and rebuild the local database (-i filename.json) (any existing 'findings' table is dropped ):

```python
$ python3 FoundIt.py -i findings_db.json
Using findings_db.json
================================
================================
Populating database using: findings_db.json (6 findings)
================================
Database built
================================
```

To enter interactive mode (-c):
```python
$ python3 FoundIt.py -c
================================ Entering interactive mode (CTRL+C to escape) ================================
Keyword: ssl
================================
Found 2 result(s):
('SSL v2 in use', 1.1, '=Inf=', 'SSL v2 is too old for this day and age.', 'SSL v2 is too old for this day and age. Weak crypto is bad karma.', 'Attackers sniffing traffic and such like.', 'TLS, bigger numbers are better.', 'https://nmap.org/nsedoc/scripts/sslv2.html', '', '5ef24f5824208ee7fe1a6fdf9b85e8aa')
('SSL v3 in use', 1.1, '=Inf=', 'SSL v3 is too old for this day and age.', 'SSL v3 is too old for this day and age. Weak crypto is bad for business.', 'Attackers sniffing traffic and such like.', 'TLS, bigger numbers are better.', 'https://nmap.org/nsedoc/scripts/sslv3.html', '', '51cd054352336bd374839b2bc826a878')

```

To search the DB directly:
```sql
$ sqlite3 findings_db.sqlite "select * from findings where title like '%ssl%'"
SSL v2 in use|1.1|=Inf=|SSL v2 is too old for this day and age.|SSL v2 is too old for this day and age. Weak crypto is bad karma.|Attackers sniffing traffic and such like.|TLS, bigger numbers are better.|https://nmap.org/nsedoc/scripts/sslv2.html||5ef24f5824208ee7fe1a6fdf9b85e8aa
SSL v3 in use|1.1|=Inf=|SSL v3 is too old for this day and age.|SSL v3 is too old for this day and age. Weak crypto is bad for business.|Attackers sniffing traffic and such like.|TLS, bigger numbers are better.|https://nmap.org/nsedoc/scripts/sslv3.html||51cd054352336bd374839b2bc826a878
```

___(Beta) There is also an index.html file in the root which will make calls to the same DB if accessed via a web server such as python's simpleHTTPServer module. 

There is the vague ambition of using this as the basis for a report generator, but at the moment only basic search functionality is in place. Sometimes it throws CORS errors. Working on fixing this/building the web interface out further/implementing a proper design is low on my list of things #TODO.___

```python
python -m SimpleHTTPServer 8090 | firefox http://localhost:8090
```

## Under the hood

On launch, the script will attempt to create a local SQLite DB (called 'findings_db.sqlite') and populate a table (called 'findings') from the findings_db.json file, or the file specified if the -i flag is given an argument.

Any local 'findings' table will be dropped. Sorry if you had something in there, it's gone now.

An example format of the findings JSON is shown below, but you should refer to the file directly as this documentation is more likely to fall behind with any changes to fields.

During build of the database, an MD5 hash is generated from title, category and date fields at a vague attempt to keep tabs on when something changes/which version of a finding was used. This hash is currently for display purposes only and not actively used anywhere further down the line. Initially findings had IDs, but this will become a headache if multiple people are working on the JSON and updating it with their own new entries. Suggestions welcome on a better way to track these. 

```JSON
{
   "findings":[
      {
         "title":"Template",
         "cvss":0.0,
         "category":"==",
         "overview":"",
         "description":"",
         "impact":"",
         "recommendation":"",
         "references":"",
         "dated":"",
         "md5": ""
      },
      {
         "title":"Example Finding",
         "cvss":0.0,
         "category":"TEXT: =Generic Section=",
         "overview":"TEXT NOT NULL: The short description of a finding.",
         "description":"TEXT NOT NULL: The full technical description of a finding. \nAlso include the ouput of evidence here.",
         "impact":"TEXT NOT NULL: How a successful attack will affect the organisation.",
         "recommendation":"TEXT NOT NULL: How to fix or mitigate the issue.",
         "references":"TEXT: https://github.com/stuartgl",
         "dated":"TEXT: YYYY-MM-DD",
         "md5": "TEXT NOT NULL: Generated at runtime from title + category + dated"
      }
   ]
}
``` 

__NB: At present this repository is not shipping with template findings beyond those which demonstrate rudimentary functionaility.__ 

If anybody knows where I can find a list of open source findings or wants to help in turning this into a full on report generator, please drop me a note.
 

