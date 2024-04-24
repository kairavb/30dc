# 30dc
30 days challenge one !

frontend template by:- https://github.com/estevanmaito/windmill-dashboard  
founded on https://www.tailwindawesome.com/  
license inside license folder with name of LICENSE1  

landing page template by:- https://github.com/themesberg/landwind  
license inside license folder with name of LICENSE2  

## read requirements.txt for python package requirements

## used SQL as database, 

create chef.db in the folder with app.py

## SQL Table Creation Commands

```
CREATE TABLE chef (
   id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
   status BOOL,
   intro TEXT,
   wage INTEGER,
   exp INTEGER,
   mail TEXT
);
```

```
CREATE TABLE investor (
   username TEXT NOT NULL,
   chefusername TEXT NOT NULL
);
```

```
CREATE TABLE users (
   id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
   username TEXT NOT NULL,
   type BOOL NOT NULL,
   hash TEXT NOT NULL
);
```

In help.txt you can find my thinking on how i imagined the project would work,
and over time how I imagined the layout of my project,  
like a blueprint that changes as the idea is shaped by continuous efforts over time.

also created virtual env so that i can isolate my working environment 
from my global environment. (Linux)

```
python3.10 -m venv "chefenv"
source chefenv/bin/activate
```

I am working day and night since starting of this project, may upload timelapse in future  
I have learned a lot through this 5 day project challenge,
this is fun !
