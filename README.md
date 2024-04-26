# chef connect
this project was created as part of 30dc challenge #1,  
that was to create and deploy a working full-stack project in 5 days!!  
and the challenge came just as i completed my cs50x course, without the  
teachings of cs50 i could'nt have made this project in just 5 days.

## Introduction
Chef Connect is a platform where businesses/investors can meet real chef's!!  
the good thing is the project is very simple to use and have some good features like,    
chef dashboard, investor dashboard, hashed password storage, chef search,  
responsive design, easyto set up account, dark/light mode, tons of error msgs, etc!  
hope you enjoy using the site!

### Live link-> https://kairavb.pythonanywhere.com/

frontend template by:- https://github.com/estevanmaito/windmill-dashboard  
founded on https://www.tailwindawesome.com/  
license inside license folder with name of LICENSE1  

landing page template by:- https://github.com/themesberg/landwind  
license inside license folder with name of LICENSE2  

## read requirements.txt for python package requirements
generated by, 

```
pip freeze > requirements.txt
```

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
