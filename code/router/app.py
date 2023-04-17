from threading import Thread
import uuid ,jsonpickle ,requests, json,datetime
from flask import Flask, Response, jsonify, render_template,request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from Classifier import Classifier
from urllib.parse import urlparse,parse_qs
'''
it is flask server is the entrypoint of the whole system, this server is having network access to other docker containers. it is responsible for diverting the request to the respective container.
'''

cls=Classifier()
app=Flask(__name__)
CORS(app)
app.config.from_file('config.json',load=json.load)

with open('cookie.txt','r') as f:
    cookie=list(map(str,f.read().strip().split('\n')))

# for storing the session data in database we are using flask-sqlalchemy with sqlite3 database.
db = SQLAlchemy(app)

# creating model for storing a copy of session data (local cookies).
class SessionData(db.Model):
    __tablename__ = 'session_data'
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(255), unique=True)
    data = db.Column(db.String(10000))
    expiration_time = db.Column(db.DateTime)
    Malicious=db.Column(db.Boolean)


    def __init__(self, session_id, Malicious, expiration_time,data=''):
        self.session_id = session_id
        self.data = data
        self.Malicious=Malicious
        self.expiration_time = expiration_time

with app.app_context():
    db.create_all()

# function to delete expired sessions from database
def delete_expired_sessions():
    with app.app_context():

        d=datetime.datetime.now()
      
        expired_sessions =SessionData.query.filter(SessionData.expiration_time <d ).all()

        if expired_sessions:
            for session in expired_sessions:
                db.session.delete(session)
           
        db.session.commit()
        db.session.close()

# to create anoter thread to delete expired sessions
def start_background_task():
    thread = Thread(target=delete_expired_sessions)
    thread.daemon = True
    thread.start()

# to handle 404 error
@app.errorhandler(404)
def not_found(error):
    return Response(render_template('error.html',error=error),status=404)

# starting task to delete expired sessions
@app.before_request
def allu():
    start_background_task()
  


# function to get key and value from cookie - a helper function
def cookie_value(c):
    key=c.split('=')[0]
    val=(c.split(';')[0]).split('=')[1]
    return key,val


# a function to update session data in database
@app.after_request
def after_request(response): 
    cookies={}
    f=response.headers.getlist('Set-Cookie')
    #  in this function we check if any local cookie is changed ->if changed then we update the session data in database

    for i in f:
        key,val=cookie_value(i)
        cookies[key]=val
    data={}
    for key,val in cookies.items():      
        data[key]=val
   
    session_id=None
    if 'session_id' in data:
        session_id=data['session_id']
    
    d=SessionData.query.filter_by(session_id=session_id).first()
    if d is None or d.Malicious==True:
        return response

    co=d.data
    if co is None or co=='':
        cookie_data={}
    else:
        cookie_data=dict(jsonpickle.decode(SessionData.query.filter_by(session_id=session_id).first().data))
    expiration_time = datetime.datetime.now() + datetime.timedelta(minutes=30)
    for i in cookie:
        if i in data:
            cookie_data[i]=data[i]
    
   
    up={'expiration_time':expiration_time,'data':jsonpickle.encode(cookie_data)}
    sess=SessionData.query.filter_by(session_id=session_id).first()
    sess.data=up['data']
    sess.expiration_time=up['expiration_time']
    db.session.commit()
    db.session.close() 
    
    return response


# a function to divert the request based on decision of classifier.
def route_request(request,mal,session_id,path=""):
    
    # return str(mal)
    if mal:
        Server="http://vul-web/"
    else:
        Server="http://safe-web/"
    
    
    para={}
    p=urlparse(request.url)
    w=parse_qs(p.query)
    for key,val in w.items():
        para[key]=val[0] 

    # print(para)
    r = requests.request(
        method=request.method,
        url=Server+path,
        headers=request.headers,
        data=request.get_data(),
        params=para,
        cookies=request.cookies,
        allow_redirects=False,
        verify=False
    )
    
    response=Response()
    for key,val in r.headers.items():
        if key.lower()=='content-encoding':
            continue
        response.headers[key]=val
    response.set_cookie('session_id',session_id,max_age=10*60*3)
    
    for key,val in r.cookies.get_dict().items():
        response.set_cookie(key,val)
  
    if r.status_code==404:
        response.set_data(render_template('error.html'))
    else:
        response.set_data(r.content)
    response.status_code=r.status_code
    
    return response


# a route which catch all the requests irrecspective of the path of the request
@app.route('/',defaults={'path': ''},methods=['GET','POST','PUT','DELETE'])
@app.route('/<path:path>',methods=['GET','POST','PUT','DELETE'])
def catch_all(path=""):
    # check if session_id cookie is present or not.
    session_id=request.cookies.get('session_id')
     
    #  if session_id is not present or session_id is present but not in database
    if not session_id or not db.session.query(SessionData).filter_by(session_id=session_id).first():
   
    #    check with classifier whether the request is malicious or not
        mal=cls.predict(request)
        session_id=str(uuid.uuid4())
        ses=SessionData(session_id=session_id,Malicious=mal,expiration_time=datetime.datetime.now()+datetime.timedelta(minutes=30))
        db.session.add(ses)
        db.session.commit()
    else:
        # check with classifier whether the request is malicious or not
        d=SessionData.query.filter_by(session_id=session_id).first().data
        m=SessionData.query.filter_by(session_id=session_id).first().Malicious
        # print('m',m)
        data={}
        if d is not None and d!='':
            data=dict(jsonpickle.decode(d))
        else:
            data={}
        mal=1
        
        if not m:
            mal=cls.predict(request,data=data)
            # print(mal,'mal2')
        
        sess=SessionData.query.filter_by(session_id=session_id).first()
        sess.expiration_time=datetime.datetime.now()+datetime.timedelta(minutes=30)
        sess.Malicious=mal
        print(mal,'mal')
        db.session.commit()
        
    db.session.close()
    print(SessionData.query.filter_by(session_id=session_id).first().Malicious)


    return  route_request(request,mal,session_id,path)

if __name__ == '__main__':
    app.run(host="0.0.0.0",port=80,debug=True)