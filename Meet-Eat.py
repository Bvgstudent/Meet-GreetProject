# This project was done by Benedict Georges ID#68652

from geocode import getGeocodeLocation
import json
import httplib2
from redis import Redis
redis = Redis()

import time
from functools import update_wrapper

import sys
import codecs

#From OAuth code
from models import Base, User
from flask import Flask, jsonify, request, url_for, abort, g, render_template
from sqlalchemy import Table, Column, Float, Integer, String, MetaData, ForeignKey, Boolean 
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

from flask.ext.httpauth import HTTPBasicAuth
#NEW IMPORTS
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

from flask import make_response
import requests

from sqlalchemy import Column,Integer,String
from passlib.apps import custom_app_context as pwd_context
import random, string
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)


Base = declarative_base()

auth = HTTPBasicAuth()
# From OAuth end

app = Flask(__name__)

sys.stdout = codecs.getwriter('utf8')(sys.stdout)
sys.stderr = codecs.getwriter('utf8')(sys.stderr)

foursquare_client_id = "PASTE_CLIENT_ID_HERE"
foursquare_client_secret = "PASTE_CLIENT_SECRET_HERE"
google_api_key = "PASTE_YOUR_KEY_HERE"



class RateLimit(object):
    expiration_window = 10

    def __init__(self, key_prefix, limit, per, send_x_headers):
        self.reset = (int(time.time()) // per) * per + per
        self.key = key_prefix + str(self.reset)
        self.limit = limit
        self.per = per
        self.send_x_headers = send_x_headers
        p = redis.pipeline()
        p.incr(self.key)
        p.expireat(self.key, self.reset + self.expiration_window)
        self.current = min(p.execute()[0], limit)

    remaining = property(lambda x: x.limit - x.current)
    over_limit = property(lambda x: x.current >= x.limit)

def get_view_rate_limit():
    return getattr(g, '_view_rate_limit', None)

def on_over_limit(limit):
    return (jsonify({'data':'You hit the rate limit','error':'429'}),429)

def ratelimit(limit, per=300, send_x_headers=True,
              over_limit=on_over_limit,
              scope_func=lambda: request.remote_addr,
              key_func=lambda: request.endpoint):
    def decorator(f):
        def rate_limited(*args, **kwargs):
            key = 'rate-limit/%s/%s/' % (key_func(), scope_func())
            rlimit = RateLimit(key, limit, per, send_x_headers)
            g._view_rate_limit = rlimit
            if over_limit is not None and rlimit.over_limit:
                return over_limit(rlimit)
            return f(*args, **kwargs)
        return update_wrapper(rate_limited, f)
    return decorator

#OAuth code


@auth.verify_password
def verify_password(username_or_token, password):
    #Try to see if it's a token first
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id = user_id).one()
    else:
        user = session.query(User).filter_by(username = username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

@app.route('/clientOAuth')
def start():
    return render_template('meet_greet.html')

@app.route('/oauth/<provider>', methods = ['POST'])
def login(provider):
    #STEP 1 - Parse the auth code
    auth_code = request.json.get('auth_code')
    print "Step 1 - Complete, received auth code %s" % auth_code
    if provider == 'google':
        #STEP 2 - Exchange for a token
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
          
        # Check that the access token is valid.
        access_token = credentials.access_token
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])
        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'
            
        # # Verify that the access token is used for the intended user.
        # gplus_id = credentials.id_token['sub']
        # if result['user_id'] != gplus_id:
        #     response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
        #     response.headers['Content-Type'] = 'application/json'
        #     return response

        # # Verify that the access token is valid for this app.
        # if result['issued_to'] != CLIENT_ID:
        #     response = make_response(json.dumps("Token's client ID does not match app's."), 401)
        #     response.headers['Content-Type'] = 'application/json'
        #     return response

        # stored_credentials = login_session.get('credentials')
        # stored_gplus_id = login_session.get('gplus_id')
        # if stored_credentials is not None and gplus_id == stored_gplus_id:
        #     response = make_response(json.dumps('Current user is already connected.'), 200)
        #     response.headers['Content-Type'] = 'application/json'
        #     return response
        print "Step 2 Complete! Access Token : %s " % credentials.access_token

        #STEP 3 - Find User or make a new one
        
        #Get user info
        h = httplib2.Http()
        userinfo_url =  "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt':'json'}
        answer = requests.get(userinfo_url, params=params)
      
        data = answer.json()

        name = data['name']
        picture = data['picture']
        email = data['email']
        
        
     
        #see if user exists, if it doesn't make a new one
        user = session.query(User).filter_by(email=email).first()
        if not user:
            user = User(username = name, picture = picture, email = email)
            session.add(user)
            session.commit()

        

        #STEP 4 - Make token
        token = user.generate_auth_token(600)

        

        #STEP 5 - Send back token to the client 
        return jsonify({'token': token.decode('ascii')})
        
        #return jsonify({'token': token.decode('ascii'), 'duration': 600})
    else:
        return 'Unrecoginized Provider'

@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})



@app.route('/api/users', methods = ['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        print "missing arguments"
        abort(400) 
        
    if session.query(User).filter_by(username = username).first() is not None:
        print "existing user"
        user = session.query(User).filter_by(username=username).first()
        return jsonify({'message':'user already exists'}), 200#, {'Location': url_for('get_user', id = user.id, _external = True)}
        
    user = User(username = username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return jsonify({ 'username': user.username }), 201#, {'Location': url_for('get_user', id = user.id, _external = True)}

@app.route('/api/users/<int:id>')
def get_user(id):
    user = session.query(User).filter_by(id=id).one()
    if not user:
        abort(400)
    return jsonify({'username': user.username})

@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({ 'data': 'Hello, %s!' % g.user.username })

#OAuth Code end


#Store a meal request into the database
@app.route('/MakeMealRequest/<mealType>/<meal_time>/<Location>/Json', methods = ['POST'])
@auth.login_required
@ratelimit(limit=180, per=60 * 1)
def MakeMealRequest(mealType,meal_time,Location):
    user_id = g.user.id
    (longitude,latitude) = getGeocodeLocation(Location)
    request = Request(user_id = user_id, location_string = Location, latitude = latitude, longitude = longitude, meal_time= meal_time, filled = False)
    session.add(request)
    session.commit()
    return "Request was stored"

# View all requests
@app.route('/ViewRequests/all/Json')
@auth.login_required
@ratelimit(limit=180, per=60 * 1)
def ViewRequests():
    request = session.query(Request).all()
    return jsonify(Requests=[i.serialize for i in request])

# View specific a specific request and update it
@app.route("/ViewRequests/<int:id>", methods = ['GET', 'POST'])
@auth.login_required
@ratelimit(limit=180, per=60 * 1)
def MealProposal(id):
  if request.method == 'GET':
    request = session.query(Request).request_id.filter_by(id = request_id).one()
    return jsonify(Requests=[i.serialize for i in request])
  if request.method == 'POST':
    user_id = g.user.id
    request = session.query(Request).filter_by(id = request_id).one()
    proposal = Proposal(proposed_by = user_id, proposed_to=request.user_id , request_id = request_id, filled = False)
    session.add(proposal)
    session.commit()
    return "You made a proposal!"
    
  #View proposals and accept them
@app.route("/Viewproposals/<int:id>", methods = ['GET', 'POST'])
@auth.login_required
@ratelimit(limit=180, per=60 * 1)
def ViewProposal(proposal_id):
    if request.method == 'GET':
        request = session.query(Proposal).request_id.filter_by(proposal_id = request_id).one()
        return jsonify(Proposal=[i.serialize for i in proposal])
    if request.method == 'POST':
        user_id = g.user.id
        request = session.query(Request).filter_by(id = request_id).one()
        proposal = Proposal(proposed_by = user_id, proposed_to=request.user_id , request_id = request_id, filled = True)
        session.add(proposal)
        session.commit()

        return "Proposal was confirmed!"





    





@app.after_request
def inject_x_rate_headers(response):
    limit = get_view_rate_limit()
    if limit and limit.send_x_headers:
        h = response.headers
        h.add('X-RateLimit-Remaining', str(limit.remaining))
        h.add('X-RateLimit-Limit', str(limit.limit))
        h.add('X-RateLimit-Reset', str(limit.reset))
    return response



def getGeocodeLocation(inputString):
    # Use Google Maps to convert a location into Latitute/Longitute coordinates
    # FORMAT: https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre+Parkway,+Mountain+View,+CA&key=API_KEY
    
    locationString = inputString.replace(" ", "+")
    url = ('https://maps.googleapis.com/maps/api/geocode/json?address=%s&key=%s'% (locationString, google_api_key))
    h = httplib2.Http()
    result = json.loads(h.request(url,'GET')[1])
    latitude = result['results'][0]['geometry']['location']['lat']
    longitude = result['results'][0]['geometry']['location']['lng']
    return (latitude,longitude)


def findARestaurant(mealType,location):
	#1. Use getGeocodeLocation to get the latitude and longitude coordinates of the location string.
	latitude, longitude = getGeocodeLocation(location)
	#2.  Use foursquare API to find a nearby restaurant with the latitude, longitude, and mealType strings.
	#HINT: format for url will be something like https://api.foursquare.com/v2/venues/search?client_id=CLIENT_ID&client_secret=CLIENT_SECRET&v=20130815&ll=40.7,-74&query=sushi
	url = ('https://api.foursquare.com/v2/venues/search?client_id=%s&client_secret=%s&v=20130815&ll=%s,%s&query=%s' % (foursquare_client_id, foursquare_client_secret,latitude,longitude,mealType))
	h = httplib2.Http()
	result = json.loads(h.request(url,'GET')[1])
	
	if result['response']['venues']:
		#3.  Grab the first restaurant
		restaurant = result['response']['venues'][0]
		venue_id = restaurant['id'] 
		restaurant_name = restaurant['name']
		restaurant_address = restaurant['location']['formattedAddress']
		address = ""
		for i in restaurant_address:
			address += i + " "
		restaurant_address = address
		#4.  Get a  300x300 picture of the restaurant using the venue_id (you can change this by altering the 300x300 value in the URL or replacing it with 'orginal' to get the original picture
		url = ('https://api.foursquare.com/v2/venues/%s/photos?client_id=%s&v=20150603&client_secret=%s' % ((venue_id,foursquare_client_id,foursquare_client_secret)))
		result = json.loads(h.request(url, 'GET')[1])
		#5.  Grab the first image
		if result['response']['photos']['items']:
			firstpic = result['response']['photos']['items'][0]
			prefix = firstpic['prefix']
			suffix = firstpic['suffix']
			imageURL = prefix + "300x300" + suffix
		else:
			#6.  if no image available, insert default image url
			imageURL = "http://pixabay.com/get/8926af5eb597ca51ca4c/1433440765/cheeseburger-34314_1280.png?direct"
		#7.  return a dictionary containing the restaurant name, address, and image url
		restaurantInfo = {'name':restaurant_name, 'address':restaurant_address, 'image':imageURL}
		print "Restaurant Name: %s" % restaurantInfo['name']
		print "Restaurant Address: %s" % restaurantInfo['address']
		print "Image: %s \n" % restaurantInfo['image']
		return restaurantInfo
	else:
		print "No Restaurants Found for %s" % location
		return "No Restaurants Found"

if __name__ == '__main__':


    class User(Base):
        __tablename__ = 'user'
        id = Column(Integer, primary_key=True)
        password_hash = Column(String(64))
        email = Column(String(32),index=True)
        picture= Column(String(32),index=True)

        @property
        def serialize(self):
            """Return object data in easily serializeable format"""
            return {
            'email' : self.email,
            'picture' : self.picture,
                }

        def hash_password(self, password):
            self.password_hash = pwd_context.encrypt(password)

        def verify_password(self, password):
            return pwd_context.verify(password, self.password_hash)

    class Request(Base):
        __tablename__ = 'request'    
        id = Column(Integer, primary_key=True)
        mealType = Column(String(50), nullable = False)
      #  city = Column(String)
        location_string = Column(String)
        latitude = Column(Float, nullable = False)
        longitude = Column(Float, nullable = False)
        user_id = Column(Integer, ForeignKey('user.id'))
        meal_time = Column(String)
        filled = Column(Boolean)

        @property
        def serialize(self):
            """Return object data in easily serializeable format"""
            return {
            'mealType' : self.mealType,
            'location' : self.location_string,
            'user_id' : self.user_id,
            'meal_time' : self.meal_time
                }


    class Proposal(Base):
        __tablename__ = 'proposal'
        id = Column (Integer, primary_key=True)
        user_proposed_to = Column(String)
        user_proposed_from = Column(String)
        request_id = Column(Integer, ForeignKey('request.id'))
        filled = Column(Boolean)

        @property
        def serialize(self):
            """Return object data in easily serializeable format"""
            return {
            'user_proposed_to' : self.user_proposed_to,
            'user_proposed_from' : self.user_proposed_from,
            'request_id' : self.request_id,
                }


    class MealDate(Base):
         __tablename__ = 'meal_date'
         id = Column(Integer, primary_key=True)
         user1 = Column(String, nullable = False)
         user2 = Column(String, nullable = False)
         restaurant_name = Column(String)
         restaurant_address = Column(String)
         restaurant_picture = Column(String)
         meal_time = Column(String)

         @property
         def serialize(self):
            """Return object data in easily serializeable format"""
            return {
            'user1' : self.user1,
            'user2' : self.user2,
            'restaurant_name' : self.restaurant_name,
            'meal_time' : self.meal_time
                }


    engine = create_engine('sqlite:///Meet-Eat.db')
    Base.metadata.create_all(engine)
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host = '0.0.0.0', port = 5000)
	#findARestaurant("Pizza", "Tokyo, Japan")
	#findARestaurant("Tacos", "Jakarta, Indonesia")
	#findARestaurant("Tapas", "Maputo, Mozambique")
	#findARestaurant("Falafel", "Cairo, Egypt")
	#findARestaurant("Spaghetti", "New Delhi, India")
	#findARestaurant("Cappuccino", "Geneva, Switzerland")
	#findARestaurant("Sushi", "Los Angeles, California")
	#findARestaurant("Steak", "La Paz, Bolivia")
	#findARestaurant("Gyros", "Sydney Australia")

#if __name__ == '__main__':

	