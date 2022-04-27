from crypt import methods
from datetime import datetime

from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow

# For interacting with the Operating System to generate base directory address
import os
from forms import SignUpForm

import generate_key
from passlib.hash import sha256_crypt

# Initialising app
app = Flask(__name__)

# Generating base directory address
basedir = os.path.abspath(os.path.dirname(__file__))
basedir = os.path.join(basedir, 'databases')

# Modifying app configuration variables of our app
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///" + os.path.join(basedir, 'maindb.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = "abcd1234ndwek"
app.config['SQLALCHEMY_BINDS'] = {
	'keys' : "sqlite:///" + os.path.join(basedir, 'keysdb.sqlite')
}

db = SQLAlchemy(app)
ma = Marshmallow(app)

# Creating models for our app
# User model
class User(db.Model):
	__tablename__ = 'users'

	# Primary Key
	# uid = db.Column(db.Integer, primary_key = True)

	"""
	@param email: Store email id, either from frontend or through Google integration. Also the primary key
	Email id is the primary key because when onboarding a new user we will
	lookup our database to find if a user with the email already exists
	If it exists, then simply login. Otherwise ask for name and other details
	"""
	email = db.Column(db.String, primary_key=True, nullable=False)
	
	first_name = db.Column(db.String(20))
	last_name = db.Column(db.String(30))
	
	"""
	@param nickname: A nickname for our user. This will come in handy when other users on the platform
	want to befriend this user.
	This way there won't be the hassle of remembering the friend's email id to communicate.
	"""
	nickname = db.Column(db.String, db.ForeignKey('nicknames.nickname'), nullable = False)

	# Store the OAuth token. If not that then store password hash here
	# TODO: Use persistent storage on the device to store the auth token for seamless authentication
	auth_token = db.Column(db.String, unique=True, nullable=False)

	# Store url path for profile picture uploaded from database
	avatar = db.Column(db.String)

	# In case of OAuth token, store an expiry date
	# Token needs to be refreshed before this date
	# Refresh token if there has been in activity before the jig's up
	expiry_date = db.Column(db.Date)

	# Store the datetime for when the user first onboarded to the application
	# Not to be implemented in front-end for now, but a nifty feature for future releases
	# Also helpful in tracking loyalty
	created = db.Column(db.DateTime, default=datetime.utcnow)

	# For storing friends of the user

	# Try self referencing the table 'users'
	# Specify a foreign key for friends, db.ForeignKey('users.id'). This should seed the friends column
	# with the data we want
	friend_id = db.Column(db.Integer, db.ForeignKey('users.email'))
	friends = db.relationship('User', remote_side = [email])

	# Storing meetings for host
	meeting_host = db.relationship('Meetings', backref='meetings')

	def __init__(self, email, first_name, last_name, nickname, avatar) -> None:
		self.email = email
		self.first_name = first_name
		self.last_name = last_name
		self.nickname = nickname
		self.avatar = avatar
		self.created = datetime.utcnow()

# Nickname lookup table. This table eliminates O(n) lookup of database for allocating nicknames
class Nickname(db.Model):
	__tablename__ = 'nicknames'

	nickname = db.Column(db.String(20), primary_key=True)
	email = db.relationship('User', backref='nickname_email', uselist=False)

# Association table for implementing  many-to-many relationship between user and meetings
meeting_audience = db.Table('meeting_audience',
	db.Column('meeting_id', db.Integer, db.ForeignKey('meetings.meeting_id'), primary_key = True),
	db.Column('audience_id', db.Integer, db.ForeignKey('users.email'), primary_key=True)
)

# Model for meetings
class Meetings(db.Model):
	__tablename__ = 'meetings'

	meeting_id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(100))
	at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
	# Point to User id here for host (One-To-Many relationship)
	host = db.Column(db.String, db.ForeignKey('users.email'), nullable=False)
	# Point to user uids here for audience (Many-To-Many relationship)
	audience = db.relationship('User', secondary=meeting_audience, backref='meetings')

	def __init__(self, title, at, host, audience) -> None:
		self.title = title
		self.at = at
		self.host = host
		self.audience = audience

# Model for storing api keys corresponding to email
class APIKey(db.Model):
	__bind_key__ = 'keys'
	email = db.Column(db.String, primary_key=True, nullable=False)
	password_hash = db.Column(db.String, nullable=False)
	api_key = db.Column(db.String, nullable=False)

# Creating the keys database
db.create_all(bind='keys')

# Creating the main database
db.create_all()

# View function for generating api key
@app.route('/generateKey', methods=['GET', 'POST'])
def generateKey():
	signUpForm = SignUpForm()
	if signUpForm.validate_on_submit():
		mail = signUpForm.email.data
		password = signUpForm.password.data

		queriedUser = APIKey.query.get(mail)
		if queriedUser is None:
			# Generate the API Key for provided email
			apiKey = generate_key.generateAPIKey()
			user_key = APIKey(email=mail, password_hash=sha256_crypt.hash(password), api_key=apiKey)
			
			# Adding the APIKey instance to the db
			db.session.add(user_key)
			try:
				# Committing the changes to the database
				db.session.commit()
			except Exception as e:
				db.session.rollback()
			
			success_msg = "API Key generated for {} is {}. Include the key in your POST requests to the server with the title ['API_KEY']".format(mail, apiKey)
			return render_template('generate.html', message=success_msg)
		else:
			# apiUser = APIKey.query.get(mail)
			if sha256_crypt.verify(password, queriedUser.password_hash):
				myKey = queriedUser.api_key
				return render_template('generate.html', message="Your API key is {}".format(myKey))
			else:
				return render_template('generate.html', form=signUpForm, error_msg="Wrong password entered. Please try again.")
	return render_template('generate.html', form=signUpForm)

# Function for creating the user in the database
@app.route('/create-user', methods=["POST"])
def createUser():
	email = request.json['email']
	first_name = request.json['first_name']
	last_name = request.json['last_name']
	avatar = request.json['avatar']
	nickname = request.json['nickname']

	new_user = User(email, first_name, last_name, nickname, avatar)

	# Adding the user to the database
	db.session.add(new_user)
	try:
		db.session.commit()
	except Exception as e:
		db.session.rollback()
	
	return jsonify(new_user)

# Function for updating the user details
@app.route('/update-user/<u_email>', methods=["PUT"])
def updateUser(u_email):
	user = User.query.get(u_email)

	email = request.json['email']
	first_name = request.json['first_name']
	last_name = request.json['last_name']
	avatar = request.json['avatar']
	nickname = request.json['nickname']

	user.email = email
	user.first_name = first_name
	user.last_name = last_name
	user.nickname = nickname
	user.avatar = avatar

	try:
		db.session.commit()
	except Exception as e:
		db.session.rollback()
	
	pass

# Function for deleting a user
@app.route('/delete-user/<u_email>', methods=["DELETE"])
def deleteUser(u_email):
	del_user = User.query.get(u_email)
	
	# Deleting specified user from the database
	db.session.delete(del_user)
	try:
		db.session.commit()
	except Exception as e:
		db.session.rollback()
	
	pass

# Function for scheduling a meeting
@app.route('/create-meeting', methods=["POST"])
def createMeeting():


# Starting the server at port 3300 with debug flag set to true.
# TODO: Set the debug flag to false in production mode
if __name__=="__main__":
	app.run(debug=True, port=3300)