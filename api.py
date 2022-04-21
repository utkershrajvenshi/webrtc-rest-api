from datetime import datetime
import email
from email.policy import default
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy

# For interacting with the Operating System to generate base directory address
import os

# Initialising app
app = Flask(__name__)

# Generating base directory address
basedir = os.path.abspath(os.path.dirname(__file__))
basedir = os.path.join(basedir, 'databases')

# Adding the directory address in app configuration for SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///" + os.path.join(basedir, 'maindb.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Creating models for our app
class User(db.Model):
    __tablename__ = 'users'

    # Primary Key
    uid = db.Column(db.Integer, primary_key = True)

    # Store email id, either from frontend or through google integration
    email = db.Column(db.String, nullable=False)
    first_name = db.Column(db.String(20))
    last_name = db.Column(db.String(30))

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
    friend_id = db.Column(db.Integer, db.ForeignKey('users.uid'))
    friends = db.relationship('User', remote_side = [uid], useList=True)

    # Storing meetings for host
    meeting_host = db.relationship('Meetings', backref='meetings')


# Association table for implementing  many-to-many relationship between user and meetings
meeting_audience = db.Table('meeting_audience',
    db.Column('meeting_id', db.Integer, db.ForeignKey('meetings.meeting_id'), primary_key = True),
    db.Column('audience_id', db.Integer, db.ForeignKey('users.uid'), primary_key=True)
)

class Meetings(db.Model):
    __tablename__ = 'meetings'

    meeting_id = db.Column(db.Integer, primary_key=True)
    at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # Point to User id here for host (One-To-Many relationship)
    host = db.Column(db.String, db.ForeignKey('users.uid'), nullable=False)
    # Point to user uids here for audience (Many-To-Many relationship)
    audience = db.relationship('User', secondary=meeting_audience, backref='meetings')



# Creating the database
db.create_all()

# Starting the server at port 3300 with debug flag set to true.
# TODO: Set the debug flag to false in production mode
if __name__=="__main__":
    app.run(debug=True, port=3300)