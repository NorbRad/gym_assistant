from flask import Flask, jsonify, request, session
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import OperationalError
import os
from datetime import datetime
import string
import random
from dotenv import load_dotenv
import redis
from flask_caching import Cache
import hashlib
import logging

load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.config['CACHE_TYPE'] = os.getenv('APP_CACHE_TYPE')
app.config['CACHE_REDIS_HOST'] = os.getenv('APP_CACHE_REDIS_HOST')
app.config['CACHE_REDIS_PORT'] = os.getenv('APP_CACHE_REDIS_PORT')
app.config['CACHE_REDIS_DB'] = os.getenv('APP_CACHE_REDIS_DB')

cache = Cache(app=app)
cache.init_app(app)

redis_client = redis.Redis(host=os.getenv('APP_CACHE_REDIS_HOST'), port=os.getenv('APP_CACHE_REDIS_PORT'), db=os.getenv('APP_CACHE_REDIS_DB'), decode_responses=True)

app.secret_key = os.getenv('APP_SECRET_KEY')

DATABASE_URI = os.getenv('POSTGRES_URL')

engine = create_engine(DATABASE_URI)

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    username = Column(String(20), unique=True, primary_key=True)
    password = Column(String(64))  # Adjusted for hashed password length

Base.metadata.create_all(engine)

SessionFactory = sessionmaker(bind=engine)
Session = scoped_session(SessionFactory)

def consistent_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()

@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return jsonify({'message': 'Username and password are required'}), 400
    
    username = auth.username
    password = auth.password
    hashed_password = consistent_hash(password)
    
    db_session = Session()
    try:
        user = db_session.query(User).filter(User.username==username, User.password==hashed_password).first()
        if user:
            return create_session(username)
        else:
            return jsonify({'message': 'Invalid credentials'}), 401
    finally:
        db_session.close()

def create_session(username):
    current_timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    rand_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    session_id = f"{username}_{current_timestamp}_{rand_str}"
    session_id_hashed = consistent_hash(session_id)
    
    session_key = f'session:{session_id_hashed}'
    redis_client.hset(session_key, mapping={'username': username})
    redis_client.expire(session_key, 3600)  # 1 hour expiration
    
    return jsonify({'session_id': session_key}), 200

@app.route('/verify-session', methods=['POST'])
def verify_session():
    data = request.form
    session_key = data.get('session_id')
    if not session_key:
        return jsonify({'error': 'Session ID is required'}), 400

    cached_session_data = redis_client.hgetall(session_key)
    if not cached_session_data:
        return jsonify({'error': 'Invalid or expired session'}), 401
    
    return jsonify(cached_session_data), 200

if __name__ == '__main__':
    app.run(port=5000)
