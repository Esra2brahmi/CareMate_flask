import os
from dotenv import load_dotenv

# Load environment variables from the .env file in the project root
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'paradice')
    MONGO_URI = os.environ.get('MONGO_URI', 'MONGO_URI=mongodb+srv://rawia-ghrairi2:Rgh%402020@cluster0.g1ja8.mongodb.net/users')
