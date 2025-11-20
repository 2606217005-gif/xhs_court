from flask import Flask
from flask_cors import CORS # 导入

app = Flask(__name__)
CORS(app) # 启用跨域，允许所有来源访问

@app.route('/')
def home():
    return "CORS enabled!"
