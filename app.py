from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import pickle
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Configure SQLite DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Define user model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)

# Create the database
with app.app_context():
    db.create_all()

# Load the trained model
model = pickle.load(open('random_forest_model.pkl', 'rb'))

# Feature names
feature_names = [
    'age', 'sex', 'cp', 'trestbps', 'chol', 'fbs',
    'restecg', 'thalach', 'exang', 'oldpeak', 'slope',
    'ca', 'thal'
]

@app.route('/')
def home():
    if 'user' in session:
        return render_template('index.html')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            error = "Username already taken."
        else:
            hashed_pw = generate_password_hash(password)
            new_user = User(username=username, password_hash=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user'] = username
            return redirect(url_for('home'))
        else:
            error = "Invalid username or password"
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/predict', methods=['POST'])
def predict():
    if 'user' not in session:
        return redirect(url_for('login'))
    try:
        input_features = [float(request.form[feature]) for feature in feature_names]
        prediction = model.predict([input_features])[0]
        result = "Heart Disease Detected" if prediction == 0 else "No Heart Disease"
        return render_template('index.html', prediction=result)
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)
