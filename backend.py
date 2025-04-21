from flask import Flask, jsonify, request, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

# App Configuration
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///./admin.db')  # Use environment variable or default
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key') #  Use environment variable
db = SQLAlchemy(app)

# --- Database Models ---

class User(db.Model):
    """
    User model for the admin panel.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    role = db.Column(db.String(20), default='editor') #  'admin', 'editor', etc.
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        """Hashes the password using Werkzeug's security module."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Post(db.Model):
    """
    Model for blog posts.  Added for demonstration.
    """
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref=db.backref('posts', lazy=True))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Post {self.title}>'

# --- Authentication and Authorization ---

def authenticate(username, password):
    """
    Authenticates a user.  Returns the user object if successful, None otherwise.
    """
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        return user
    return None

def login_required(f):
    """
    Decorator to protect routes that require authentication.
    """
    from functools import wraps
    from flask import request, jsonify, g
    import jwt
    import os
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Authentication required'}), 401

        try:
            #  Use the SECRET_KEY from the environment
            secret_key = os.environ.get('SECRET_KEY', 'your_secret_key')
            data = jwt.decode(token, secret_key, algorithms=['HS256']) # Specify the algorithm
            user_id = data.get('user_id')  # Corrected to fetch user_id
            if not user_id:
                raise jwt.InvalidTokenError("Missing user_id in token")
            user = User.query.get(user_id)
            if not user:
                return jsonify({'message': 'Invalid token: User not found'}), 401
            g.user = user  # Store the user object in the global context
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired'}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({'message': 'Invalid token', 'error': str(e)}), 401
        except Exception as e:
            return jsonify({'message': 'An error occurred', 'error': str(e)}), 500

        return f(*args, **kwargs)
    return wraps(f)

def role_required(role):
    """
    Decorator to restrict access to users with a specific role.
    """
    from functools import wraps
    from flask import jsonify, g

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'user') or g.user.role != role:
                return jsonify({'message': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- User Management API ---

@app.route('/admin/login', methods=['POST'])
def login():
    """
    Logs in a user and returns a JWT token.
    """
    from flask import request, jsonify
    import jwt
    from datetime import datetime, timedelta
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    user = authenticate(username, password)
    if not user:
        return jsonify({'message': 'Invalid credentials'}), 401

    #  Use the SECRET_KEY from the environment
    secret_key = os.environ.get('SECRET_KEY', 'your_secret_key')
    # Generate JWT token
    token = jwt.encode({
        'user_id': user.id,  # Store user ID, not the whole object
        'exp': datetime.utcnow() + timedelta(hours=24)  # Token expiration time
    }, secret_key, algorithm='HS256')  #  Specify the algorithm

    # Update last login time
    user.last_login = datetime.utcnow()
    db.session.commit()

    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role
        }
    }), 200

@app.route('/admin/users', methods=['GET'])
@login_required
@role_required('admin')  # Only admins can list all users
def get_users():
    """
    Returns a list of all users.  Requires admin role.
    """
    users = User.query.all()
    user_list = [{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role,
        'created_at': user.created_at.isoformat(),
        'last_login': user.last_login.isoformat() if user.last_login else None
    } for user in users]
    return jsonify({'users': user_list}), 200

@app.route('/admin/users/<int:user_id>', methods=['GET'])
@login_required
@role_required('admin') # Only admins can get user details
def get_user(user_id):
    """
    Returns a single user.  Requires admin role.
    """
    user = User.query.get_or_404(user_id)
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role,
        'created_at': user.created_at.isoformat(),
        'last_login': user.last_login.isoformat() if user.last_login else None
    }), 200

@app.route('/admin/users', methods=['POST'])
@login_required
@role_required('admin') # Only admins can create users
def create_user():
    """
    Creates a new user.  Requires admin role.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    role = data.get('role', 'editor')  # Default role

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400

    new_user = User(username=username, email=email, role=role)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully', 'user_id': new_user.id}), 201

@app.route('/admin/users/<int:user_id>', methods=['PUT'])
@login_required
@role_required('admin') # Only admins can update users
def update_user(user_id):
    """
    Updates an existing user.  Requires admin role.
    """
    data = request.get_json()
    user = User.query.get_or_404(user_id)

    user.username = data.get('username', user.username)
    user.email = data.get('email', user.email)
    user.role = data.get('role', user.role) # added role update

    if data.get('password'):
        user.set_password(data['password'])

    db.session.commit()
    return jsonify({'message': 'User updated successfully'}), 200

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
@role_required('admin') # Only admins can delete users
def delete_user(user_id):
    """
    Deletes a user.  Requires admin role.
    """
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'}), 200

# --- Post Management API (Example) ---

@app.route('/admin/posts', methods=['GET'])
@login_required
def get_posts():
    """
    Returns all posts.  Any logged-in user can access.
    """
    posts = Post.query.all()
    post_list = [{
        'id': post.id,
        'title': post.title,
        'content': post.content,
        'author_id': post.author_id,
        'author': post.author.username,
        'created_at': post.created_at.isoformat(),
        'updated_at': post.updated_at.isoformat() if post.updated_at else None
    } for post in posts]
    return jsonify({'posts': post_list}), 200

@app.route('/admin/posts/<int:post_id>', methods=['GET'])
@login_required
def get_post(post_id):
    """
    Returns a specific post. Any logged-in user can access.
    """
    post = Post.query.get_or_404(post_id)
    return jsonify({
        'id': post.id,
        'title': post.title,
        'content': post.content,
        'author_id': post.author_id,
        'author': post.author.username,
        'created_at': post.created_at.isoformat(),
        'updated_at': post.updated_at.isoformat() if post.updated_at else None
    }), 200

@app.route('/admin/posts', methods=['POST'])
@login_required
def create_post():
    """
    Creates a new post.  Any logged-in user can create.
    """
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')
    # The current user is the author
    author_id = g.user.id

    if not title or not content:
        return jsonify({'message': 'Title and content are required'}), 400

    new_post = Post(title=title, content=content, author_id=author_id)
    db.session.add(new_post)
    db.session.commit()
    return jsonify({'message': 'Post created successfully', 'post_id': new_post.id}), 201

@app.route('/admin/posts/<int:post_id>', methods=['PUT'])
@login_required
def update_post(post_id):
    """
    Updates an existing post.  Only the author or an admin can update.
    """
    data = request.get_json()
    post = Post.query.get_or_404(post_id)

    # Check if the user is the author or an admin
    if g.user.id != post.author_id and g.user.role != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403

    post.title = data.get('title', post.title)
    post.content = data.get('content', post.content)
    db.session.commit()
    return jsonify({'message': 'Post updated successfully'}), 200

@app.route('/admin/posts/<int:post_id>', methods=['DELETE'])
@login_required
def delete_post(post_id):
    """
    Deletes a post. Only the author or an admin can delete.
    """
    post = Post.query.get_or_404(post_id)
     # Check if the user is the author or an admin
    if g.user.id != post.author_id and g.user.role != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403
    db.session.delete(post)
    db.session.commit()
    return jsonify({'message': 'Post deleted successfully'}), 200

# --- Initialize Database ---

@app.cli.command('initdb')
def initdb_command():
    """Creates the database tables and an initial admin user."""
    with app.app_context():
        db.create_all()
        # Check if an admin user already exists
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', email='admin@example.com', role='admin')
            admin_user.set_password('adminpassword')  #  Use a strong password in production
            db.session.add(admin_user)
            db.session.commit()
            print('Initialized database and created admin user.')
        else:
            print('Database already initialized.')

# --- Run the Application ---

if __name__ == '__main__':
    # Create an application context for the database operations
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=True, host='0.0.0.0') # make app accessible externally
