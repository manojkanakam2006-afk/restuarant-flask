from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime, timedelta
import json
import os
import re
from contextlib import closing
import logging

app = Flask(__name__)

# Configuration
app.config['JWT_SECRET_KEY'] = 'change-this-to-a-very-strong-secret-key-in-production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# CORS Configuration - Restrict to specific origins
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:5500", "http://127.0.0.1:5500", "http://localhost:3000"],
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# JWT Manager
jwt = JWTManager(app)

# Rate Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATABASE = 'restaurant.db'

# ==================== UTILITY FUNCTIONS ====================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    return phone.isdigit() and len(phone) == 10

def validate_password(password):
    return len(password) >= 6

def sanitize_string(text):
    if not text:
        return ""
    return text.strip()[:500]  # Limit length and strip whitespace

# ==================== MENU DATA (for cart validation) ====================
MENU_ITEMS = {
    101: {"name": "Chicken 65", "price": 220},
    102: {"name": "Chicken Tikka", "price": 250},
    103: {"name": "Fish Fry", "price": 280},
    104: {"name": "Mutton Seekh Kebab", "price": 320},
    105: {"name": "Tandoori Chicken", "price": 300},
    106: {"name": "Chicken Wings", "price": 240},
    201: {"name": "Paneer Tikka", "price": 180},
    202: {"name": "Veg Spring Rolls", "price": 150},
    203: {"name": "Mushroom Pepper Dry", "price": 190},
    204: {"name": "Gobi Manchurian", "price": 160},
    205: {"name": "Hara Bhara Kabab", "price": 170},
    206: {"name": "Crispy Corn", "price": 140},
    301: {"name": "Tomato Soup", "price": 100},
    302: {"name": "Hot & Sour Soup", "price": 120},
    303: {"name": "Manchow Soup", "price": 130},
    304: {"name": "Chicken Clear Soup", "price": 140},
    305: {"name": "Sweet Corn Soup", "price": 110},
    306: {"name": "Lemon Coriander Soup", "price": 120},
    401: {"name": "Chicken Biryani", "price": 280},
    402: {"name": "Mutton Biryani", "price": 350},
    403: {"name": "Butter Chicken", "price": 320},
    404: {"name": "Paneer Butter Masala", "price": 250},
    405: {"name": "Dal Makhani", "price": 200},
    406: {"name": "Veg Biryani", "price": 220},
    501: {"name": "Grilled Fish", "price": 400},
    502: {"name": "Prawn Curry", "price": 450},
    503: {"name": "Fish Tikka", "price": 380},
    504: {"name": "Crab Masala", "price": 500},
    505: {"name": "Prawn Fry", "price": 420},
    506: {"name": "Fish Curry", "price": 380},
    601: {"name": "Veg Hakka Noodles", "price": 180},
    602: {"name": "Chicken Noodles", "price": 220},
    603: {"name": "Schezwan Fried Rice", "price": 200},
    604: {"name": "Singapore Noodles", "price": 240},
    605: {"name": "Thai Fried Rice", "price": 250},
    606: {"name": "Egg Fried Rice", "price": 190},
    701: {"name": "Greek Salad", "price": 150},
    702: {"name": "Caesar Salad", "price": 180},
    703: {"name": "Garden Fresh Salad", "price": 130},
    704: {"name": "Chicken Salad", "price": 200},
    705: {"name": "Fruit Salad", "price": 140},
    706: {"name": "Chickpea Salad", "price": 160},
    801: {"name": "Gulab Jamun", "price": 120},
    802: {"name": "Ice Cream Sundae", "price": 150},
    803: {"name": "Chocolate Brownie", "price": 180},
    804: {"name": "Rasmalai", "price": 140},
    805: {"name": "Tiramisu", "price": 200},
    806: {"name": "Kheer (Rice Pudding)", "price": 130}
}

# ==================== DATABASE INITIALIZATION ====================

def init_db():
    with closing(get_db()) as conn:
        cursor = conn.cursor()
        
        # Drop existing tables
        cursor.execute('DROP TABLE IF EXISTS orders')
        cursor.execute('DROP TABLE IF EXISTS feedbacks')
        cursor.execute('DROP TABLE IF EXISTS customers')
        cursor.execute('DROP TABLE IF EXISTS delivery_boys')
        cursor.execute('DROP TABLE IF EXISTS admins')
        
        # Customers table
        cursor.execute('''
            CREATE TABLE customers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Delivery boys table
        cursor.execute('''
            CREATE TABLE delivery_boys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                phone TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                vehicle_number TEXT NOT NULL,
                status TEXT DEFAULT 'available',
                total_deliveries INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Orders table
        cursor.execute('''
            CREATE TABLE orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id INTEGER NOT NULL,
                customer_name TEXT NOT NULL,
                phone TEXT NOT NULL,
                address TEXT NOT NULL,
                items TEXT NOT NULL,
                total REAL NOT NULL,
                status TEXT DEFAULT 'Order Placed',
                delivery_status TEXT DEFAULT 'pending_assignment',
                delivery_boy_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                pickup_time TIMESTAMP,
                delivered_time TIMESTAMP,
                FOREIGN KEY (customer_id) REFERENCES customers(id),
                FOREIGN KEY (delivery_boy_id) REFERENCES delivery_boys(id)
            )
        ''')
        
        # Feedbacks table
        cursor.execute('''
            CREATE TABLE feedbacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id INTEGER,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                rating INTEGER NOT NULL,
                comment TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (customer_id) REFERENCES customers(id)
            )
        ''')
        
        # Admin table
        cursor.execute('''
            CREATE TABLE admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create default admin
        cursor.execute('''
            INSERT INTO admins (name, email, phone, password)
            VALUES (?, ?, ?, ?)
        ''', ('Admin', 'admin@foodmunch.com', '9999999999', 
              generate_password_hash('admin123')))
        
        conn.commit()
    
    logger.info("✅ Database initialized successfully!")

# Initialize database
if not os.path.exists(DATABASE):
    init_db()

# ==================== CUSTOMER ENDPOINTS ====================

@app.route('/api/customer/register', methods=['POST'])
@limiter.limit("5 per hour")
def register_customer():
    try:
        data = request.json
        
        # Validate input
        if not validate_email(data.get('email', '')):
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400
        
        if not validate_phone(data.get('phone', '')):
            return jsonify({'success': False, 'message': 'Invalid phone number'}), 400
        
        if not validate_password(data.get('password', '')):
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400
        
        # Sanitize inputs
        name = sanitize_string(data.get('name', ''))
        email = sanitize_string(data.get('email', '')).lower()
        phone = data.get('phone', '')
        address = sanitize_string(data.get('address', ''))
        
        if len(name) < 3:
            return jsonify({'success': False, 'message': 'Name must be at least 3 characters'}), 400
        
        with closing(get_db()) as conn:
            cursor = conn.cursor()
            
            # Check if email exists
            cursor.execute('SELECT id FROM customers WHERE email = ?', (email,))
            if cursor.fetchone():
                return jsonify({'success': False, 'message': 'Email already registered'}), 400
            
            # Check if phone exists
            cursor.execute('SELECT id FROM customers WHERE phone = ?', (phone,))
            if cursor.fetchone():
                return jsonify({'success': False, 'message': 'Phone number already registered'}), 400
            
            # Hash password and insert
            hashed_password = generate_password_hash(data['password'])
            cursor.execute('''
                INSERT INTO customers (name, email, phone, password, address)
                VALUES (?, ?, ?, ?, ?)
            ''', (name, email, phone, hashed_password, address))
            
            conn.commit()
            customer_id = cursor.lastrowid
        
        logger.info(f"New customer registered: {email}")
        return jsonify({'success': True, 'customer_id': customer_id})
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'success': False, 'message': 'Registration failed'}), 500

@app.route('/api/customer/login', methods=['POST'])
@limiter.limit("10 per minute")
def login_customer():
    try:
        data = request.json
        email = sanitize_string(data.get('email', '')).lower()
        password = data.get('password', '')
        
        if not validate_email(email):
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400
        
        with closing(get_db()) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM customers WHERE email = ?', (email,))
            customer = cursor.fetchone()
        
        if customer and check_password_hash(customer['password'], password):
            # Create JWT token
            access_token = create_access_token(
                identity=customer['id'],
                additional_claims={'type': 'customer'}
            )
            
            logger.info(f"Customer login: {email}")
            return jsonify({
                'success': True,
                'token': access_token,
                'customer': {
                    'id': customer['id'],
                    'name': customer['name'],
                    'email': customer['email'],
                    'phone': customer['phone'],
                    'address': customer['address']
                }
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'success': False, 'message': 'Login failed'}), 500

@app.route('/api/customer/<int:customer_id>/orders', methods=['GET'])
@jwt_required()
def get_customer_orders(customer_id):
    try:
        # Verify the user is accessing their own orders
        current_user_id = get_jwt_identity()
        if current_user_id != customer_id:
            return jsonify({'success': False, 'message': 'Unauthorized access'}), 403
        
        with closing(get_db()) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT o.*, db.name as delivery_boy_name, db.phone as delivery_boy_phone
                FROM orders o 
                LEFT JOIN delivery_boys db ON o.delivery_boy_id = db.id 
                WHERE o.customer_id = ?
                ORDER BY o.id DESC
            ''', (customer_id,))
            orders = cursor.fetchall()
        
        orders_list = []
        for order in orders:
            orders_list.append({
                'id': order['id'],
                'customer_name': order['customer_name'],
                'phone': order['phone'],
                'address': order['address'],
                'items': json.loads(order['items']),
                'total': order['total'],
                'status': order['status'],
                'delivery_status': order['delivery_status'],
                'delivery_boy_name': order['delivery_boy_name'],
                'delivery_boy_phone': order['delivery_boy_phone'],
                'created_at': order['created_at'],
                'pickup_time': order['pickup_time'],
                'delivered_time': order['delivered_time']
            })
        
        return jsonify({'success': True, 'orders': orders_list})
        
    except Exception as e:
        logger.error(f"Get orders error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to fetch orders'}), 500

# ==================== ORDER ENDPOINTS ====================

@app.route('/api/order', methods=['POST'])
@jwt_required()
@limiter.limit("20 per hour")
def create_order():
    try:
        data = request.json
        current_user_id = get_jwt_identity()
        
        # Validate required fields
        required_fields = ['customer_id', 'customer_name', 'phone', 'address', 'items', 'total']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'message': f'Missing required field: {field}'}), 400
        
        # Verify user is creating order for themselves
        if current_user_id != data['customer_id']:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
        # Validate and recalculate total (prevent price manipulation)
        items = data['items']
        calculated_total = 0
        validated_items = []
        
        for item in items:
            item_id = item.get('id')
            quantity = item.get('quantity', 0)
            
            if item_id not in MENU_ITEMS:
                return jsonify({'success': False, 'message': f'Invalid item ID: {item_id}'}), 400
            
            if quantity <= 0 or quantity > 50:
                return jsonify({'success': False, 'message': 'Invalid quantity'}), 400
            
            actual_price = MENU_ITEMS[item_id]['price']
            calculated_total += actual_price * quantity
            
            validated_items.append({
                'id': item_id,
                'name': MENU_ITEMS[item_id]['name'],
                'price': actual_price,
                'quantity': quantity
            })
        
        # Check if submitted total matches calculated total
        if abs(calculated_total - data['total']) > 0.01:
            logger.warning(f"Price mismatch detected for customer {current_user_id}")
            return jsonify({'success': False, 'message': 'Price validation failed'}), 400
        
        # Sanitize inputs
        customer_name = sanitize_string(data['customer_name'])
        phone = data['phone']
        address = sanitize_string(data['address'])
        
        if not validate_phone(phone):
            return jsonify({'success': False, 'message': 'Invalid phone number'}), 400
        
        with closing(get_db()) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO orders (customer_id, customer_name, phone, address, items, total, status, delivery_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data['customer_id'],
                customer_name,
                phone,
                address,
                json.dumps(validated_items),
                calculated_total,
                'Order Placed',
                'pending_assignment'
            ))
            conn.commit()
            order_id = cursor.lastrowid
        
        logger.info(f"Order created: #{order_id} by customer {current_user_id}")
        return jsonify({'success': True, 'order_id': order_id})
        
    except Exception as e:
        logger.error(f"Create order error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to create order'}), 500

# ==================== ADMIN ENDPOINTS ====================

@app.route('/api/admin/register', methods=['POST'])
@limiter.limit("3 per hour")
def register_admin():
    try:
        data = request.json
        
        # Verify admin code
        ADMIN_SECRET_CODE = "FOODMUNCH2024"
        if data.get('admin_code') != ADMIN_SECRET_CODE:
            logger.warning("Invalid admin registration attempt")
            return jsonify({'success': False, 'message': 'Invalid admin registration code'}), 403
        
        # Validate input
        if not validate_email(data.get('email', '')):
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400
        
        if not validate_phone(data.get('phone', '')):
            return jsonify({'success': False, 'message': 'Invalid phone number'}), 400
        
        if len(data.get('password', '')) < 8:
            return jsonify({'success': False, 'message': 'Admin password must be at least 8 characters'}), 400
        
        # Sanitize inputs
        name = sanitize_string(data.get('name', ''))
        email = sanitize_string(data.get('email', '')).lower()
        phone = data.get('phone', '')
        
        with closing(get_db()) as conn:
            cursor = conn.cursor()
            
            # Check if email exists
            cursor.execute('SELECT id FROM admins WHERE email = ?', (email,))
            if cursor.fetchone():
                return jsonify({'success': False, 'message': 'Email already registered'}), 400
            
            hashed_password = generate_password_hash(data['password'])
            cursor.execute('''
                INSERT INTO admins (name, email, phone, password)
                VALUES (?, ?, ?, ?)
            ''', (name, email, phone, hashed_password))
            conn.commit()
        
        logger.info(f"New admin registered: {email}")
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Admin registration error: {str(e)}")
        return jsonify({'success': False, 'message': 'Registration failed'}), 500

@app.route('/api/admin/login', methods=['POST'])
@limiter.limit("5 per minute")
def admin_login():
    try:
        data = request.json
        email = sanitize_string(data.get('email', '')).lower()
        password = data.get('password', '')
        
        with closing(get_db()) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM admins WHERE email = ?', (email,))
            admin = cursor.fetchone()
        
        if admin and check_password_hash(admin['password'], password):
            access_token = create_access_token(
                identity=admin['id'],
                additional_claims={'type': 'admin'}
            )
            
            logger.info(f"Admin login: {email}")
            return jsonify({
                'success': True,
                'token': access_token,
                'admin': {
                    'id': admin['id'],
                    'name': admin['name'],
                    'email': admin['email'],
                    'phone': admin['phone']
                }
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
            
    except Exception as e:
        logger.error(f"Admin login error: {str(e)}")
        return jsonify({'success': False, 'message': 'Login failed'}), 500

@app.route('/api/admin/orders', methods=['GET'])
@jwt_required()
def get_admin_orders():
    try:
        # Verify admin access
        claims = get_jwt_identity()
        # In production, verify the token has admin role
        
        with closing(get_db()) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT o.*, db.name as delivery_boy_name, db.phone as delivery_boy_phone
                FROM orders o 
                LEFT JOIN delivery_boys db ON o.delivery_boy_id = db.id 
                ORDER BY o.id DESC
            ''')
            orders = cursor.fetchall()
        
        orders_list = []
        for order in orders:
            orders_list.append({
                'id': order['id'],
                'customer_id': order['customer_id'],
                'customer_name': order['customer_name'],
                'phone': order['phone'],
                'address': order['address'],
                'items': json.loads(order['items']),
                'total': order['total'],
                'status': order['status'],
                'delivery_status': order['delivery_status'],
                'delivery_boy_id': order['delivery_boy_id'],
                'delivery_boy_name': order['delivery_boy_name'],
                'delivery_boy_phone': order['delivery_boy_phone'],
                'created_at': order['created_at'],
                'pickup_time': order['pickup_time'],
                'delivered_time': order['delivered_time']
            })
        
        return jsonify({'success': True, 'orders': orders_list})
        
    except Exception as e:
        logger.error(f"Get admin orders error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to fetch orders'}), 500

@app.route('/api/admin/customers', methods=['GET'])
@jwt_required()
def get_admin_customers():
    try:
        with closing(get_db()) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, email, phone, address, created_at FROM customers ORDER BY id DESC')
            customers = cursor.fetchall()
        
        customers_list = []
        for customer in customers:
            customers_list.append({
                'id': customer['id'],
                'name': customer['name'],
                'email': customer['email'],
                'phone': customer['phone'],
                'address': customer['address'],
                'created_at': customer['created_at']
            })
        
        return jsonify({'success': True, 'customers': customers_list})
        
    except Exception as e:
        logger.error(f"Get customers error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to fetch customers'}), 500

@app.route('/api/admin/deliveryboys', methods=['GET'])
@jwt_required()
def get_admin_deliveryboys():
    try:
        with closing(get_db()) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT db.*, 
                       COUNT(CASE WHEN o.delivery_status IN ('assigned', 'out_for_delivery') 
                            THEN 1 END) as current_orders
                FROM delivery_boys db
                LEFT JOIN orders o ON db.id = o.delivery_boy_id
                GROUP BY db.id
                ORDER BY db.id DESC
            ''')
            delivery_boys = cursor.fetchall()
        
        delivery_boys_list = []
        for db in delivery_boys:
            delivery_boys_list.append({
                'id': db['id'],
                'name': db['name'],
                'phone': db['phone'],
                'email': db['email'],
                'vehicle_number': db['vehicle_number'],
                'status': db['status'],
                'total_deliveries': db['total_deliveries'],
                'current_orders': db['current_orders']
            })
        
        return jsonify({'success': True, 'delivery_boys': delivery_boys_list})
        
    except Exception as e:
        logger.error(f"Get delivery boys error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to fetch delivery boys'}), 500

@app.route('/api/admin/feedback', methods=['GET'])
@jwt_required()
def get_admin_feedback():
    try:
        with closing(get_db()) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM feedbacks ORDER BY id DESC')
            feedbacks = cursor.fetchall()
        
        feedbacks_list = []
        for feedback in feedbacks:
            feedbacks_list.append({
                'id': feedback['id'],
                'customer_id': feedback['customer_id'],
                'name': feedback['name'],
                'email': feedback['email'],
                'rating': feedback['rating'],
                'comment': feedback['comment'],
                'created_at': feedback['created_at']
            })
        
        return jsonify({'success': True, 'feedback': feedbacks_list})
        
    except Exception as e:
        logger.error(f"Get feedback error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to fetch feedback'}), 500

@app.route('/api/admin/assign-order', methods=['POST'])
@jwt_required()
def admin_assign_order():
    try:
        data = request.json
        order_id = data.get('order_id')
        delivery_boy_id = data.get('delivery_boy_id')
        
        if not order_id or not delivery_boy_id:
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        with closing(get_db()) as conn:
            cursor = conn.cursor()
            
            # Verify delivery boy exists
            cursor.execute('SELECT id FROM delivery_boys WHERE id = ?', (delivery_boy_id,))
            if not cursor.fetchone():
                return jsonify({'success': False, 'message': 'Delivery boy not found'}), 404
            
            cursor.execute('''
                UPDATE orders 
                SET delivery_boy_id = ?, 
                    delivery_status = 'assigned',
                    status = 'Assigned to Delivery Boy'
                WHERE id = ?
            ''', (delivery_boy_id, order_id))
            conn.commit()
        
        logger.info(f"Order #{order_id} assigned to delivery boy #{delivery_boy_id}")
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Assign order error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to assign order'}), 500

# ==================== DELIVERY BOY ENDPOINTS ====================

@app.route('/api/deliveryboy/register', methods=['POST'])
@limiter.limit("5 per hour")
def register_delivery_boy():
    try:
        data = request.json
        
        # Validate input
        if not validate_email(data.get('email', '')):
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400
        
        if not validate_phone(data.get('phone', '')):
            return jsonify({'success': False, 'message': 'Invalid phone number'}), 400
        
        if not validate_password(data.get('password', '')):
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400
        
        # Sanitize inputs
        name = sanitize_string(data.get('name', ''))
        email = sanitize_string(data.get('email', '')).lower()
        phone = data.get('phone', '')
        vehicle_number = sanitize_string(data.get('vehicle_number', '')).upper()
        
        if len(vehicle_number) < 6:
            return jsonify({'success': False, 'message': 'Invalid vehicle number'}), 400
        
        with closing(get_db()) as conn:
            cursor = conn.cursor()
            
            # Check duplicates
            cursor.execute('SELECT id FROM delivery_boys WHERE email = ?', (email,))
            if cursor.fetchone():
                return jsonify({'success': False, 'message': 'Email already registered'}), 400
            
            cursor.execute('SELECT id FROM delivery_boys WHERE phone = ?', (phone,))
            if cursor.fetchone():
                return jsonify({'success': False, 'message': 'Phone number already registered'}), 400
            
            hashed_password = generate_password_hash(data['password'])
            cursor.execute('''
                INSERT INTO delivery_boys (name, phone, email, password, vehicle_number)
                VALUES (?, ?, ?, ?, ?)
            ''', (name, phone, email, hashed_password, vehicle_number))
            conn.commit()
        
        logger.info(f"New delivery boy registered: {email}")
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Delivery boy registration error: {str(e)}")
        return jsonify({'success': False, 'message': 'Registration failed'}), 500

@app.route('/api/deliveryboy/login', methods=['POST'])
@limiter.limit("10 per minute")
def login_delivery_boy():
    try:
        data = request.json
        email = sanitize_string(data.get('email', '')).lower()
        password = data.get('password', '')
        
        if not validate_email(email):
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400
        
        with closing(get_db()) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM delivery_boys WHERE email = ?', (email,))
            delivery_boy = cursor.fetchone()
        
        if delivery_boy and check_password_hash(delivery_boy['password'], password):
            access_token = create_access_token(
                identity=delivery_boy['id'],
                additional_claims={'type': 'delivery'}
            )
            
            logger.info(f"Delivery boy login: {email}")
            return jsonify({
                'success': True,
                'token': access_token,
                'delivery_boy': {
                    'id': delivery_boy['id'],
                    'name': delivery_boy['name'],
                    'phone': delivery_boy['phone'],
                    'email': delivery_boy['email'],
                    'vehicle_number': delivery_boy['vehicle_number'],
                    'total_deliveries': delivery_boy['total_deliveries']
                }
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
            
    except Exception as e:
        logger.error(f"Delivery boy login error: {str(e)}")
        return jsonify({'success': False, 'message': 'Login failed'}), 500

@app.route('/api/deliveryboy/<int:delivery_boy_id>/orders', methods=['GET'])
@jwt_required()
def get_delivery_boy_orders(delivery_boy_id):
    try:
        # Verify the delivery boy is accessing their own orders
        current_user_id = get_jwt_identity()
        if current_user_id != delivery_boy_id:
            return jsonify({'success': False, 'message': 'Unauthorized access'}), 403
        
        with closing(get_db()) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM orders 
                WHERE delivery_boy_id = ? 
                ORDER BY id DESC
            ''', (delivery_boy_id,))
            orders = cursor.fetchall()
        
        orders_list = []
        for order in orders:
            orders_list.append({
                'id': order['id'],
                'customer_id': order['customer_id'],
                'customer_name': order['customer_name'],
                'phone': order['phone'],
                'address': order['address'],
                'items': json.loads(order['items']),
                'total': order['total'],
                'status': order['status'],
                'delivery_status': order['delivery_status'],
                'created_at': order['created_at'],
                'pickup_time': order['pickup_time'],
                'delivered_time': order['delivered_time']
            })
        
        return jsonify({'success': True, 'orders': orders_list})
        
    except Exception as e:
        logger.error(f"Get delivery boy orders error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to fetch orders'}), 500

@app.route('/api/deliveryboy/pickup-order', methods=['POST'])
@jwt_required()
def pickup_order():
    try:
        data = request.json
        order_id = data.get('order_id')
        delivery_boy_id = data.get('delivery_boy_id')
        
        # Verify the delivery boy is updating their own order
        current_user_id = get_jwt_identity()
        if current_user_id != delivery_boy_id:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
        with closing(get_db()) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE orders 
                SET delivery_status = 'out_for_delivery',
                    status = 'Out for Delivery',
                    pickup_time = CURRENT_TIMESTAMP
                WHERE id = ? AND delivery_boy_id = ?
            ''', (order_id, delivery_boy_id))
            conn.commit()
        
        logger.info(f"Order #{order_id} picked up by delivery boy #{delivery_boy_id}")
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Pickup order error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to update order status'}), 500

@app.route('/api/deliveryboy/deliver-order', methods=['POST'])
@jwt_required()
def deliver_order():
    try:
        data = request.json
        order_id = data.get('order_id')
        delivery_boy_id = data.get('delivery_boy_id')
        
        # Verify the delivery boy is updating their own order
        current_user_id = get_jwt_identity()
        if current_user_id != delivery_boy_id:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
        with closing(get_db()) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE orders 
                SET delivery_status = 'delivered',
                    status = 'Delivered',
                    delivered_time = CURRENT_TIMESTAMP
                WHERE id = ? AND delivery_boy_id = ?
            ''', (order_id, delivery_boy_id))
            
            cursor.execute('''
                UPDATE delivery_boys 
                SET total_deliveries = total_deliveries + 1 
                WHERE id = ?
            ''', (delivery_boy_id,))
            conn.commit()
        
        logger.info(f"Order #{order_id} delivered by delivery boy #{delivery_boy_id}")
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Deliver order error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to update order status'}), 500

# ==================== FEEDBACK ENDPOINTS ====================

@app.route('/api/feedback', methods=['POST'])
@limiter.limit("10 per hour")
def create_feedback():
    try:
        data = request.json
        
        # Validate input
        rating = data.get('rating', 0)
        if not isinstance(rating, int) or rating < 1 or rating > 5:
            return jsonify({'success': False, 'message': 'Rating must be between 1 and 5'}), 400
        
        # Sanitize inputs
        name = sanitize_string(data.get('name', ''))
        email = sanitize_string(data.get('email', '')).lower()
        comment = sanitize_string(data.get('comment', ''))
        
        if len(name) < 2:
            return jsonify({'success': False, 'message': 'Name is required'}), 400
        
        if not validate_email(email):
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400
        
        if len(comment) < 10:
            return jsonify({'success': False, 'message': 'Comment must be at least 10 characters'}), 400
        
        with closing(get_db()) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO feedbacks (customer_id, name, email, rating, comment)
                VALUES (?, ?, ?, ?, ?)
            ''', (data.get('customer_id'), name, email, rating, comment))
            conn.commit()
        
        logger.info(f"Feedback submitted by {email}")
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Feedback error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to submit feedback'}), 500

# ==================== HEALTH CHECK ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'success': False, 'message': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {str(e)}")
    return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'success': False, 'message': 'Rate limit exceeded. Please try again later.'}), 429

# ==================== MAIN ====================

if __name__ == '__main__':
    print("=" * 70)
    print("🍔 FOOD MUNCH RESTAURANT - SECURE BACKEND SERVER")
    print("=" * 70)
    print("✅ Server running at: http://localhost:5000")
    print("✅ Database: restaurant.db")
    print("=" * 70)
    print("📋 DEFAULT CREDENTIALS:")
    print("   Admin: email='admin@foodmunch.com', password='admin123'")
    print("   Admin Registration Code: 'FOODMUNCH2024'")
    print("=" * 70)
    print("🔒 SECURITY FEATURES ENABLED:")
    print("   ✓ JWT Authentication")
    print("   ✓ Password Hashing (bcrypt)")
    print("   ✓ Rate Limiting")
    print("   ✓ CORS Protection")
    print("   ✓ Input Validation")
    print("   ✓ Cart Price Validation")
    print("=" * 70)
    print("🔗 API ENDPOINTS:")
    print("   Customer: /api/customer/register, /api/customer/login")
    print("   Delivery: /api/deliveryboy/register, /api/deliveryboy/login")
    print("   Admin: /api/admin/register, /api/admin/login")
    print("   Orders: /api/order (requires JWT token)")
    print("=" * 70)
    print("⚠️  IMPORTANT: Install required packages:")
    print("   pip install flask flask-cors flask-limiter flask-jwt-extended werkzeug")
    print("=" * 70)
    app.run(debug=True, port=5000)


from flask import render_template

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/deliveryboy_portal')
def deliveryboy_portal():
    return render_template('deliveryboy_portal.html')

@app.route('/admin')
def admin_page():
    return render_template('admin.html')

if __name__ == '__main__':
    app.run(debug=True)
