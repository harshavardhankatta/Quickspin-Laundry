# app.py

import os
import random
import string
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename

from dotenv import load_dotenv
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from io import BytesIO
import qrcode
from flask import send_file
from PIL import Image
from sqlalchemy import func

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'supersecretkey')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///spinate.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Upload configuration
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
# Ensure invoices directory exists
invoices_folder = os.path.join(os.path.dirname(__file__), 'static', 'invoices')
if not os.path.exists(invoices_folder):
    os.makedirs(invoices_folder)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Mail configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True if os.getenv('MAIL_USE_TLS', 'True') == 'True' else False
app.config['MAIL_USE_SSL'] = True if os.getenv('MAIL_USE_SSL', 'False') == 'True' else False
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

# Google Maps API Key
app.config['MAPS_API_KEY'] = os.getenv('MAPS_API_KEY', '')

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

# Role-based access decorator
def role_required(role):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                flash("Access denied.")
                return redirect(url_for('login'))
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

statuses = [
    'Order Placed',     # ✅
    'Accepted',         # 👀
    'Pickup Assigned',  # 🛵
    'Picked Up',        # 📦
    'Washing',          # 🧺
    'Drying',           # 💨
    'Ironing',          # 🧲
    'Packed',           # 📦
    'Out for Delivery', # 🚚
    'Delivered'         # 🏡
]
# Database Models

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    password = db.Column(db.String(256))
    role = db.Column(db.String(20), default='Customer')  # roles: Customer, Executive, Admin
    otp = db.Column(db.String(6), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)
    language = db.Column(db.String(5), default='en')  # en, hi, te etc.
    dark_mode = db.Column(db.Boolean, default=False)

    orders = db.relationship(
        'Order',
        backref='customer',
        lazy=True,
        foreign_keys='Order.customer_id'
    )

    # Orders where this user is the executive (optional but recommended)
    executive_orders = db.relationship(
        'Order',
        backref='executive',
        lazy=True,
        foreign_keys='Order.executive_id'
    )

    complaints = db.relationship('Complaint', backref='user', lazy=True)
    def __repr__(self):
        return f"<User {self.email}>"

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service = db.Column(db.String(100))
    pickup_time = db.Column(db.DateTime, nullable=False)
    delivery_time = db.Column(db.DateTime, nullable=True)
    weight = db.Column(db.Float)
    instructions = db.Column(db.Text)
    status = db.Column(db.String(50), default='Pending')  # e.g., Pending, In-Process, Delivered, Cancelled
    image = db.Column(db.String(100))  # path to uploaded image
    rating = db.Column(db.Integer, nullable=True)
    feedback = db.Column(db.Text, nullable=True)

    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    executive_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    complaint = db.relationship('Complaint', backref='order', uselist=False)
    invoice = db.relationship('Invoice', backref='order', uselist=False)

    def __repr__(self):
        return f"<Order {self.id} - {self.status}>"

class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<Complaint {self.id}>"

class Coupon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    discount = db.Column(db.Float, nullable=False)  # e.g., 0.10 for 10%
    expiry_date = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f"<Coupon {self.code}>"

class Invoice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    pdf_path = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return f"<Invoice {self.id} for Order {self.order_id}>"

class ServiceArea(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pincode = db.Column(db.String(10), unique=True, nullable=False)

    def __repr__(self):
        return f"<ServiceArea {self.pincode}>"

class ServiceType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(255))
    price = db.Column(db.Float, nullable=False)

    def __repr__(self):
        return f"<ServiceType {self.name}>"

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Utility functions

def send_otp_email(user):
    """Generate a 6-digit OTP, save it to user, and send via email."""
    otp = ''.join(random.choices(string.digits, k=6))
    user.otp = otp
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
    db.session.commit()

    msg = Message('Your SpinMate OTP', sender=app.config['MAIL_USERNAME'], recipients=[user.email])
    msg.body = f"Your One-Time Password (OTP) is {otp}. It is valid for 10 minutes."
    mail.send(msg)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes

@app.route('/')
def index():
    return render_template('index.html', datetime=datetime)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        role = request.form.get('role', 'Customer')
        # Hash password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered.')
            return redirect(url_for('register'))

        user = User(name=name, email=email, phone=phone, password=hashed_password, role=role)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login: password or OTP"""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form.get('password')
        use_otp = request.form.get('use_otp', False)

        user = User.query.filter_by(email=email).first()
        if user:
            if use_otp:
                # Generate and send OTP
                send_otp_email(user)
                flash('OTP sent to your email.')
                return redirect(url_for('verify_otp', user_id=user.id))
            else:
                if check_password_hash(user.password, password):
                    login_user(user)
                    flash('Logged in successfully.')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid password.')
        else:
            flash('User not found.')
    return render_template('login.html')

@app.route('/verify_otp/<int:user_id>', methods=['GET', 'POST'])
def verify_otp(user_id):
    """Verify OTP for login"""
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        otp = request.form['otp']
        if user.otp == otp and datetime.utcnow() <= user.otp_expiry:
            # OTP valid
            user.otp = None
            user.otp_expiry = None
            db.session.commit()
            login_user(user)
            flash('Logged in via OTP.')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid or expired OTP.')
    return render_template('verify_otp.html', user=user)

@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    logout_user()
    flash('Logged out.')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Redirect user to role-specific dashboard"""
    if current_user.role == 'Admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'Executive':
        return redirect(url_for('executive_panel'))
    else:
        return redirect(url_for('customer_panel'))

# Customer Panel
@app.route('/customer', methods=['GET'])
@login_required
@role_required('Customer')
def customer_panel():
    """Customer main panel: list orders, actions"""
    orders = Order.query.filter_by(customer_id=current_user.id).all()
    return render_template('customer_panel.html', orders=orders)

@app.route('/place_order', methods=['GET', 'POST'])
@login_required
@role_required('Customer')
def place_order():
    """Place a new laundry order"""
    if request.method == 'POST':
        service = request.form['service']
        pickup_time = datetime.strptime(request.form['pickup_time'], '%Y-%m-%dT%H:%M')
        weight = float(request.form['weight'])
        instructions = request.form.get('instructions')
        # Handle file upload (e.g., photo of laundry)
        file = request.files.get('image')
        filename = None
        if file and allowed_file(file.filename):
            filename = f"{datetime.utcnow().timestamp()}_{secure_filename(file.filename)}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        # Create order record
        order = Order(
            service=service,
            pickup_time=pickup_time,
            weight=weight,
            instructions=instructions,
            customer_id=current_user.id,
            status='Pending',
            image=filename
        )
        db.session.add(order)
        db.session.commit()
        flash('Order placed successfully.')
        return redirect(url_for('customer_panel'))
    return render_template('place_order.html')

@app.route('/order_history')
@login_required
@role_required('Customer')
def order_history():
    orders = Order.query.filter_by(customer_id=current_user.id).all()
    return render_template('order_history.html', orders=orders)

@app.route('/customer/track_order/<int:order_id>')
@login_required
@role_required('Customer')
def track_order(order_id):
    """Track order status (customer)"""
    order = Order.query.get_or_404(order_id)
    if order.customer_id != current_user.id:
        flash("Unauthorized access.")
        return redirect(url_for('customer_panel'))
    # Could integrate Google Maps API or real-time updates here
    return render_template('track_order.html', order=order)

@app.route('/customer/feedback/<int:order_id>', methods=['POST'])
@login_required
@role_required('Customer')
def give_feedback(order_id):
    """Submit rating/feedback for an order"""
    order = Order.query.get_or_404(order_id)
    rating = int(request.form['rating'])
    feedback = request.form.get('feedback')
    order.rating = rating
    order.feedback = feedback
    db.session.commit()
    flash('Feedback submitted. Thank you!')
    return redirect(url_for('customer_panel'))

@app.route('/customer/complaint/<int:order_id>', methods=['GET', 'POST'])
@login_required
@role_required('Customer')
def file_complaint(order_id):
    """File a complaint about an order"""
    order = Order.query.get_or_404(order_id)
    if request.method == 'POST':
        text = request.form['complaint']
        complaint = Complaint(order_id=order.id, user_id=current_user.id, text=text)
        db.session.add(complaint)
        db.session.commit()
        flash('Complaint submitted.')
        return redirect(url_for('customer_panel'))
    return render_template('complaint.html', order=order)

@app.route('/customer/reorder/<int:order_id>')
@login_required
@role_required('Customer')
def reorder(order_id):
    """Reorder a previous order with same details"""
    order = Order.query.get_or_404(order_id)
    # Create a new order with same details, schedule for next day
    new_order = Order(
        service=order.service,
        pickup_time=datetime.utcnow() + timedelta(days=1),
        weight=order.weight,
        instructions=order.instructions,
        customer_id=current_user.id,
        status='Pending'
    )
    db.session.add(new_order)
    db.session.commit()
    flash('Order placed again successfully.')
    return redirect(url_for('customer_panel'))

@app.route('/customer/cancel_order/<int:order_id>')
@login_required
@role_required('Customer')
def cancel_order(order_id):
    """Cancel an existing order"""
    order = Order.query.get_or_404(order_id)
    if order.customer_id != current_user.id:
        flash("Unauthorized action.")
    else:
        order.status = 'Cancelled'
        db.session.commit()
        flash('Order cancelled.')
    return redirect(url_for('customer_panel'))

@app.route('/customer/reschedule/<int:order_id>', methods=['POST'])
@login_required
@role_required('Customer')
def reschedule_order(order_id):
    """Reschedule pickup for an order"""
    order = Order.query.get_or_404(order_id)
    new_time = datetime.strptime(request.form['new_pickup_time'], '%Y-%m-%dT%H:%M')
    order.pickup_time = new_time
    db.session.commit()
    flash('Order pickup rescheduled.')
    return redirect(url_for('customer_panel'))

@app.route('/customer/auto_schedule')
@login_required
@role_required('Customer')
def auto_schedule():
    """Auto-schedule feature (recurring pickups) - placeholder"""
    flash('Auto-scheduling not implemented yet.')
    return redirect(url_for('customer_panel'))

# Executive Panel
@app.route('/executive')
@login_required
@role_required('Executive')
def executive_panel():
    """Executive main panel: list assigned orders"""
    orders = Order.query.filter_by(executive_id=current_user.id).all()
    return render_template('executive_panel.html', orders=orders)

@app.route('/executive/update_status/<int:order_id>', methods=['POST'])
@login_required
@role_required('Executive')
def update_status(order_id):
    """Executive updates order status and can upload delivery photo"""
    order = Order.query.get_or_404(order_id)
    if order.executive_id != current_user.id:
        flash("Unauthorized action.")
        return redirect(url_for('executive_panel'))
    status = request.form['status']
    order.status = status
    if status == 'Delivered':
        order.delivery_time = datetime.utcnow()
    # Handle delivery photo upload
    file = request.files.get('delivery_photo')
    if file and allowed_file(file.filename):
        filename = f"del_{datetime.utcnow().timestamp()}_{secure_filename(file.filename)}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        order.image = filename  # store/update delivery photo
    db.session.commit()
    flash('Order status updated.')
    return redirect(url_for('executive_panel'))

# Admin Panel
@app.route('/admin')
@login_required
@role_required('Admin')
def admin_dashboard():
    users = User.query.all()
    orders = Order.query.all()
    complaints = Complaint.query.all()
    coupons = Coupon.query.all()
    pincodes = ServiceArea.query.all()

    total_users = User.query.count()
    active_orders = Order.query.filter(Order.status.in_(['Pending', 'In-Process'])).count()

    # 🔧 Explicit join condition based on Order.service == ServiceType.name
    revenue_q = db.session.query(
        func.sum(ServiceType.price * Order.weight)
    ).select_from(Order).join(
        ServiceType, ServiceType.name == Order.service
    ).filter(Order.status == 'Delivered')

    total_revenue = revenue_q.scalar() or 0

    stats = {
        'total_users': total_users,
        'active_orders': active_orders,
        'total_revenue': round(total_revenue, 2)
    }

    return render_template(
        'admin_dashboard.html',
        users=users,
        orders=orders,
        complaints=complaints,
        coupons=coupons,
        pincodes=pincodes,
        stats=stats
    )

@app.route('/admin/users')
@login_required
@role_required('Admin')
def manage_users():
    """Manage users (list/administer)"""
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/admin/orders')
@login_required
@role_required('Admin')
def manage_orders():
    orders = Order.query.all()
    executives = User.query.filter_by(role='Executive').all()
    return render_template('manage_orders.html', orders=orders, executives=executives)

@app.route('/admin/complaints')
@login_required
@role_required('Admin')
def manage_complaints():
    """manage_complaints"""
    complaints = Complaint.query.all()
    return render_template('manage_complaints.html', complaints=complaints)

@app.route('/admin/coupons', methods=['GET', 'POST'])
@login_required
@role_required('Admin')
def manage_coupons():
    """Manage coupons (create/list)"""
    if request.method == 'POST':
        code = request.form['code']
        discount = float(request.form['discount'])
        expiry = datetime.strptime(request.form['expiry'], '%Y-%m-%d')
        coupon = Coupon(code=code, discount=discount, expiry_date=expiry)
        db.session.add(coupon)
        db.session.commit()
        flash('Coupon added.')
        return redirect(url_for('manage_coupons'))
    coupons = Coupon.query.all()
    return render_template('manage_coupons.html', coupons=coupons)

@app.route('/admin/services', methods=['GET', 'POST'])
@login_required
@role_required('Admin')
def manage_services():
    """Manage laundry service types"""
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description')
        price = float(request.form['price'])
        if not ServiceType.query.filter_by(name=name).first():
            service = ServiceType(name=name, description=description, price=price)
            db.session.add(service)
            db.session.commit()
            flash('Service added.')
        else:
            flash('Service already exists.')
        return redirect(url_for('manage_services'))
    services = ServiceType.query.all()
    return render_template('manage_services.html', services=services)

@app.route('/admin/pincodes', methods=['GET', 'POST'])
@login_required
@role_required('Admin')
def manage_pincodes():
    """Manage serviceable pincodes"""
    if request.method == 'POST':
        pincode = request.form['pincode']
        if not ServiceArea.query.filter_by(pincode=pincode).first():
            new_area = ServiceArea(pincode=pincode)
            db.session.add(new_area)
            db.session.commit()
            flash('Pincode added to service area.')
        else:
            flash('Pincode already exists.')
        return redirect(url_for('manage_pincodes'))
    pincodes = ServiceArea.query.all()
    return render_template('manage_pincodes.html', pincodes=pincodes)

# Order tracking API for real-time status (could be polled by front-end)
@app.route('/api/order_status/<int:order_id>')
@login_required
def order_status(order_id):
    """API endpoint to get order status"""
    order = Order.query.get_or_404(order_id)
    # Authorization check: only customer, executive, or admin
    if current_user.id not in [order.customer_id, order.executive_id] and current_user.role != 'Admin':
        return jsonify({'error': 'Unauthorized'}), 403
    return jsonify({
        'status': order.status,
        'pickup_time': order.pickup_time.isoformat(),
        'delivery_time': order.delivery_time.isoformat() if order.delivery_time else None
    })

# Google Maps integration route (stub for demonstration)
@app.route('/maps/direction')
@login_required
def get_directions():
    """Get directions between two addresses (stub for Google Maps)"""
    origin = request.args.get('origin')
    destination = request.args.get('destination')
    # In real app, call Google Maps API with origin and destination
    return jsonify({'directions': f'Placeholder directions from {origin} to {destination}'})

# Invoice generation (stubbed)
@app.route('/generate_invoice/<int:order_id>')
@login_required
def generate_invoice(order_id):
    """Generate an invoice PDF for an order (stub implementation)"""
    order = Order.query.get_or_404(order_id)
    # Generate PDF (placeholder logic)
    pdf_filename = f"invoice_{order.id}.pdf"
    pdf_path = os.path.join('static', 'invoices', pdf_filename)
    # [PDF generation code would go here]
    # Save Invoice record
    invoice = Invoice(order_id=order.id, pdf_path=pdf_path)
    db.session.add(invoice)
    db.session.commit()
    flash('Invoice generated.')
    return redirect(url_for('admin_dashboard'))

# Language selection (multilingual support)
@app.route('/set_language/<lang_code>')
def set_language(lang_code):
    """Set user language preference"""
    if lang_code in ['en', 'hi', 'te']:
        session['lang'] = lang_code
        flash(f'Language set to {lang_code}.')
    return redirect(request.referrer or url_for('index'))

# Dark mode toggle
@app.route('/toggle_dark_mode')
@login_required
def toggle_dark_mode():
    """Toggle dark mode preference for the user"""
    current_user.dark_mode = not current_user.dark_mode
    db.session.commit()
    mode = "Dark" if current_user.dark_mode else "Light"
    flash(f'{mode} mode enabled.')
    return redirect(request.referrer or url_for('index'))

# PWA manifest and service worker (served from static files)
@app.route('/manifest.json')
def manifest():
    """Serve PWA manifest"""
    return app.send_static_file('manifest.json')

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from io import BytesIO
from flask import send_file

@app.route('/admin/assign_executive/<int:order_id>', methods=['POST'])
@login_required
@role_required('Admin')
def assign_executive(order_id):
    """Assign an executive to an order"""
    order = Order.query.get_or_404(order_id)
    executive_id = int(request.form['executive_id'])
    executive = User.query.filter_by(id=executive_id, role='Executive').first()

    if not executive:
        flash('Invalid executive selected.')
        return redirect(url_for('manage_orders'))

    order.executive_id = executive.id
    order.status = 'Accepted'  # Optional: Update status when assigned
    db.session.commit()
    flash(f'Order {order.id} assigned to {executive.name}')
    return redirect(url_for('manage_orders'))

@app.route('/download_invoice/<int:order_id>')
@login_required
def download_invoice(order_id):
    order = Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404()

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    # Draw logo
    logo_path = 'static/uploads/logo.png'
    try:
        pdf.drawImage(ImageReader(logo_path), 50, height - 100, width=100, preserveAspectRatio=True)
    except:
        pass  # Skip if logo missing

    # Invoice Header
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(200, height - 70, "SpinMate - Laundry Invoice")

    # Order Details
    pdf.setFont("Helvetica", 12)
    y = height - 130
    details = [
        f"Order ID: {order.id}",
        f"Service: {order.service}",
        f"Pickup Time: {order.pickup_time.strftime('%Y-%m-%d %H:%M')}",
        f"Load Type: {order.load_type or 'N/A'}",
        f"Weight: {order.weight or 'N/A'} kg",
        f"Status: {order.status}",
        f"Amount: ₹{order.total_price or 'N/A'}",
        f"Date Issued: {datetime.now().strftime('%Y-%m-%d')}",
    ]
    for line in details:
        pdf.drawString(50, y, line)
        y -= 20

    # QR Code with basic info
    qr_data = f"SpinMate Invoice\nOrder ID: {order.id}\nAmount: ₹{order.total_price or 'N/A'}"
    qr_img = qrcode.make(qr_data)
    qr_buffer = BytesIO()
    qr_img.save(qr_buffer)
    qr_buffer.seek(0)
    pdf.drawImage(ImageReader(qr_buffer), width - 150, y - 50, width=100, height=100)

    pdf.drawString(50, y - 80, "Thank you for choosing SpinMate!")
    pdf.showPage()
    pdf.save()

    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"invoice_{order.id}.pdf", mimetype='application/pdf')


@app.route('/service-worker.js')
def service_worker():
    """Serve PWA service worker"""
    return app.send_static_file('service-worker.js')

# Initialize database (create tables) on first request
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)