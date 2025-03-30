# Flask User Authentication and Management System

## 📖 Project Introduction
This is a user authentication and management system developed based on the Flask framework, suitable for Python web development beginners to learn and practice. The project includes a complete user registration/login process, a verification code mechanism, request frequency limitation, an administrator backend, etc., and implements multiple web security protection measures. The front - end interface is beautified with CSS to provide a good interactive experience.

## 🚀 Feature Highlights
### Core Function Modules
• **User System**
  • Login/registration process with verification code
  • Password stored with MD5 encryption
  • Session management (2 - hour validity period)
  • Password strength verification (uppercase and lowercase letters + numbers + special characters)

• **Security Protection**
  • CSRF token protection
  • Request frequency limitation (15 requests per minute)
  • Verification code to prevent brute - force cracking
  • Sensitive operation log recording

• **Management Backend**
  • Independent administrator login
  • User data query
  • Operation log auditing
  • Administrator - exclusive interface

### Enhanced Features
• Responsive front - end design
• Visualized log system (separated by role)
• Session security control
• Database error rollback mechanism

## ⚙️ Environment Dependencies
• Python 3.7+
• Flask 2.0+
• Required Components:
  ```bash
  Flask - WTF
  Flask - Limiter
  PyMySQL
  captcha
  hashlib
  ```

## 🛠️ Installation and Configuration

### 1. Environment Preparation
```bash
git clone https://github.com/name - swallow/flask - test.git
cd flask - auth - system
pip install -r requirements.txt
```

### 2. Database Configuration
1. Create a MySQL database:
```sql
CREATE DATABASE database_name;
```

2. Import the table structure (refer to `database_schema.sql`)

### 3. Key Configuration Items
```python
# Line 34 of main.py
app.secret_key = 'Set a high - strength secret key'  # It is recommended to use os.urandom(24)

# Line 35 of main.py
db = pymysql.connect(
    host="localhost",
    user='Your database username',
    password='Your database password',
    database='database_name'
)
```

## 🖥️ Usage Instructions

### Start the Application
```bash
python main.py
```

### User - side Access
• Home page: `http://localhost:5000`
• Login page: `http://localhost:5000/login`
• Registration page: Switch through the login page

### Management Backend
• Administrator login: `http://localhost:5000/adminlogin`
• User management: `http://localhost:5000/admin`

### Function Demonstration
1. When registering a new user, the password complexity requirements must be met.
2. If the number of failed logins exceeds 15 times per minute, the limit will be triggered.
3. Click the verification code image to refresh the verification code.
4. The administrator backend supports querying users by ID.

## 📂 Project Structure
```
flask - auth - system/
├── templates/            # Front - end templates
│   ├── admin.html        # Management backend
│   ├── adminlogin.html   # Administrator login
│   ├── index.html        # User home page  
│   └── login.html        # User login/registration
├── log/                  # Log directory (automatically created)
├── main.py               # Main program
└── requirements.txt      # Dependency list
```

## 🔒 Security Measures
1. **CSRF Protection**: All forms contain CSRF tokens.
2. **Password Security**: MD5 hashing storage + complexity verification.
3. **Request Limitation**:
   • General interfaces: 20 requests per minute
   • Login interface: 15 requests per minute
4. **Session Security**:
   • Independent administrator sessions
   • Automatic cleaning of verification code sessions
5. **Input Verification**:
   • SQL parameterized queries
   • User input filtering
