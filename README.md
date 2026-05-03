# SecureShield 🔐
A Role-Based Access Control (RBAC) API built with Python Flask and JWT.

## Team Members
| Name | Student ID |
|------|------------|
| Barkhad Mohamed | 210208908 |
| Sabrin Ali Isack | 210208994 |
| Sadik Hassan Ismail | 220208742 |

## What This Project Does
- User registration with bcrypt password hashing
- JWT token authentication
- Role-based access control (Admin vs User)
- Token blacklisting on logout
- Security logging for unauthorized attempts

## How to Run
1. Install requirements:
pip install flask pyjwt flask-bcrypt

2. Run the app:
python app.py

3. Server runs at: http://localhost:5000

## API Endpoints
| Method | Endpoint | Access |
|--------|----------|--------|
| POST | /register | Public |
| POST | /login | Public |
| GET | /profile | User + Admin |
| DELETE | /user/<id> | Admin only |
| POST | /logout | User + Admin |

## Libraries Used
- Flask
- PyJWT
- Flask-Bcrypt
