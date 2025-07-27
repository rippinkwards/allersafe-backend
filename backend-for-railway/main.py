from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict, Any
import pymongo
import os
from datetime import datetime, timedelta
import jwt
import bcrypt
import uuid
import requests
from bs4 import BeautifulSoup
import qrcode
import io
import base64
import re
from urllib.parse import urljoin, urlparse
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Production/Test Mode Configuration
APP_MODE = os.environ.get("APP_MODE", "test")
IS_PRODUCTION = APP_MODE == "production"

print(f"🚀 AllerSafe starting in {APP_MODE.upper()} mode")

# Third-party integrations
from emergentintegrations.payments.stripe.checkout import StripeCheckout, CheckoutSessionResponse, CheckoutStatusResponse, CheckoutSessionRequest
from twilio.rest import Client
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content

# Initialize FastAPI
app = FastAPI(title="AllerSafe API", version="2.0.0")

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()
JWT_SECRET = os.environ.get("JWT_SECRET", "your-secret-key-change-in-production")
if not IS_PRODUCTION:
    JWT_SECRET = "development-secret-key-not-secure"
JWT_ALGORITHM = "HS256"

# MongoDB Connection
MONGO_URL = os.environ.get("MONGO_URL", "mongodb://localhost:27017")
client = pymongo.MongoClient(MONGO_URL)
db = client.allersafe_db

# Collections
users_collection = db.users
restaurants_collection = db.restaurants
families_collection = db.families
menu_items_collection = db.menu_items
allergens_collection = db.allergens
payment_transactions_collection = db.payment_transactions
sms_logs_collection = db.sms_logs
email_logs_collection = db.email_logs
subscriptions_collection = db.subscriptions
consumer_scans_collection = db.consumer_scans
restaurant_requests_collection = db.restaurant_requests
saved_menus_collection = db.saved_menus

# Third-party service configuration
STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY")
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.environ.get("TWILIO_PHONE_NUMBER")
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "noreply@allersafe.com")

# Initialize third-party clients
twilio_client = None
if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN:
    twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

sendgrid_client = None
if SENDGRID_API_KEY:
    sendgrid_client = SendGridAPIClient(api_key=SENDGRID_API_KEY)

# Subscription packages
SUBSCRIPTION_PACKAGES = {
    "restaurant_monthly": {"amount": 99.0, "setup_fee": 299.0, "interval": "month", "name": "Restaurant Monthly"},
    "family_monthly": {"amount": 14.99, "interval": "month", "name": "Family Monthly"},
    "family_annual": {"amount": 149.0, "interval": "year", "name": "Family Annual"}
}

# Initialize allergens data
ALLERGENS_DATA = [
    {"id": "milk", "name": "Milk", "synonyms": ["milk", "dairy", "cream", "butter", "cheese", "casein", "whey", "lactose", "yogurt", "ghee"]},
    {"id": "egg", "name": "Egg", "synonyms": ["egg", "eggs", "albumen", "ovalbumin", "mayonnaise", "mayo", "meringue"]},
    {"id": "wheat", "name": "Wheat", "synonyms": ["wheat", "flour", "gluten", "bread", "pasta", "noodles", "panko", "breadcrumb", "seitan"]},
    {"id": "soy", "name": "Soy", "synonyms": ["soy", "soya", "tofu", "tempeh", "miso", "edamame", "soy sauce", "tamari"]},
    {"id": "peanuts", "name": "Peanuts", "synonyms": ["peanut", "peanuts", "groundnut", "arachis", "peanut butter", "peanut oil"]},
    {"id": "tree_nuts", "name": "Tree Nuts", "synonyms": ["almond", "walnut", "cashew", "pecan", "hazelnut", "pistachio", "macadamia", "brazil nut", "pine nut"]},
    {"id": "sesame", "name": "Sesame", "synonyms": ["sesame", "tahini", "sesame oil", "sesame seed", "sesame paste"]},
    {"id": "shellfish", "name": "Shellfish", "synonyms": ["shrimp", "crab", "lobster", "crawfish", "crayfish", "prawns", "scallop", "oyster", "mussel", "clam"]},
    {"id": "fish", "name": "Fish", "synonyms": ["salmon", "tuna", "cod", "bass", "trout", "anchovy", "sardine", "mackerel", "fish sauce", "worcestershire"]}
]

# Initialize allergens in database
def init_allergens():
    for allergen in ALLERGENS_DATA:
        allergens_collection.update_one(
            {"id": allergen["id"]},
            {"$set": allergen},
            upsert=True
        )

init_allergens()

# Create demo accounts
def init_demo_accounts():
    demo_users = [
        {"email": "restaurant@demo.com", "password": "demo123", "name": "Demo Restaurant", "role": "restaurant"},
        {"email": "family@demo.com", "password": "demo123", "name": "Demo Family", "role": "family"},
        {"email": "admin@demo.com", "password": "demo123", "name": "Demo Admin", "role": "admin"},
        {"email": "consumer@demo.com", "password": "demo123", "name": "Free Consumer", "role": "family"},
        {"email": "premium@demo.com", "password": "demo123", "name": "Premium Consumer", "role": "family"}
    ]
    
    for user_data in demo_users:
        if not users_collection.find_one({"email": user_data["email"]}):
            user_id = str(uuid.uuid4())
            hashed_password = bcrypt.hashpw(user_data["password"].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # Set subscription status
            subscription_status = "trial"
            if user_data["email"] == "premium@demo.com":
                subscription_status = "active"
            
            user_doc = {
                "id": user_id,
                "email": user_data["email"],
                "password": hashed_password,
                "name": user_data["name"],
                "role": user_data["role"],
                "created_at": datetime.utcnow(),
                "is_active": True,
                "subscription_status": subscription_status
            }
            users_collection.insert_one(user_doc)
            
            # Create premium user subscription record
            if user_data["email"] == "premium@demo.com":
                subscription_record = {
                    "id": str(uuid.uuid4()),
                    "user_id": user_id,
                    "package_id": "family_annual",
                    "package_name": "Family Annual",
                    "amount": 149.0,
                    "interval": "year",
                    "status": "active",
                    "created_at": datetime.utcnow(),
                    "next_billing_date": datetime.utcnow() + timedelta(days=365)
                }
                subscriptions_collection.insert_one(subscription_record)

# Create demo family profiles for consumer users
def init_demo_families():
    consumer_family_data = [
        {
            "email": "consumer@demo.com",
            "family_name": "Free Consumer Family",
            "members": [
                {
                    "name": "Alex Smith",
                    "allergies": ["peanuts", "milk"]
                },
                {
                    "name": "Jordan Smith",
                    "allergies": ["wheat", "shellfish"]
                }
            ]
        },
        {
            "email": "premium@demo.com",
            "family_name": "Premium Consumer Family",
            "members": [
                {
                    "name": "Taylor Johnson",
                    "allergies": ["tree_nuts", "soy", "eggs"]
                },
                {
                    "name": "Casey Johnson",
                    "allergies": ["fish", "sesame"]
                },
                {
                    "name": "Riley Johnson",
                    "allergies": ["milk", "wheat"]
                }
            ]
        }
    ]
    
    for family_data in consumer_family_data:
        # Find user
        user = users_collection.find_one({"email": family_data["email"]})
        if user and not families_collection.find_one({"user_id": user["id"]}):
            family_id = str(uuid.uuid4())
            
            # Create family members
            members = []
            for member_data in family_data["members"]:
                members.append({
                    "id": str(uuid.uuid4()),
                    "name": member_data["name"],
                    "allergies": member_data["allergies"]
                })
            
            family_doc = {
                "id": family_id,
                "user_id": user["id"],
                "family_name": family_data["family_name"],
                "members": members,
                "created_at": datetime.utcnow()
            }
            families_collection.insert_one(family_doc)

init_demo_accounts()
init_demo_families()

# Pydantic Models
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str
    role: str  # 'restaurant', 'family', 'admin'

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class RestaurantCreate(BaseModel):
    name: str
    address: str
    phone: Optional[str] = None
    description: Optional[str] = None

class FamilyMemberCreate(BaseModel):
    name: str
    allergies: List[str]  # List of allergen IDs

class FamilyCreate(BaseModel):
    family_name: str
    members: List[FamilyMemberCreate]

class MenuItemCreate(BaseModel):
    name: str
    description: Optional[str] = None
    ingredients: List[str]
    price: Optional[float] = None
    category: Optional[str] = None

class MenuScrapeRequest(BaseModel):
    url: str

class MenuItemUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    ingredients: Optional[List[str]] = None
    price: Optional[float] = None
    category: Optional[str] = None
    is_published: Optional[bool] = None

class EmergencyContactCreate(BaseModel):
    name: str
    phone_number: str

class EmergencyAlertRequest(BaseModel):
    location_lat: Optional[float] = None
    location_lng: Optional[float] = None
    location_address: Optional[str] = "Unknown location"

class SubscriptionRequest(BaseModel):
    package_id: str  # 'restaurant_monthly', 'family_monthly', 'family_annual'
    origin_url: str

class PaymentStatusRequest(BaseModel):
    session_id: str

class ConsumerScanRequest(BaseModel):
    url: str
    restaurant_name: Optional[str] = None

class RestaurantSupportRequest(BaseModel):
    restaurant_name: str
    restaurant_url: str
    reason: Optional[str] = "Consumer requested restaurant partnership"

class SaveMenuRequest(BaseModel):
    scan_id: str
    menu_name: str
    notes: Optional[str] = None

# Utility Functions for Phase 2
def send_welcome_email(user_email: str, user_name: str, user_role: str, dashboard_url: str):
    """Send welcome email using SendGrid"""
    if not sendgrid_client:
        return False
    
    try:
        # Create email content based on user role
        if user_role == "restaurant":
            subject = "Welcome to AllerSafe - Restaurant Dashboard Ready!"
            content = f"""
            <html>
                <body>
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #2563eb;">🏪 Welcome to AllerSafe, {user_name}!</h2>
                        
                        <p>Thank you for joining AllerSafe, the leading platform for allergy-safe dining.</p>
                        
                        <h3>Quick Start Guide:</h3>
                        <ol>
                            <li><strong>Access your dashboard:</strong> <a href="{dashboard_url}" style="color: #2563eb;">Click here</a></li>
                            <li><strong>Add your menu:</strong> Use our URL scraper or add items manually</li>
                            <li><strong>Generate QR codes:</strong> Print and place at your tables</li>
                            <li><strong>Help families dine safely:</strong> Your allergen data helps families make informed choices</li>
                        </ol>
                        
                        <div style="background-color: #f3f4f6; padding: 15px; border-radius: 8px; margin: 20px 0;">
                            <h4>💡 Pro Tips:</h4>
                            <ul>
                                <li>Complete your menu setup to start serving allergy-conscious customers</li>
                                <li>Our system automatically detects 9 major allergens</li>
                                <li>QR codes link directly to your live menu</li>
                            </ul>
                        </div>
                        
                        <p><strong>Need help?</strong> Contact support at <a href="mailto:support@allersafe.com">support@allersafe.com</a></p>
                        
                        <p style="color: #6b7280; font-size: 14px;">
                            Best regards,<br>
                            The AllerSafe Team
                        </p>
                    </div>
                </body>
            </html>
            """
        
        elif user_role == "family":
            subject = "Welcome to AllerSafe - Keep Your Family Safe While Dining!"
            content = f"""
            <html>
                <body>
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #7c3aed;">👨‍👩‍👧‍👦 Welcome to AllerSafe, {user_name}!</h2>
                        
                        <p>Thank you for choosing AllerSafe to protect your family while dining out.</p>
                        
                        <h3>Getting Started:</h3>
                        <ol>
                            <li><strong>Access your dashboard:</strong> <a href="{dashboard_url}" style="color: #7c3aed;">Click here</a></li>
                            <li><strong>Set up family profiles:</strong> Add each family member's allergies</li>
                            <li><strong>Scan QR codes:</strong> At restaurants to see safe menu items</li>
                            <li><strong>Set emergency contacts:</strong> For quick alerts if needed</li>
                        </ol>
                        
                        <div style="background-color: #fef3c7; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #f59e0b;">
                            <h4>🚨 Emergency Features:</h4>
                            <p>Set up emergency contacts in your dashboard. In case of an allergic reaction, tap the emergency button to instantly send your location and allergy information to your emergency contact.</p>
                        </div>
                        
                        <p><strong>Questions?</strong> We're here to help at <a href="mailto:support@allersafe.com">support@allersafe.com</a></p>
                        
                        <p style="color: #6b7280; font-size: 14px;">
                            Stay safe and enjoy dining out!<br>
                            The AllerSafe Team
                        </p>
                    </div>
                </body>
            </html>
            """
        
        else:  # admin
            subject = "Welcome to AllerSafe - Admin Access Granted"
            content = f"""
            <html>
                <body>
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #dc2626;">⚙️ Welcome to AllerSafe Admin, {user_name}!</h2>
                        
                        <p>Your administrator account has been created successfully.</p>
                        
                        <p><strong>Admin Dashboard:</strong> <a href="{dashboard_url}" style="color: #dc2626;">Access Here</a></p>
                        
                        <h3>Admin Capabilities:</h3>
                        <ul>
                            <li>Monitor all restaurant and family accounts</li>
                            <li>View subscription statuses and billing</li>
                            <li>Review SMS and email delivery logs</li>
                            <li>System health monitoring</li>
                        </ul>
                        
                        <p><strong>Support:</strong> <a href="mailto:admin@allersafe.com">admin@allersafe.com</a></p>
                        
                        <p style="color: #6b7280; font-size: 14px;">
                            AllerSafe Platform Team
                        </p>
                    </div>
                </body>
            </html>
            """
        
        # Create and send email
        message = Mail(
            from_email=Email(SENDER_EMAIL),
            to_emails=To(user_email),
            subject=subject,
            html_content=Content("text/html", content)
        )
        
        response = sendgrid_client.send(message)
        
        # Log email attempt
        email_log = {
            "id": str(uuid.uuid4()),
            "to_email": user_email,
            "subject": subject,
            "email_type": "welcome",
            "status": "sent" if response.status_code == 202 else "failed",
            "status_code": response.status_code,
            "created_at": datetime.utcnow()
        }
        email_logs_collection.insert_one(email_log)
        
        return response.status_code == 202
        
    except Exception as e:
        # Log failed email attempt
        email_log = {
            "id": str(uuid.uuid4()),
            "to_email": user_email,
            "subject": subject if 'subject' in locals() else "Welcome Email",
            "email_type": "welcome",
            "status": "failed",
            "error": str(e),
            "created_at": datetime.utcnow()
        }
        email_logs_collection.insert_one(email_log)
        return False

def send_emergency_sms(family_member_name: str, allergies: List[str], location_info: str, emergency_contact_phone: str, emergency_contact_name: str):
    """Send emergency SMS alert using Twilio"""
    if not twilio_client:
        return False
    
    try:
        # Compose emergency message
        allergies_text = ", ".join(allergies) if allergies else "Unknown allergies"
        message_body = f"""🚨 EMERGENCY ALERT 🚨

{family_member_name} may be experiencing an allergic reaction and needs help immediately.

ALLERGIES: {allergies_text}
LOCATION: {location_info}

This is an automated emergency alert from AllerSafe. Please respond immediately."""
        
        # Send SMS
        message = twilio_client.messages.create(
            body=message_body,
            from_=TWILIO_PHONE_NUMBER,
            to=emergency_contact_phone
        )
        
        # Log SMS attempt
        sms_log = {
            "id": str(uuid.uuid4()),
            "to_phone": emergency_contact_phone,
            "to_name": emergency_contact_name,
            "message_body": message_body,
            "sms_type": "emergency",
            "status": "sent",
            "twilio_sid": message.sid,
            "family_member": family_member_name,
            "allergies": allergies,
            "location": location_info,
            "created_at": datetime.utcnow()
        }
        sms_logs_collection.insert_one(sms_log)
        
        return True
        
    except Exception as e:
        # Log failed SMS attempt
        sms_log = {
            "id": str(uuid.uuid4()),
            "to_phone": emergency_contact_phone,
            "to_name": emergency_contact_name,
            "sms_type": "emergency",
            "status": "failed",
            "error": str(e),
            "family_member": family_member_name,
            "allergies": allergies,
            "location": location_info,
            "created_at": datetime.utcnow()
        }
        sms_logs_collection.insert_one(sms_log)
        return False

def create_subscription_record(user_id: str, package_id: str, session_id: str, amount: float):
    """Create subscription record"""
    subscription = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "package_id": package_id,
        "package_name": SUBSCRIPTION_PACKAGES[package_id]["name"],
        "amount": amount,
        "interval": SUBSCRIPTION_PACKAGES[package_id]["interval"],
        "session_id": session_id,
        "status": "pending",
        "created_at": datetime.utcnow(),
        "next_billing_date": datetime.utcnow() + timedelta(days=30 if SUBSCRIPTION_PACKAGES[package_id]["interval"] == "month" else 365)
    }
    subscriptions_collection.insert_one(subscription)
    return subscription

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        user = users_collection.find_one({"id": user_id})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

def detect_allergens(ingredients: List[str]) -> List[str]:
    """Detect allergens in ingredients list"""
    detected_allergens = []
    allergens = list(allergens_collection.find())
    
    # Join all ingredients into one text for easier matching
    ingredients_text = " ".join(ingredients).lower()
    
    for allergen in allergens:
        for synonym in allergen["synonyms"]:
            if synonym.lower() in ingredients_text:
                if allergen["id"] not in detected_allergens:
                    detected_allergens.append(allergen["id"])
                break
    
    return detected_allergens

def scrape_menu_from_url(url: str) -> List[Dict[str, Any]]:
    """Scrape menu items from URL"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        menu_items = []
        
        # Try different common menu item selectors
        selectors = [
            '.menu-item',
            '.dish',
            '.food-item', 
            'li:has(.price)',
            'tr:has(.price)',
            '.item'
        ]
        
        items_found = []
        for selector in selectors:
            items = soup.select(selector)
            if len(items) > len(items_found):
                items_found = items
        
        # If no structured items found, try to find text patterns
        if not items_found:
            # Look for price patterns to identify menu items
            price_pattern = r'\$\d+(?:\.\d{2})?'
            text_content = soup.get_text()
            lines = text_content.split('\n')
            
            for line in lines:
                if re.search(price_pattern, line) and len(line.strip()) > 10:
                    # Try to extract name and description
                    parts = line.strip().split('$')
                    if len(parts) >= 2:
                        name_desc = parts[0].strip()
                        price_text = '$' + parts[1].split()[0] if parts[1].split() else ''
                        
                        # Split name and description
                        if '...' in name_desc:
                            name, desc = name_desc.split('...', 1)
                        elif ' - ' in name_desc:
                            name, desc = name_desc.split(' - ', 1)
                        else:
                            name = name_desc
                            desc = ""
                        
                        menu_items.append({
                            "name": name.strip(),
                            "description": desc.strip(),
                            "ingredients": [desc.strip()] if desc.strip() else [],
                            "price": price_text.replace('$', '') if price_text else None
                        })
        
        # Process structured items
        for item in items_found[:20]:  # Limit to 20 items
            name_elem = item.find(['h1', 'h2', 'h3', 'h4', '.name', '.title', 'strong'])
            desc_elem = item.find(['.description', '.desc', 'p', '.ingredients'])
            price_elem = item.find(['.price', '.cost'])
            
            name = name_elem.get_text(strip=True) if name_elem else ""
            description = desc_elem.get_text(strip=True) if desc_elem else ""
            price_text = price_elem.get_text(strip=True) if price_elem else ""
            
            if name and len(name) > 2:
                # Extract ingredients from description
                ingredients = [description] if description else []
                
                menu_items.append({
                    "name": name,
                    "description": description,
                    "ingredients": ingredients,
                    "price": price_text.replace('$', '').replace(',', '') if price_text else None
                })
        
        return menu_items[:15]  # Return max 15 items
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to scrape menu: {str(e)}")

def scrape_consumer_menu_from_url(url: str, restaurant_name: str = None) -> Dict[str, Any]:
    """Scrape menu items from any restaurant URL for consumer use"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Extract restaurant name if not provided
        if not restaurant_name:
            title_elem = soup.find('title')
            h1_elem = soup.find('h1')
            restaurant_name = (
                title_elem.get_text(strip=True) if title_elem else 
                h1_elem.get_text(strip=True) if h1_elem else 
                urlparse(url).netloc
            )
        
        menu_items = []
        
        # Enhanced menu item detection
        selectors = [
            '.menu-item', '.dish', '.food-item', '.menu-entry',
            'li:has(.price)', 'tr:has(.price)', '.item',
            '[class*="menu"]', '[class*="dish"]', '[class*="food"]'
        ]
        
        items_found = []
        for selector in selectors:
            try:
                items = soup.select(selector)
                if len(items) > len(items_found) and len(items) < 100:  # Avoid selecting too many elements
                    items_found = items
            except:
                continue
        
        # Enhanced text-based detection
        if not items_found or len(items_found) < 3:
            # Look for common menu patterns
            text_content = soup.get_text()
            lines = [line.strip() for line in text_content.split('\n') if line.strip()]
            
            price_pattern = r'\$\d+(?:\.\d{2})?'
            menu_lines = []
            
            for i, line in enumerate(lines):
                if re.search(price_pattern, line) and len(line) > 10 and len(line) < 200:
                    # Get context around the price line
                    context_lines = []
                    for j in range(max(0, i-2), min(len(lines), i+3)):
                        if j != i and len(lines[j]) > 5:
                            context_lines.append(lines[j])
                    
                    # Parse name, description, and price
                    parts = re.split(r'[\$]\d+(?:\.\d{2})?', line)
                    if len(parts) >= 1:
                        name_desc = parts[0].strip()
                        price_match = re.search(price_pattern, line)
                        price = price_match.group() if price_match else None
                        
                        # Try to separate name and description
                        if '...' in name_desc:
                            name, desc = name_desc.split('...', 1)
                        elif ' - ' in name_desc:
                            name, desc = name_desc.split(' - ', 1)
                        elif '. ' in name_desc and len(name_desc.split('. ')) == 2:
                            name, desc = name_desc.split('. ', 1)
                        else:
                            name = name_desc
                            desc = " ".join(context_lines[:2])  # Use context as description
                        
                        if name and len(name.strip()) > 2:
                            menu_items.append({
                                "name": name.strip(),
                                "description": desc.strip(),
                                "ingredients": [desc.strip()] if desc.strip() else [],
                                "price": price.replace('$', '') if price else None,
                                "source": "text_extraction"
                            })
        
        # Process structured items
        for item in items_found[:25]:  # Limit to 25 items
            try:
                # More flexible element detection
                name_elem = item.find(['h1', 'h2', 'h3', 'h4', 'h5', '.name', '.title', 'strong', 'b']) or item
                desc_elem = item.find(['.description', '.desc', 'p', '.ingredients', '.details'])
                price_elem = item.find(['.price', '.cost']) or item
                
                # Extract text more carefully
                name = ""
                if name_elem:
                    name = name_elem.get_text(strip=True)
                    # If name is too long, try to find a more specific element
                    if len(name) > 100:
                        specific_name = name_elem.find(['strong', 'b', 'span'])
                        if specific_name:
                            name = specific_name.get_text(strip=True)
                
                description = desc_elem.get_text(strip=True) if desc_elem else ""
                
                # Extract price more carefully
                price_text = ""
                full_text = item.get_text()
                price_match = re.search(r'\$(\d+(?:\.\d{2})?)', full_text)
                if price_match:
                    price_text = price_match.group(1)
                
                # Clean up name (remove price if it got included)
                if price_text and price_text in name:
                    name = re.sub(r'\$?\d+(?:\.\d{2})?', '', name).strip()
                
                # Filter out non-food items and duplicates
                if (name and len(name) > 2 and len(name) < 100 and
                    not any(skip_word in name.lower() for skip_word in 
                           ['wine', 'beer', 'cocktail', 'beverage', 'drink', 'soda', 'water', 'juice']) and
                    name not in [item['name'] for item in menu_items]):
                    
                    # Extract potential ingredients from description
                    ingredients = []
                    if description:
                        # Common ingredient separators
                        desc_lower = description.lower()
                        if any(word in desc_lower for word in ['with', 'contains', 'made with', 'includes']):
                            ingredients = [description]
                        elif ',' in description:
                            # Try to extract comma-separated ingredients
                            potential_ingredients = [ing.strip() for ing in description.split(',')]
                            ingredients = [ing for ing in potential_ingredients if len(ing) > 2 and len(ing) < 50]
                        else:
                            ingredients = [description]
                    
                    menu_items.append({
                        "name": name,
                        "description": description,
                        "ingredients": ingredients,
                        "price": price_text if price_text else None,
                        "source": "structured_extraction"
                    })
                    
            except Exception as e:
                continue
        
        # Remove duplicates and limit results
        seen_names = set()
        unique_items = []
        for item in menu_items:
            if item['name'].lower() not in seen_names and len(unique_items) < 20:
                seen_names.add(item['name'].lower())
                unique_items.append(item)
        
        return {
            "restaurant_name": restaurant_name,
            "url": url,
            "menu_items": unique_items,
            "scraped_at": datetime.utcnow(),
            "total_items_found": len(unique_items)
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to scrape menu: {str(e)}")

def analyze_consumer_menu_safety(menu_items: List[Dict], family_allergies: List[str], is_premium: bool = False) -> Dict[str, Any]:
    """Analyze menu safety for consumer-scanned menus"""
    safe_items = []
    unsafe_items = []
    uncertain_items = []
    
    for item in menu_items:
        # Detect allergens in ingredients
        detected_allergens = detect_allergens(item.get("ingredients", []))
        
        # Check against family allergies
        matching_allergens = list(set(family_allergies) & set(detected_allergens))
        
        # Enhanced analysis for premium users
        confidence_score = 0.7 if is_premium else 0.5
        
        # Calculate confidence based on ingredient detail
        ingredient_detail = len(" ".join(item.get("ingredients", [])))
        if ingredient_detail > 50:
            confidence_score += 0.2
        elif ingredient_detail < 10:
            confidence_score -= 0.2
        
        item_analysis = {
            **item,
            "detected_allergens": detected_allergens,
            "matching_allergens": matching_allergens,
            "confidence_score": confidence_score,
            "analysis_type": "premium" if is_premium else "basic"
        }
        
        if matching_allergens:
            unsafe_items.append(item_analysis)
        elif not detected_allergens and ingredient_detail < 10:
            # Limited ingredient info - uncertain
            uncertain_items.append(item_analysis)
        else:
            safe_items.append(item_analysis)
    
    return {
        "safe_items": safe_items,
        "unsafe_items": unsafe_items,
        "uncertain_items": uncertain_items,
        "total_items": len(menu_items),
        "safe_count": len(safe_items),
        "unsafe_count": len(unsafe_items),
        "uncertain_count": len(uncertain_items),
        "confidence_level": "premium" if is_premium else "basic",
        "disclaimer": "This analysis is based on publicly available menu data and has not been verified by the restaurant. Always confirm with restaurant staff before ordering."
    }

def generate_qr_code(data: str) -> str:
    """Generate QR code and return as base64 string"""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    return base64.b64encode(buffer.getvalue()).decode()

# API Routes

@app.post("/api/auth/register")
async def register(user: UserCreate, background_tasks: BackgroundTasks):
    # Check if user exists
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user_id = str(uuid.uuid4())
    hashed_password = hash_password(user.password)
    
    user_doc = {
        "id": user_id,
        "email": user.email,
        "password": hashed_password,
        "name": user.name,
        "role": user.role,
        "created_at": datetime.utcnow(),
        "is_active": True,
        "subscription_status": "trial"  # New field for subscription tracking
    }
    
    users_collection.insert_one(user_doc)
    
    # Create access token
    access_token = create_access_token(data={"sub": user_id})
    
    # Send welcome email in background
    base_url = os.environ.get("FRONTEND_URL", "http://localhost:3000")
    dashboard_url = f"{base_url}/dashboard"
    
    background_tasks.add_task(
        send_welcome_email, 
        user.email, 
        user.name, 
        user.role, 
        dashboard_url
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user_id,
            "email": user.email,
            "name": user.name,
            "role": user.role,
            "subscription_status": "trial"
        }
    }

@app.post("/api/auth/login")
async def login(user: UserLogin):
    # Find user
    db_user = users_collection.find_one({"email": user.email})
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Create access token
    access_token = create_access_token(data={"sub": db_user["id"]})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": db_user["id"],
            "email": db_user["email"],
            "name": db_user["name"],
            "role": db_user["role"]
        }
    }

@app.get("/api/auth/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    # Get subscription status
    subscription = subscriptions_collection.find_one(
        {"user_id": current_user["id"], "status": "active"}, 
        sort=[("created_at", -1)]
    )
    
    subscription_info = None
    if subscription:
        subscription_info = {
            "package_name": subscription.get("package_name"),
            "status": subscription.get("status"),
            "next_billing_date": subscription.get("next_billing_date")
        }
    
    return {
        "id": current_user["id"],
        "email": current_user["email"],
        "name": current_user["name"],
        "role": current_user["role"],
        "subscription_status": current_user.get("subscription_status", "trial"),
        "subscription": subscription_info
    }

# Stripe Payment Routes
@app.post("/api/payments/create-checkout")
async def create_checkout_session(request: SubscriptionRequest, current_user: dict = Depends(get_current_user)):
    """Create Stripe checkout session for subscription"""
    
    # Validate package
    if request.package_id not in SUBSCRIPTION_PACKAGES:
        raise HTTPException(status_code=400, detail="Invalid subscription package")
    
    package = SUBSCRIPTION_PACKAGES[request.package_id]
    
    # Validate user role matches package
    if request.package_id.startswith("restaurant") and current_user["role"] != "restaurant":
        raise HTTPException(status_code=400, detail="Restaurant packages only for restaurant users")
    elif request.package_id.startswith("family") and current_user["role"] != "family":
        raise HTTPException(status_code=400, detail="Family packages only for family users")
    
    # Calculate total amount (include setup fee for restaurants)
    total_amount = package["amount"]
    if request.package_id == "restaurant_monthly" and package.get("setup_fee"):
        total_amount += package["setup_fee"]
    
    try:
        # Initialize Stripe checkout
        webhook_url = f"{request.origin_url.rstrip('/')}/api/webhook/stripe"
        stripe_checkout = StripeCheckout(api_key=STRIPE_API_KEY, webhook_url=webhook_url)
        
        # Create success and cancel URLs
        success_url = f"{request.origin_url}/dashboard?payment=success&session_id={{CHECKOUT_SESSION_ID}}"
        cancel_url = f"{request.origin_url}/dashboard?payment=cancelled"
        
        # Create checkout session
        checkout_request = CheckoutSessionRequest(
            amount=total_amount,
            currency="usd",
            success_url=success_url,
            cancel_url=cancel_url,
            metadata={
                "user_id": current_user["id"],
                "package_id": request.package_id,
                "user_email": current_user["email"],
                "user_role": current_user["role"]
            }
        )
        
        session = await stripe_checkout.create_checkout_session(checkout_request)
        
        # Create payment transaction record
        transaction = {
            "id": str(uuid.uuid4()),
            "session_id": session.session_id,
            "user_id": current_user["id"],
            "package_id": request.package_id,
            "amount": total_amount,
            "currency": "usd",
            "status": "pending",
            "payment_status": "pending",
            "metadata": checkout_request.metadata,
            "created_at": datetime.utcnow()
        }
        payment_transactions_collection.insert_one(transaction)
        
        return {
            "checkout_url": session.url,
            "session_id": session.session_id,
            "amount": total_amount,
            "package_name": package["name"]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create checkout session: {str(e)}")

@app.get("/api/payments/status/{session_id}")
async def get_payment_status(session_id: str, current_user: dict = Depends(get_current_user)):
    """Get payment status for a checkout session"""
    
    # Find transaction
    transaction = payment_transactions_collection.find_one({"session_id": session_id, "user_id": current_user["id"]})
    if not transaction:
        raise HTTPException(status_code=404, detail="Payment session not found")
    
    try:
        # Initialize Stripe checkout  
        stripe_checkout = StripeCheckout(api_key=STRIPE_API_KEY, webhook_url="")
        
        # Get checkout status from Stripe
        status_response = await stripe_checkout.get_checkout_status(session_id)
        
        # Update transaction status if payment completed
        if status_response.payment_status == "paid" and transaction["payment_status"] != "paid":
            # Update transaction
            payment_transactions_collection.update_one(
                {"session_id": session_id},
                {"$set": {
                    "status": "completed",
                    "payment_status": "paid",
                    "completed_at": datetime.utcnow()
                }}
            )
            
            # Create/update subscription
            package_id = transaction["package_id"]
            subscription = create_subscription_record(
                current_user["id"], 
                package_id, 
                session_id, 
                transaction["amount"]
            )
            
            # Update user subscription status
            users_collection.update_one(
                {"id": current_user["id"]},
                {"$set": {"subscription_status": "active"}}
            )
        
        return {
            "session_id": session_id,
            "status": status_response.status,
            "payment_status": status_response.payment_status,
            "amount": status_response.amount_total / 100,  # Convert from cents
            "currency": status_response.currency
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get payment status: {str(e)}")

@app.post("/api/webhook/stripe")
async def stripe_webhook(request: Request):
    """Handle Stripe webhooks"""
    try:
        body = await request.body()
        sig_header = request.headers.get("stripe-signature")
        
        # Initialize Stripe checkout
        stripe_checkout = StripeCheckout(api_key=STRIPE_API_KEY, webhook_url="")
        
        # Handle webhook
        webhook_response = await stripe_checkout.handle_webhook(body, sig_header)
        
        # Process webhook based on event type
        if webhook_response.event_type == "checkout.session.completed":
            session_id = webhook_response.session_id
            
            # Update transaction
            payment_transactions_collection.update_one(
                {"session_id": session_id},
                {"$set": {
                    "status": "completed",
                    "payment_status": "paid",
                    "webhook_processed_at": datetime.utcnow()
                }}
            )
            
            # Update user subscription status
            transaction = payment_transactions_collection.find_one({"session_id": session_id})
            if transaction:
                users_collection.update_one(
                    {"id": transaction["user_id"]},
                    {"$set": {"subscription_status": "active"}}
                )
        
        return {"status": "success"}
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Webhook error: {str(e)}")

# Emergency Contact Routes
@app.post("/api/families/{family_id}/emergency-contact")
async def set_emergency_contact(family_id: str, contact: EmergencyContactCreate, current_user: dict = Depends(get_current_user)):
    """Set emergency contact for family"""
    
    # Verify family ownership
    family = families_collection.find_one({"id": family_id, "user_id": current_user["id"]})
    if not family:
        raise HTTPException(status_code=404, detail="Family not found or access denied")
    
    # Update family with emergency contact
    families_collection.update_one(
        {"id": family_id},
        {"$set": {
            "emergency_contact": {
                "name": contact.name,
                "phone_number": contact.phone_number,
                "updated_at": datetime.utcnow()
            }
        }}
    )
    
    return {"message": "Emergency contact updated successfully"}

@app.post("/api/families/{family_id}/members/{member_id}/emergency-alert")
async def send_emergency_alert(
    family_id: str, 
    member_id: str, 
    alert_request: EmergencyAlertRequest, 
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Send emergency alert SMS"""
    
    # Verify family ownership
    family = families_collection.find_one({"id": family_id, "user_id": current_user["id"]})
    if not family:
        raise HTTPException(status_code=404, detail="Family not found or access denied")
    
    # Find family member
    member = None
    for m in family.get("members", []):
        if m["id"] == member_id:
            member = m
            break
    
    if not member:
        raise HTTPException(status_code=404, detail="Family member not found")
    
    # Check if emergency contact exists
    emergency_contact = family.get("emergency_contact")
    if not emergency_contact:
        raise HTTPException(status_code=400, detail="No emergency contact set for this family")
    
    # Format location information
    location_info = alert_request.location_address or "Unknown location"
    if alert_request.location_lat and alert_request.location_lng:
        maps_url = f"https://maps.google.com/?q={alert_request.location_lat},{alert_request.location_lng}"
        location_info = f"{location_info}\nMap: {maps_url}"
    
    # Send emergency SMS in background
    background_tasks.add_task(
        send_emergency_sms,
        member["name"],
        member.get("allergies", []),
        location_info,
        emergency_contact["phone_number"],
        emergency_contact["name"]
    )
    
    return {"message": "Emergency alert sent successfully"}

@app.get("/api/families/my")
async def get_my_family(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "family":
        raise HTTPException(status_code=403, detail="Only family users can access this")
    
    family = families_collection.find_one({"user_id": current_user["id"]})
    if not family:
        return None
    
    family.pop("_id", None)
    
    # Check subscription status for payment warning
    subscription_warning = None
    if current_user.get("subscription_status") != "active":
        subscription_warning = "Activate your account to stay live"
    
    return {
        **family,
        "subscription_warning": subscription_warning
    }

# Restaurant Routes
@app.post("/api/restaurants")
async def create_restaurant(restaurant: RestaurantCreate, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "restaurant":
        raise HTTPException(status_code=403, detail="Only restaurant users can create restaurants")
    
    restaurant_id = str(uuid.uuid4())
    restaurant_doc = {
        "id": restaurant_id,
        "user_id": current_user["id"],
        "name": restaurant.name,
        "address": restaurant.address,
        "phone": restaurant.phone,
        "description": restaurant.description,
        "created_at": datetime.utcnow(),
        "is_active": True,
        "menu_published": False
    }
    
    restaurants_collection.insert_one(restaurant_doc)
    
    return {"id": restaurant_id, "message": "Restaurant created successfully"}

@app.get("/api/restaurants/my")
async def get_my_restaurant(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "restaurant":
        raise HTTPException(status_code=403, detail="Only restaurant users can access this")
    
    restaurant = restaurants_collection.find_one({"user_id": current_user["id"]})
    if not restaurant:
        return None
    
    # Remove MongoDB _id
    restaurant.pop("_id", None)
    
    # Check subscription status for payment warning
    subscription_warning = None
    if current_user.get("subscription_status") != "active":
        subscription_warning = "Activate your account to stay live"
    
    return {
        **restaurant,
        "subscription_warning": subscription_warning
    }

@app.get("/api/restaurants")
async def get_all_restaurants():
    """Get all active restaurants for family users"""
    restaurants = list(restaurants_collection.find({"is_active": True}))
    for restaurant in restaurants:
        restaurant.pop("_id", None)
    return restaurants

@app.get("/api/restaurants/{restaurant_id}")
async def get_restaurant(restaurant_id: str):
    restaurant = restaurants_collection.find_one({"id": restaurant_id, "is_active": True})
    if not restaurant:
        raise HTTPException(status_code=404, detail="Restaurant not found")
    
    restaurant.pop("_id", None)
    return restaurant

# Family Routes
@app.post("/api/families")
async def create_family(family: FamilyCreate, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "family":
        raise HTTPException(status_code=403, detail="Only family users can create families")
    
    family_id = str(uuid.uuid4())
    family_doc = {
        "id": family_id,
        "user_id": current_user["id"],
        "family_name": family.family_name,
        "members": [
            {
                "id": str(uuid.uuid4()),
                "name": member.name,
                "allergies": member.allergies
            }
            for member in family.members
        ],
        "created_at": datetime.utcnow(),
        "is_active": True
    }
    
    families_collection.insert_one(family_doc)
    
    return {"id": family_id, "message": "Family created successfully"}

@app.get("/api/families/my")
async def get_my_family(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "family":
        raise HTTPException(status_code=403, detail="Only family users can access this")
    
    family = families_collection.find_one({"user_id": current_user["id"]})
    if not family:
        return None
    
    family.pop("_id", None)
    return family

@app.put("/api/families/my")
async def update_my_family(family: FamilyCreate, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "family":
        raise HTTPException(status_code=403, detail="Only family users can access this")
    
    result = families_collection.update_one(
        {"user_id": current_user["id"]},
        {"$set": {
            "family_name": family.family_name,
            "members": [
                {
                    "id": str(uuid.uuid4()),
                    "name": member.name,
                    "allergies": member.allergies
                }
                for member in family.members
            ],
            "updated_at": datetime.utcnow()
        }}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Family not found")
    
    return {"message": "Family updated successfully"}

# Menu Routes
@app.post("/api/restaurants/{restaurant_id}/menu-items")
async def create_menu_item(restaurant_id: str, menu_item: MenuItemCreate, current_user: dict = Depends(get_current_user)):
    # Verify restaurant ownership
    restaurant = restaurants_collection.find_one({"id": restaurant_id, "user_id": current_user["id"]})
    if not restaurant:
        raise HTTPException(status_code=404, detail="Restaurant not found or access denied")
    
    # Detect allergens
    detected_allergens = detect_allergens(menu_item.ingredients)
    
    menu_item_id = str(uuid.uuid4())
    menu_item_doc = {
        "id": menu_item_id,
        "restaurant_id": restaurant_id,
        "name": menu_item.name,
        "description": menu_item.description,
        "ingredients": menu_item.ingredients,
        "price": menu_item.price,
        "category": menu_item.category,
        "allergens_detected": detected_allergens,
        "is_published": False,
        "created_at": datetime.utcnow()
    }
    
    menu_items_collection.insert_one(menu_item_doc)
    
    return {"id": menu_item_id, "allergens_detected": detected_allergens, "message": "Menu item created successfully"}

@app.get("/api/restaurants/{restaurant_id}/menu-items")
async def get_menu_items(restaurant_id: str, published_only: bool = False):
    query = {"restaurant_id": restaurant_id}
    if published_only:
        query["is_published"] = True
    
    menu_items = list(menu_items_collection.find(query))
    for item in menu_items:
        item.pop("_id", None)
    
    return menu_items

@app.put("/api/restaurants/{restaurant_id}/menu-items/{item_id}")
async def update_menu_item(restaurant_id: str, item_id: str, menu_item: MenuItemUpdate, current_user: dict = Depends(get_current_user)):
    # Verify restaurant ownership
    restaurant = restaurants_collection.find_one({"id": restaurant_id, "user_id": current_user["id"]})
    if not restaurant:
        raise HTTPException(status_code=404, detail="Restaurant not found or access denied")
    
    # Prepare update data
    update_data = {}
    for field, value in menu_item.dict(exclude_unset=True).items():
        if field == "ingredients" and value is not None:
            update_data["ingredients"] = value
            # Re-detect allergens
            update_data["allergens_detected"] = detect_allergens(value)
        else:
            update_data[field] = value
    
    update_data["updated_at"] = datetime.utcnow()
    
    result = menu_items_collection.update_one(
        {"id": item_id, "restaurant_id": restaurant_id},
        {"$set": update_data}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Menu item not found")
    
    return {"message": "Menu item updated successfully"}

@app.delete("/api/restaurants/{restaurant_id}/menu-items/{item_id}")
async def delete_menu_item(restaurant_id: str, item_id: str, current_user: dict = Depends(get_current_user)):
    # Verify restaurant ownership
    restaurant = restaurants_collection.find_one({"id": restaurant_id, "user_id": current_user["id"]})
    if not restaurant:
        raise HTTPException(status_code=404, detail="Restaurant not found or access denied")
    
    result = menu_items_collection.delete_one({"id": item_id, "restaurant_id": restaurant_id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Menu item not found")
    
    return {"message": "Menu item deleted successfully"}

# Menu Scraping Routes
@app.post("/api/restaurants/{restaurant_id}/scrape-menu")
async def scrape_menu(restaurant_id: str, scrape_request: MenuScrapeRequest, current_user: dict = Depends(get_current_user)):
    # Verify restaurant ownership
    restaurant = restaurants_collection.find_one({"id": restaurant_id, "user_id": current_user["id"]})
    if not restaurant:
        raise HTTPException(status_code=404, detail="Restaurant not found or access denied")
    
    # Scrape menu items
    scraped_items = scrape_menu_from_url(scrape_request.url)
    
    # Process and save scraped items (but don't publish yet)
    menu_items = []
    for item in scraped_items:
        detected_allergens = detect_allergens(item["ingredients"])
        
        menu_item_id = str(uuid.uuid4())
        menu_item_doc = {
            "id": menu_item_id,
            "restaurant_id": restaurant_id,
            "name": item["name"],
            "description": item.get("description", ""),
            "ingredients": item["ingredients"],
            "price": float(item["price"]) if item["price"] and str(item["price"]).replace('.', '').isdigit() else None,
            "category": item.get("category", ""),
            "allergens_detected": detected_allergens,
            "is_published": False,
            "created_at": datetime.utcnow(),
            "scraped_from": scrape_request.url
        }
        
        menu_items_collection.insert_one(menu_item_doc)
        menu_item_doc.pop("_id", None)
        menu_items.append(menu_item_doc)
    
    return {
        "message": f"Successfully scraped {len(menu_items)} menu items",
        "items": menu_items
    }

# Menu Publishing Routes
@app.post("/api/restaurants/{restaurant_id}/publish-menu")
async def publish_menu(restaurant_id: str, current_user: dict = Depends(get_current_user)):
    # Verify restaurant ownership
    restaurant = restaurants_collection.find_one({"id": restaurant_id, "user_id": current_user["id"]})
    if not restaurant:
        raise HTTPException(status_code=404, detail="Restaurant not found or access denied")
    
    # Publish all menu items for this restaurant
    menu_items_collection.update_many(
        {"restaurant_id": restaurant_id},
        {"$set": {"is_published": True, "published_at": datetime.utcnow()}}
    )
    
    # Update restaurant status
    restaurants_collection.update_one(
        {"id": restaurant_id},
        {"$set": {"menu_published": True, "menu_published_at": datetime.utcnow()}}
    )
    
    return {"message": "Menu published successfully"}

# QR Code Routes
@app.get("/api/restaurants/{restaurant_id}/qr-code")
async def get_restaurant_qr_code(restaurant_id: str, current_user: dict = Depends(get_current_user)):
    # Verify restaurant ownership
    restaurant = restaurants_collection.find_one({"id": restaurant_id, "user_id": current_user["id"]})
    if not restaurant:
        raise HTTPException(status_code=404, detail="Restaurant not found or access denied")
    
    # Generate QR code data (URL to restaurant menu)
    base_url = os.environ.get("FRONTEND_URL", "http://localhost:3000")
    menu_url = f"{base_url}/menu/{restaurant_id}"
    
    # Generate QR code
    qr_code_base64 = generate_qr_code(menu_url)
    
    return {
        "qr_code": qr_code_base64,
        "menu_url": menu_url,
        "restaurant_name": restaurant["name"]
    }

# Public Menu Routes (for families)
@app.get("/api/menu/{restaurant_id}")
async def get_public_menu(restaurant_id: str):
    """Get published menu for a restaurant (public access for QR scanning)"""
    restaurant = restaurants_collection.find_one({"id": restaurant_id, "is_active": True})
    if not restaurant:
        raise HTTPException(status_code=404, detail="Restaurant not found")
    
    menu_items = list(menu_items_collection.find({
        "restaurant_id": restaurant_id,
        "is_published": True
    }))
    
    for item in menu_items:
        item.pop("_id", None)
    
    return {
        "restaurant": {
            "id": restaurant["id"],
            "name": restaurant["name"],
            "address": restaurant.get("address", ""),
            "description": restaurant.get("description", "")
        },
        "menu_items": menu_items
    }

@app.post("/api/menu/{restaurant_id}/check-safety")
async def check_menu_safety(restaurant_id: str, member_allergies: List[str]):
    """Check menu safety for specific allergies (used by family app)"""
    menu_items = list(menu_items_collection.find({
        "restaurant_id": restaurant_id,
        "is_published": True
    }))
    
    safe_items = []
    unsafe_items = []
    
    for item in menu_items:
        item.pop("_id", None)
        
        # Check if any of the member's allergies are detected in this item
        has_allergen = bool(set(member_allergies) & set(item.get("allergens_detected", [])))
        
        if has_allergen:
            unsafe_items.append({
                **item,
                "matching_allergens": list(set(member_allergies) & set(item.get("allergens_detected", [])))
            })
        else:
            safe_items.append(item)
    
    return {
        "safe_items": safe_items,
        "unsafe_items": unsafe_items,
        "total_items": len(menu_items),
        "safe_count": len(safe_items),
        "unsafe_count": len(unsafe_items)
    }

# Allergen Routes
@app.get("/api/allergens")
async def get_allergens():
    allergens = list(allergens_collection.find())
    for allergen in allergens:
        allergen.pop("_id", None)
    return allergens

# Consumer Menu Scanning Routes (Free Feature)
@app.post("/api/consumer/scan-menu")
async def scan_consumer_menu(scan_request: ConsumerScanRequest, current_user: dict = Depends(get_current_user)):
    """Scan any restaurant menu URL for allergen analysis (free feature)"""
    if current_user["role"] != "family":
        raise HTTPException(status_code=403, detail="Only family users can scan menus")
    
    try:
        # Scrape menu from URL
        scraped_data = scrape_consumer_menu_from_url(scan_request.url, scan_request.restaurant_name)
        
        # Create scan record
        scan_id = str(uuid.uuid4())
        scan_record = {
            "id": scan_id,
            "user_id": current_user["id"],
            "restaurant_name": scraped_data["restaurant_name"],
            "restaurant_url": scan_request.url,
            "menu_items": scraped_data["menu_items"],
            "total_items_found": scraped_data["total_items_found"],
            "scraped_at": scraped_data["scraped_at"],
            "scan_type": "consumer_free",
            "created_at": datetime.utcnow()
        }
        
        consumer_scans_collection.insert_one(scan_record)
        
        return {
            "scan_id": scan_id,
            "restaurant_name": scraped_data["restaurant_name"],
            "total_items_found": scraped_data["total_items_found"],
            "menu_items": scraped_data["menu_items"],
            "disclaimer": "This menu was scanned using public data and is not confirmed by the restaurant. Always verify allergen information with restaurant staff.",
            "is_partner_restaurant": False
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Menu scanning failed: {str(e)}")

@app.post("/api/consumer/analyze-safety/{scan_id}")
async def analyze_menu_safety(scan_id: str, member_allergies: List[str], current_user: dict = Depends(get_current_user)):
    """Analyze menu safety for specific allergies"""
    if current_user["role"] != "family":
        raise HTTPException(status_code=403, detail="Only family users can analyze menu safety")
    
    # Find scan record
    scan_record = consumer_scans_collection.find_one({"id": scan_id, "user_id": current_user["id"]})
    if not scan_record:
        raise HTTPException(status_code=404, detail="Menu scan not found")
    
    # Check if user has premium access
    is_premium = current_user.get("subscription_status") == "active"
    
    # Analyze menu safety
    safety_analysis = analyze_consumer_menu_safety(
        scan_record["menu_items"], 
        member_allergies, 
        is_premium
    )
    
    # Update scan record with analysis
    consumer_scans_collection.update_one(
        {"id": scan_id},
        {"$set": {
            "last_analysis": safety_analysis,
            "analyzed_for_allergies": member_allergies,
            "analyzed_at": datetime.utcnow(),
            "is_premium_analysis": is_premium
        }}
    )
    
    return {
        **safety_analysis,
        "restaurant_name": scan_record["restaurant_name"],
        "scan_id": scan_id,
        "is_premium_analysis": is_premium,
        "upgrade_message": None if is_premium else "Upgrade to Premium for more accurate allergen detection and personalized recommendations"
    }

@app.get("/api/consumer/scan-history")
async def get_scan_history(current_user: dict = Depends(get_current_user), limit: int = 20):
    """Get user's menu scan history"""
    if current_user["role"] != "family":
        raise HTTPException(status_code=403, detail="Only family users can access scan history")
    
    scans = list(consumer_scans_collection.find(
        {"user_id": current_user["id"]}, 
        sort=[("created_at", -1)]
    ).limit(limit))
    
    for scan in scans:
        scan.pop("_id", None)
    
    return scans

@app.post("/api/consumer/save-menu")
async def save_menu_to_favorites(save_request: SaveMenuRequest, current_user: dict = Depends(get_current_user)):
    """Save a scanned menu to favorites (Premium feature)"""
    if current_user["role"] != "family":
        raise HTTPException(status_code=403, detail="Only family users can save menus")
    
    is_premium = current_user.get("subscription_status") == "active"
    if not is_premium:
        raise HTTPException(
            status_code=403, 
            detail="Saving favorite menus is a Premium feature. Upgrade to access this functionality."
        )
    
    # Find scan record
    scan_record = consumer_scans_collection.find_one({"id": save_request.scan_id, "user_id": current_user["id"]})
    if not scan_record:
        raise HTTPException(status_code=404, detail="Menu scan not found")
    
    # Save to favorites
    favorite_id = str(uuid.uuid4())
    favorite_record = {
        "id": favorite_id,
        "user_id": current_user["id"],
        "scan_id": save_request.scan_id,
        "menu_name": save_request.menu_name,
        "notes": save_request.notes,
        "restaurant_name": scan_record["restaurant_name"],
        "restaurant_url": scan_record["restaurant_url"],
        "created_at": datetime.utcnow()
    }
    
    saved_menus_collection.insert_one(favorite_record)
    
    return {"message": "Menu saved to favorites", "favorite_id": favorite_id}

@app.get("/api/consumer/saved-menus")
async def get_saved_menus(current_user: dict = Depends(get_current_user)):
    """Get user's saved favorite menus (Premium feature)"""
    if current_user["role"] != "family":
        raise HTTPException(status_code=403, detail="Only family users can access saved menus")
    
    is_premium = current_user.get("subscription_status") == "active"
    if not is_premium:
        raise HTTPException(
            status_code=403, 
            detail="Saved menus is a Premium feature. Upgrade to access this functionality."
        )
    
    saved_menus = list(saved_menus_collection.find(
        {"user_id": current_user["id"]}, 
        sort=[("created_at", -1)]
    ))
    
    for menu in saved_menus:
        menu.pop("_id", None)
    
    return saved_menus

@app.post("/api/consumer/request-restaurant-support")
async def request_restaurant_support(support_request: RestaurantSupportRequest, current_user: dict = Depends(get_current_user)):
    """Request restaurant partnership (triggers admin alert)"""
    if current_user["role"] != "family":
        raise HTTPException(status_code=403, detail="Only family users can request restaurant support")
    
    # Check if restaurant already requested by this user
    existing_request = restaurant_requests_collection.find_one({
        "user_id": current_user["id"],
        "restaurant_url": support_request.restaurant_url
    })
    
    if existing_request:
        return {"message": "Restaurant support already requested", "status": "duplicate"}
    
    # Create support request
    request_id = str(uuid.uuid4())
    request_record = {
        "id": request_id,
        "user_id": current_user["id"],
        "user_name": current_user["name"],
        "user_email": current_user["email"],
        "restaurant_name": support_request.restaurant_name,
        "restaurant_url": support_request.restaurant_url,
        "reason": support_request.reason,
        "status": "pending",
        "is_premium_user": current_user.get("subscription_status") == "active",
        "priority": "high" if current_user.get("subscription_status") == "active" else "normal",
        "created_at": datetime.utcnow()
    }
    
    restaurant_requests_collection.insert_one(request_record)
    
    return {
        "message": "Restaurant support requested successfully", 
        "request_id": request_id,
        "priority": request_record["priority"]
    }

# Enhanced Admin Routes for Consumer Features
@app.get("/api/admin/consumer-users")
async def get_consumer_users(current_user: dict = Depends(get_current_user)):
    """Get all consumer (family) users with premium status"""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    family_users = list(users_collection.find({"role": "family"}))
    
    consumer_stats = []
    for user in family_users:
        user.pop("_id", None)
        user.pop("password", None)
        
        # Get scan count for this user
        scan_count = consumer_scans_collection.count_documents({"user_id": user["id"]})
        
        # Get favorite menus count
        favorites_count = saved_menus_collection.count_documents({"user_id": user["id"]})
        
        # Get restaurant requests count
        requests_count = restaurant_requests_collection.count_documents({"user_id": user["id"]})
        
        consumer_stats.append({
            **user,
            "total_scans": scan_count,
            "saved_menus": favorites_count,
            "restaurant_requests": requests_count,
            "last_scan": None  # Could be enhanced to get last scan date
        })
    
    return consumer_stats

@app.get("/api/admin/restaurant-requests")
async def get_restaurant_requests(current_user: dict = Depends(get_current_user), status: str = "all"):
    """Get restaurant partnership requests"""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    query = {}
    if status != "all":
        query["status"] = status
    
    requests = list(restaurant_requests_collection.find(
        query, 
        sort=[("priority", -1), ("created_at", -1)]
    ))
    
    for request in requests:
        request.pop("_id", None)
    
    return requests

@app.put("/api/admin/restaurant-requests/{request_id}/status")
async def update_request_status(request_id: str, new_status: str, current_user: dict = Depends(get_current_user)):
    """Update restaurant request status"""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    valid_statuses = ["pending", "in_progress", "contacted", "completed", "rejected"]
    if new_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")
    
    result = restaurant_requests_collection.update_one(
        {"id": request_id},
        {"$set": {
            "status": new_status,
            "updated_by": current_user["name"],
            "updated_at": datetime.utcnow()
        }}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Restaurant request not found")
    
    return {"message": "Request status updated successfully"}

@app.get("/api/admin/consumer-scans")
async def get_consumer_scans(current_user: dict = Depends(get_current_user), limit: int = 50):
    """Get recent consumer menu scans"""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    scans = list(consumer_scans_collection.find(
        {}, 
        sort=[("created_at", -1)]
    ).limit(limit))
    
    for scan in scans:
        scan.pop("_id", None)
        # Add user info
        user = users_collection.find_one({"id": scan["user_id"]})
        if user:
            scan["user_name"] = user["name"]
            scan["user_email"] = user["email"]
            scan["is_premium_user"] = user.get("subscription_status") == "active"
    
    return scans

@app.get("/api/admin/most-requested-restaurants")
async def get_most_requested_restaurants(current_user: dict = Depends(get_current_user), limit: int = 20):
    """Get most requested restaurants by consumers"""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Aggregate restaurant requests by restaurant
    pipeline = [
        {"$group": {
            "_id": "$restaurant_url",
            "restaurant_name": {"$first": "$restaurant_name"},
            "request_count": {"$sum": 1},
            "premium_user_requests": {
                "$sum": {"$cond": [{"$eq": ["$is_premium_user", True]}, 1, 0]}
            },
            "latest_request": {"$max": "$created_at"},
            "sample_users": {"$push": {"name": "$user_name", "email": "$user_email"}}
        }},
        {"$sort": {"request_count": -1}},
        {"$limit": limit}
    ]
    
    most_requested = list(restaurant_requests_collection.aggregate(pipeline))
    
    # Format results
    formatted_results = []
    for item in most_requested:
        formatted_results.append({
            "restaurant_url": item["_id"],
            "restaurant_name": item["restaurant_name"],
            "total_requests": item["request_count"],
            "premium_user_requests": item["premium_user_requests"],
            "latest_request": item["latest_request"],
            "sample_requesting_users": item["sample_users"][:3]  # Show first 3 users
        })
    
    return formatted_results
@app.get("/api/admin/restaurants")
async def get_all_restaurants_admin(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    restaurants = list(restaurants_collection.find())
    for restaurant in restaurants:
        restaurant.pop("_id", None)
        # Add user subscription info
        user = users_collection.find_one({"id": restaurant["user_id"]})
        if user:
            restaurant["user_subscription_status"] = user.get("subscription_status", "trial")
    return restaurants

@app.get("/api/admin/families")
async def get_all_families_admin(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    families = list(families_collection.find())
    for family in families:
        family.pop("_id", None)
        # Add user subscription info
        user = users_collection.find_one({"id": family["user_id"]})
        if user:
            family["user_subscription_status"] = user.get("subscription_status", "trial")
    return families

@app.get("/api/admin/users")
async def get_all_users_admin(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    users = list(users_collection.find())
    for user in users:
        user.pop("_id", None)
        user.pop("password", None)  # Don't return passwords
    return users

@app.get("/api/admin/subscriptions")
async def get_all_subscriptions_admin(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    subscriptions = list(subscriptions_collection.find())
    for subscription in subscriptions:
        subscription.pop("_id", None)
        # Add user info
        user = users_collection.find_one({"id": subscription["user_id"]})
        if user:
            subscription["user_name"] = user["name"]
            subscription["user_email"] = user["email"]
            subscription["user_role"] = user["role"]
    
    return subscriptions

@app.get("/api/admin/sms-logs")
async def get_sms_logs_admin(current_user: dict = Depends(get_current_user), limit: int = 50):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    sms_logs = list(sms_logs_collection.find().sort("created_at", -1).limit(limit))
    for log in sms_logs:
        log.pop("_id", None)
    return sms_logs

@app.get("/api/admin/email-logs")
async def get_email_logs_admin(current_user: dict = Depends(get_current_user), limit: int = 50):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    email_logs = list(email_logs_collection.find().sort("created_at", -1).limit(limit))
    for log in email_logs:
        log.pop("_id", None)
    return email_logs

@app.get("/api/admin/payment-transactions")
async def get_payment_transactions_admin(current_user: dict = Depends(get_current_user), limit: int = 50):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    transactions = list(payment_transactions_collection.find().sort("created_at", -1).limit(limit))
    for transaction in transactions:
        transaction.pop("_id", None)
        # Add user info
        user = users_collection.find_one({"id": transaction["user_id"]})
        if user:
            transaction["user_name"] = user["name"]
            transaction["user_email"] = user["email"]
    
    return transactions

@app.get("/api/admin/stats")
async def get_admin_stats(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Basic stats
    total_restaurants = restaurants_collection.count_documents({})
    total_families = families_collection.count_documents({})
    total_menu_items = menu_items_collection.count_documents({})
    published_menus = restaurants_collection.count_documents({"menu_published": True})
    
    # Subscription stats
    active_subscriptions = subscriptions_collection.count_documents({"status": "active"})
    trial_users = users_collection.count_documents({"subscription_status": "trial"})
    active_users = users_collection.count_documents({"subscription_status": "active"})
    
    # Consumer stats (new)
    total_consumer_scans = consumer_scans_collection.count_documents({})
    total_restaurant_requests = restaurant_requests_collection.count_documents({})
    pending_restaurant_requests = restaurant_requests_collection.count_documents({"status": "pending"})
    premium_consumer_users = users_collection.count_documents({"role": "family", "subscription_status": "active"})
    free_consumer_users = users_collection.count_documents({"role": "family", "subscription_status": {"$ne": "active"}})
    
    # Communication stats (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_sms = sms_logs_collection.count_documents({"created_at": {"$gte": thirty_days_ago}})
    recent_emails = email_logs_collection.count_documents({"created_at": {"$gte": thirty_days_ago}})
    recent_consumer_scans = consumer_scans_collection.count_documents({"created_at": {"$gte": thirty_days_ago}})
    
    # Emergency alerts (last 30 days)
    emergency_alerts = sms_logs_collection.count_documents({
        "sms_type": "emergency", 
        "created_at": {"$gte": thirty_days_ago}
    })
    
    # Revenue calculation (total successful payments)
    pipeline = [
        {"$match": {"payment_status": "paid"}},
        {"$group": {"_id": None, "total_revenue": {"$sum": "$amount"}}}
    ]
    revenue_result = list(payment_transactions_collection.aggregate(pipeline))
    total_revenue = revenue_result[0]["total_revenue"] if revenue_result else 0
    
    return {
        # Existing stats
        "total_restaurants": total_restaurants,
        "total_families": total_families,
        "total_menu_items": total_menu_items,
        "published_menus": published_menus,
        "active_subscriptions": active_subscriptions,
        "trial_users": trial_users,
        "active_users": active_users,
        "recent_sms_sent": recent_sms,
        "recent_emails_sent": recent_emails,
        "emergency_alerts_30_days": emergency_alerts,
        "total_revenue": round(total_revenue, 2),
        "subscription_packages": SUBSCRIPTION_PACKAGES,
        
        # New consumer stats
        "total_consumer_scans": total_consumer_scans,
        "recent_consumer_scans_30_days": recent_consumer_scans,
        "total_restaurant_requests": total_restaurant_requests,
        "pending_restaurant_requests": pending_restaurant_requests,
        "premium_consumer_users": premium_consumer_users,
        "free_consumer_users": free_consumer_users,
        
        # Consumer engagement metrics
        "consumer_conversion_rate": round((premium_consumer_users / max(total_families, 1)) * 100, 1)
    }

# Webhook Endpoints for Production Integration
@app.post("/api/webhooks/stripe")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events"""
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')
    
    # Log webhook received (stub for now)
    webhook_log = {
        "id": str(uuid.uuid4()),
        "type": "stripe_webhook", 
        "received_at": datetime.utcnow(),
        "payload_size": len(payload),
        "processed": False
    }
    
    try:
        # In production, verify webhook signature here
        # event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        
        # For now, just log the webhook
        webhook_log["processed"] = True
        webhook_log["status"] = "received"
        
        # TODO: Handle different Stripe events:
        # - payment_intent.succeeded
        # - invoice.payment_succeeded  
        # - customer.subscription.updated
        # - customer.subscription.deleted
        
        return {"received": True}
        
    except Exception as e:
        webhook_log["error"] = str(e)
        webhook_log["status"] = "failed"
        return {"error": "Webhook processing failed"}, 400

@app.post("/api/webhooks/twilio") 
async def twilio_webhook(request: Request):
    """Handle Twilio webhook events"""
    form_data = await request.form()
    
    # Log Twilio status callback
    webhook_log = {
        "id": str(uuid.uuid4()),
        "type": "twilio_webhook",
        "received_at": datetime.utcnow(),
        "message_sid": form_data.get("MessageSid"),
        "message_status": form_data.get("MessageStatus"),
        "processed": True
    }
    
    try:
        # TODO: Handle Twilio delivery status updates
        # Update SMS logs with delivery status
        message_sid = form_data.get("MessageSid")
        message_status = form_data.get("MessageStatus")
        
        if message_sid and message_status:
            # Update SMS log record
            sms_logs_collection.update_one(
                {"twilio_sid": message_sid},
                {"$set": {
                    "delivery_status": message_status,
                    "updated_at": datetime.utcnow()
                }}
            )
        
        return {"received": True}
        
    except Exception as e:
        webhook_log["error"] = str(e)
        return {"error": "Webhook processing failed"}, 400

@app.get("/api/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "mode": APP_MODE,
        "timestamp": datetime.utcnow(),
        "services": {
            "mongodb": "connected",
            "stripe": "configured" if os.environ.get("STRIPE_API_KEY") else "not_configured",
            "twilio": "configured" if os.environ.get("TWILIO_ACCOUNT_SID") else "not_configured"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
