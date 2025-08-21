#!/usr/bin/env python3
"""
Generate a secure secret key for Flask production deployment
"""

import secrets

def generate_secret_key():
    """Generate a secure secret key"""
    key = secrets.token_hex(32)
    print("🔐 Generated secure SECRET_KEY for production:")
    print(f"SECRET_KEY={key}")
    print("\n📋 Copy this to your .env file and Vercel environment variables")
    return key

if __name__ == "__main__":
    generate_secret_key()
