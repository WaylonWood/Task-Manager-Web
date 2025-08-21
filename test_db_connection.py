#!/usr/bin/env python3
"""
Test script to verify PostgreSQL connection for Neon database
Run this after setting up your database to test the connection
"""

import os
import sys

def test_database_connection():
    """Test connection to PostgreSQL database"""
    
    # Get database URL from environment or prompt
    database_url = os.environ.get('DATABASE_URL')
    
    if not database_url:
        print("🔧 Enter your Neon PostgreSQL connection string:")
        print("Format: postgresql://username:password@ep-xxx.region.aws.neon.tech/neondb?sslmode=require")
        database_url = input("DATABASE_URL: ").strip()
    
    if not database_url:
        print("❌ No database URL provided")
        return False
    
    try:
        print("🔗 Testing connection to PostgreSQL...")
        
        # Try using psycopg (newer version)
        try:
            import psycopg
            from psycopg import sql
            
            # Test connection with psycopg
            with psycopg.connect(database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT version()")
                    version = cur.fetchone()[0]
                    print(f"✅ Connection successful!")
                    print(f"🐘 PostgreSQL version: {version}")
                    
                    # Test basic operations
                    cur.execute("SELECT 1")
                    print("✅ Basic queries working")
                    
                    # Check if we can create tables (important for migrations)
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS connection_test (
                            id SERIAL PRIMARY KEY,
                            test_message TEXT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                    print("✅ Table creation permissions working")
                    
                    # Clean up test table
                    cur.execute("DROP TABLE IF EXISTS connection_test")
                    print("✅ Table deletion permissions working")
                    
                    conn.commit()
                    
        except ImportError:
            # Fallback to SQLAlchemy (what your app actually uses)
            from sqlalchemy import create_engine, text
            
            engine = create_engine(database_url)
            with engine.connect() as connection:
                result = connection.execute(text("SELECT version()"))
                version = result.fetchone()[0]
                print(f"✅ Connection successful!")
                print(f"🐘 PostgreSQL version: {version}")
                
                # Test basic operations
                connection.execute(text("SELECT 1"))
                print("✅ Basic queries working")
                
                # Check if we can create tables (important for migrations)
                connection.execute(text("""
                    CREATE TABLE IF NOT EXISTS connection_test (
                        id SERIAL PRIMARY KEY,
                        test_message TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """))
                print("✅ Table creation permissions working")
                
                # Clean up test table
                connection.execute(text("DROP TABLE IF EXISTS connection_test"))
                print("✅ Table deletion permissions working")
                
                connection.commit()
            
        print("\n🎉 Neon database connection test PASSED!")
        print("Your Neon PostgreSQL database is ready for deployment!")
        return True
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        print("\n🔧 Troubleshooting tips:")
        print("1. Check your connection string format")
        print("2. Verify database endpoint and credentials in Neon dashboard")
        print("3. Ensure the connection string includes ?sslmode=require")
        print("4. Check if you copied the full connection string (including password)")
        return False

if __name__ == "__main__":
    print("🧪 Neon PostgreSQL Connection Test")
    print("=" * 50)
    test_database_connection()
