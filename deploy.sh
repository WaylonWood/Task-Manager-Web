#!/bin/bash

# This script runs database migrations on Vercel
# You might need to run this manually or set up a separate deployment step

# Set environment variables
export FLASK_APP=app.py

# Run database migrations
flask db upgrade

echo "Database migrations completed"
