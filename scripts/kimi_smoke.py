#!/usr/bin/env python3
"""Test script for Kimi.com API connection."""
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

# Load .env
env_path = Path(__file__).parent / ".env"
if env_path.exists():
    load_dotenv(env_path)
else:
    print("❌ .env file not found!")
    sys.exit(1)

from app.core.llm_config import get_llm_config

def test_kimi():
    """Test Kimi.com API connection."""
    print("=" * 60)
    print("Testing Kimi.com For Coding API")
    print("=" * 60)
    print()
    
    try:
        config = get_llm_config()
        provider = config.get_active_provider()
        
        print(f"Provider: {provider.name}")
        print(f"Base URL: {provider.base_url}")
        print(f"Model: {provider.model}")
        print(f"API Key: {'SET' if provider.api_key and len(provider.api_key) > 10 else 'NOT SET'}")
        if provider.api_key:
            print(f"API Key (first 15 chars): {provider.api_key[:15]}...")
        print()
        
        print("Making test API call...")
        client = config.get_client()
        
        # Use Anthropic API format for Kimi
        if provider.type == 'anthropic':
            response = client.messages.create(
                model=provider.model,
                messages=[
                    {"role": "user", "content": "Say 'Hello from Kimi!' if you can hear me."}
                ],
                max_tokens=20,
                temperature=0
            )
            content = response.content[0].text
        else:
            # OpenAI format
            response = client.chat.completions.create(
                model=provider.model,
                messages=[
                    {"role": "user", "content": "Say 'Hello from Kimi!' if you can hear me."}
                ],
                max_tokens=20,
                temperature=0
            )
            content = response.choices[0].message.content
        
        print("✅ SUCCESS!")
        print(f"Response: {content}")
        print()
        print("🎉 Kimi.com is working correctly!")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        print()
        if "403" in str(e) or "Access terminated" in str(e):
            print("This error indicates:")
            print("1. The API key may be invalid or expired")
            print("2. The account access may have been terminated")
            print("3. The API key may not have permissions for the coding API")
            print()
            print("Please:")
            print("- Check your API key on the Kimi.com membership page")
            print("- Verify your account has access to 'Kimi For Coding'")
            print("- Regenerate the API key if needed")
            print("- Update the .env file with the new key")
        return False

if __name__ == "__main__":
    success = test_kimi()
    sys.exit(0 if success else 1)
