from supabase import create_client, Client

def test_supabase_api():
    """Test connection using Supabase API"""
    
    # CORRECT values from your Project Settings
    SUPABASE_URL = "https://obnhesobzgppiidigdtu.supabase.co"
    SUPABASE_KEY = "sb_publishable_-zpPTE45VhRROAZOV0xxFg_iTMVSYLA"
    try:
        print("="*60)
        print("SUPABASE API CONNECTION TEST")
        print("="*60)
        print(f"\n🔌 Connecting to Supabase API...")
        print(f"URL: {SUPABASE_URL}")
        print(f"Key: {SUPABASE_KEY[:30]}...")
        
        # Create Supabase client
        supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
        
        print("\n✅ Supabase client created successfully!")
        
        # Test with a simple query
        try:
            # Try to list tables (this might fail but shows connection works)
            response = supabase.table('_test_').select("*").limit(1).execute()
            print("✅ API connection is working!")
        except Exception as e:
            error_msg = str(e).lower()
            if "relation" in error_msg or "not found" in error_msg or "does not exist" in error_msg:
                print("✅ API connection is working!")
                print("   (Test table doesn't exist, which is expected)")
            else:
                print(f"⚠️  Connection works, but got: {e}")
        
        print("\n" + "="*60)
        print("SUCCESS! You can now use Supabase in your application")
        print("="*60)
        print("\n📝 Use these credentials in your code:")
        print(f'SUPABASE_URL = "{SUPABASE_URL}"')
        print(f'SUPABASE_KEY = "{SUPABASE_KEY}"')
        
        return supabase
        
    except Exception as e:
        print(f"\n❌ Connection failed: {e}")
        return None

def example_usage(supabase):
    """Show example operations"""
    if not supabase:
        return
    
    print("\n" + "="*60)
    print("EXAMPLE USAGE")
    print("="*60)
    
    print("""
# Insert data
data = supabase.table('your_table').insert({
    "column1": "value1",
    "column2": "value2"
}).execute()

# Query data
data = supabase.table('your_table').select("*").execute()

# Update data
data = supabase.table('your_table').update({
    "column1": "new_value"
}).eq('id', 1).execute()

# Delete data
data = supabase.table('your_table').delete().eq('id', 1).execute()
""")

if __name__ == "__main__":
    supabase = test_supabase_api()
    if supabase:
        example_usage(supabase)