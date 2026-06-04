import asyncio
import os
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

client = genai.Client(api_key=os.getenv('GEMINI_API_KEY'))

async def main():
    models_to_test = ['gemini-2.0-flash-lite', 'gemini-flash-latest']
    for m in models_to_test:
        print(f"Testing {m}...")
        try:
            response = await client.aio.models.generate_content(
                model=m,
                contents='Test'
            )
            print(f"SUCCESS for {m}:", response.text)
        except Exception as e:
            print(f"ERROR for {m}:", repr(e))

asyncio.run(main())
