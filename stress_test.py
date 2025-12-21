import asyncio
import aiohttp
import time
import sys

async def fetch(session, url):
    try:
        async with session.get(url, timeout=2) as response:
            return response.status
    except Exception as e:
        return 0 # Error

async def run_stress_test(url, concurrency, duration):
    print(f"Starting stress test: {url} with concurrency={concurrency} for {duration}s")
    start_time = time.time()
    results = []
    
    async with aiohttp.ClientSession() as session:
        while time.time() - start_time < duration:
            tasks = [fetch(session, url) for _ in range(concurrency)]
            batch_results = await asyncio.gather(*tasks)
            results.extend(batch_results)
            # await asyncio.sleep(0.01)

    end_time = time.time()
    total_time = end_time - start_time
    total_requests = len(results)
    rps = total_requests / total_time
    
    success = results.count(200)
    errors = total_requests - success
    
    print(f"Results:")
    print(f"  Total Requests: {total_requests}")
    print(f"  Total Time: {total_time:.2f}s")
    print(f"  Requests/sec: {rps:.2f}")
    print(f"  Success (200 OK): {success}")
    print(f"  Errors: {errors}")

if __name__ == "__main__":
    url = "http://localhost:8080"
    conc = 50
    dur = 10
    if len(sys.argv) > 1: conc = int(sys.argv[1])
    if len(sys.argv) > 2: dur = int(sys.argv[2])
    if len(sys.argv) > 3: url = sys.argv[3]
    
    asyncio.run(run_stress_test(url, concurrency=conc, duration=dur))
