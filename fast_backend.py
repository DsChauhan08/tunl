import asyncio


async def handle_echo(reader, writer):
    try:
        _ = await reader.read(1024)
        response = (
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHello"
        )
        writer.write(response.encode())
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


async def main():
    server = await asyncio.start_server(handle_echo, "127.0.0.1", 9000, backlog=1000)
    print("Fast backend listening on 9000")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
