import asyncio
import websockets
import json
import redis
import time
import geoip2.database

class MapTrafficServer():
    def __init__(self):
        self.wsclients = set()
        self.redis = redis.Redis()
        self.geoip = geoip2.database.Reader('../database/GeoLite2-City_20190402/GeoLite2-City.mmdb')
        self.publicip = "82.212.177.72"
        self.cooldown = {}
        self.colors = [
            '#F0FF60', '#FFC460', '#FF7D60',
	    '#FF6081', '#FF60C0', '#FF60F7',
	    '#B760FF', '#7E60FF', '#6077FF',
	    '#60AFFF', '#60F2FF', '#60FFC4',
	    '#60FF75', '#9CFF60', '#D7FF60',
        ]

    #
    # Websocket
    #
    async def wsbroadcast(self, payload):
        if not len(self.wsclients):
            return

        for client in list(self.wsclients):
            if not client.open:
                continue

            try:
                await client.send(payload)

            except Exception as e:
                print(e)

    async def wspayload(self, websocket, type, payload):
        content = json.dumps({"type": type, "payload": payload})
        await websocket.send(content)

    async def handler(self, websocket, path):
        self.wsclients.add(websocket)

        print("[+] websocket: client connected")

        try:
            while True:
                if not websocket.open:
                    break

                await asyncio.sleep(1)

        finally:
            print("[+] websocket: client disconnected")
            self.wsclients.remove(websocket)

    async def redisloop(self):
        pubsub = self.redis.pubsub()
        pubsub.subscribe(['maptraffic'])

        while True:
            message = pubsub.get_message()
            if message and message['type'] == 'message':
                # skipping of no clients are connected
                if not len(self.wsclients):
                    continue

                handler = json.loads(message['data'].decode('utf-8'))
                target = '0.0.0.0'

                if handler['src'] == self.publicip:
                    target = handler['dst']

                    if handler['dst'] in self.cooldown:
                        if self.cooldown[handler['dst']] == int(time.time()):
                            continue

                if handler['dst'] == self.publicip:
                    target = handler['src']

                    if handler['src'] in self.cooldown:
                        if self.cooldown[handler['src']] == int(time.time()):
                            continue

                print("[+] data from analyzer: %s" % handler)

                """
                if handler['src'] == "10.241.0.18":
                    handler['src'] = "82.212.177.72"

                if handler['dst'] == "10.241.0.18":
                    handler['dst'] = "82.212.177.72"
                """

                try:
                    srcobj = self.geoip.city(handler['src'])
                    dstobj = self.geoip.city(handler['dst'])

                except Exception as e:
                    # could not find one address on the database
                    continue

                ip = int(handler['src'].replace(".", ""))

                payload = {
                    "src": [srcobj.location.latitude, srcobj.location.longitude],
                    "dst": [dstobj.location.latitude, dstobj.location.longitude],
                    "coloring": self.colors[ip % len(self.colors)],
                }

                self.cooldown[target] = int(time.time())

                # forwarding
                await self.wsbroadcast(json.dumps(payload))
                continue

            await asyncio.sleep(0.1)

    def run(self):
        # standard polling handlers
        loop = asyncio.get_event_loop()
        loop.set_debug(True)

        # handle websocket communication
        websocketd = websockets.serve(self.handler, "0.0.0.0", 1441, subprotocols=["maptraffic"])
        asyncio.ensure_future(websocketd, loop=loop)
        asyncio.ensure_future(self.redisloop(), loop=loop)

        print("[+] waiting for redis messages or clients")
        loop.run_forever()

if __name__ == '__main__':
    mtraffic = MapTrafficServer()
    mtraffic.run()

