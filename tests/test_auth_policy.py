from aiohttp import web
from aiohttp_security import setup as _setup
from aiohttp_security import (AbstractAuthenticationPolicy,
                              AbstractAuthorizationPolicy,
                              authenticate_user)
from aiohttp_security.cookies_identity import CookiesIdentityPolicy


class Auth(AbstractAuthenticationPolicy):

    async def authenticate_user(self, credentials, context=None):

        username = credentials.get('username')
        password = credentials.get('password')
        if username == 'UserID' and password == 'pass':
            return 'Andrew'
        else:
            return None


class Autz(AbstractAuthorizationPolicy):

    async def permits(self, identity, permission, context=None):
        if identity == 'UserID':
            return permission in {'read', 'write'}
        else:
            return False

    async def authorized_userid(self, identity):
        if identity == 'UserID':
            return 'Andrew'
        else:
            return None


async def test_authenticate_user(loop, aiohttp_client):
    async def login(request):
        context = {'app': request.app}
        credentials = await request.json()
        user = await authenticate_user(credentials, context)
        return web.Response(text=user)

    app = web.Application()
    _setup(app, CookiesIdentityPolicy(), Autz(), Auth())
    app.router.add_route('POST', '/login', login)
    client = await aiohttp_client(app)

    resp = await client.post('/login',
                             json={'username': 'UserID', 'password': 'pass'})
    assert 200 == resp.status
    txt = await resp.text()
    assert 'Andrew' == txt


async def test_authenticate_user_by_request(loop, aiohttp_client):
    async def login(request):
        credentials = await request.json()
        user = await authenticate_user(credentials, request)
        return web.Response(text=user)

    app = web.Application()
    _setup(app, CookiesIdentityPolicy(), Autz(), Auth())
    app.router.add_route('POST', '/login', login)
    client = await aiohttp_client(app)

    resp = await client.post('/login',
                             json={'username': 'UserID', 'password': 'pass'})
    assert 200 == resp.status
    txt = await resp.text()
    assert 'Andrew' == txt
