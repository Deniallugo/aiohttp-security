"""Identity policy for storing info directly into HTTP cookie.

Use mostly for demonstration purposes, SessionIdentityPolicy is much
more handy.

"""

from .abc import AbstractIdentityPolicy


sentinel = object()


class CookiesIdentityPolicy(AbstractIdentityPolicy):

    def __init__(self):
        self._cookie_name = 'AIOHTTP_SECURITY'
        self._max_age = 30 * 24 * 3600

    async def identify(self, request, context=None):
        identity = request.cookies.get(self._cookie_name)
        return identity

    async def remember(self, request, response, identity, max_age=sentinel,
                       **kwargs):
        if max_age is sentinel:
            max_age = self._max_age
        response.set_cookie(self._cookie_name, identity,
                            max_age=max_age, **kwargs)

    async def forget(self, request, response):
        response.del_cookie(self._cookie_name)
