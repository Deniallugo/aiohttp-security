import enum
import warnings
from aiohttp import web
from aiohttp_security.abc import (AbstractIdentityPolicy,
                                  AbstractAuthorizationPolicy,
                                  AbstractAuthenticationPolicy)
from functools import wraps

IDENTITY_KEY = 'aiohttp_security_identity_policy'
AUTZ_KEY = 'aiohttp_security_autz_policy'
AUTH_KEY = 'aiohttp_security_auth_policy'


async def remember(request, response, identity, **kwargs):
    """Remember identity into response.

    The action is performed by identity_policy.remember()

    Usually the identity is stored in user cookies somehow but may be
    pushed into custom header also.
    """
    assert isinstance(identity, str), identity
    assert identity
    identity_policy = request.app.get(IDENTITY_KEY)
    if identity_policy is None:
        text = ("Security subsystem is not initialized, "
                "call aiohttp_security.setup(...) first")
        # in order to see meaningful exception message both: on console
        # output and rendered page we add same message to *reason* and
        # *text* arguments.
        raise web.HTTPInternalServerError(reason=text, text=text)
    await identity_policy.remember(request, response, identity, **kwargs)


async def forget(request, response):
    """Forget previously remembered identity.

    Usually it clears cookie or server-side storage to forget user
    session.
    """
    identity_policy = request.app.get(IDENTITY_KEY)
    if identity_policy is None:
        text = ("Security subsystem is not initialized, "
                "call aiohttp_security.setup(...) first")
        # in order to see meaningful exception message both: on console
        # output and rendered page we add same message to *reason* and
        # *text* arguments.
        raise web.HTTPInternalServerError(reason=text, text=text)
    await identity_policy.forget(request, response)


async def authorized_userid(request, context=None):
    identity_policy = request.app.get(IDENTITY_KEY)
    autz_policy = request.app.get(AUTZ_KEY)
    if identity_policy is None or autz_policy is None:
        return None
    identity = await identity_policy.identify(request, context)
    if identity is None:
        return None  # non-registered user has None user_id
    user_id = await autz_policy.authorized_userid(identity, context)
    return user_id


async def authenticate_user(credentials, context):
    """Authenticate user by credentials

    :param credentials: Authenticate credentials for AuthenticationPolicy
    :param context: context can be dict or object,
     you can send request like context
    :return: User
    """
    app = context.get('app') or getattr(context, 'app', None)
    if app is None:
        raise Exception('No app in context')
    authenticate_policy = app.get(AUTH_KEY)
    if authenticate_policy is None:
        return None
    user = await authenticate_policy.authenticate_user(credentials, context)
    return user


async def permits(request, permission, context=None):
    assert isinstance(permission, (str, enum.Enum)), permission
    assert permission
    identity_policy = request.app.get(IDENTITY_KEY)
    autz_policy = request.app.get(AUTZ_KEY)
    if identity_policy is None or autz_policy is None:
        return True
    identity = await identity_policy.identify(request)
    # non-registered user still may has some permissions
    access = await autz_policy.permits(identity, permission, context)
    return access


async def is_anonymous(request, context=None):
    """Check if user is anonymous.

    User is considered anonymous if there is not identity
    in request.
    """
    identity_policy = request.app.get(IDENTITY_KEY)
    if identity_policy is None:
        return True
    identity = await identity_policy.identify(request, context)
    if identity is None:
        return True
    return False


async def check_authorized(request, context=None):
    """Checker that raises HTTPUnauthorized for anonymous users.
    """
    userid = await authorized_userid(request, context)
    if userid is None:
        raise web.HTTPUnauthorized()
    return userid


def login_required(fn):
    """Decorator that restrict access only for authorized users.

    User is considered authorized if authorized_userid
    returns some value.

    Decorator add extra argument "user"

    """

    @wraps(fn)
    async def wrapped(*args, **kwargs):
        request = args[-1]
        if not isinstance(request, web.BaseRequest):
            msg = ("Incorrect decorator usage. "
                   "Expecting `def handler(request)` "
                   "or `def handler(self, request)`.")
            raise RuntimeError(msg)

        await check_authorized(request)
        return await fn(*args, **kwargs)

    warnings.warn("login_required decorator is deprecated, "
                  "use check_authorized instead",
                  DeprecationWarning)
    return wrapped


async def check_permission(request, permission, context=None):
    """Checker that passes only to authoraised users with given permission.

    If user is not authorized - raises HTTPUnauthorized,
    if user is authorized and does not have permission -
    raises HTTPForbidden.
    """

    await check_authorized(request, context)
    allowed = await permits(request, permission, context)
    if not allowed:
        raise web.HTTPForbidden()


def has_permission(
        permission,
        context=None,
):
    """Decorator that restricts access only for authorized users
    with correct permissions.

    If user is not authorized - raises HTTPUnauthorized,
    if user is authorized and does not have permission -
    raises HTTPForbidden.

    Decorator add extra argument "user"
    """

    def wrapper(fn):
        @wraps(fn)
        async def wrapped(*args, **kwargs):
            request = args[-1]
            if not isinstance(request, web.BaseRequest):
                msg = ("Incorrect decorator usage. "
                       "Expecting `def handler(request)` "
                       "or `def handler(self, request)`.")
                raise RuntimeError(msg)

            await check_permission(request, permission, context)
            return await fn(*args, **kwargs)

        return wrapped

    warnings.warn("has_permission decorator is deprecated, "
                  "use check_permission instead",
                  DeprecationWarning)
    return wrapper


def setup(app, identity_policy, autz_policy, auth_policy=None):
    assert isinstance(identity_policy, AbstractIdentityPolicy), identity_policy
    assert isinstance(autz_policy, AbstractAuthorizationPolicy), autz_policy

    if auth_policy:
        assert isinstance(auth_policy,
                          AbstractAuthenticationPolicy), auth_policy
        app[AUTH_KEY] = auth_policy

    app[IDENTITY_KEY] = identity_policy
    app[AUTZ_KEY] = autz_policy
