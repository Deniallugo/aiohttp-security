from .abc import (AbstractAuthorizationPolicy, AbstractIdentityPolicy,
                  AbstractAuthenticationPolicy)
from .api import (authorized_userid, forget, has_permission, is_anonymous,
                  login_required, permits, remember, setup, provide_user,
                  authenticate_user)
from .cookies_identity import CookiesIdentityPolicy
from .session_identity import SessionIdentityPolicy
from .jwt_identity import JWTIdentityPolicy

__version__ = '0.2.1'

__all__ = ('AbstractIdentityPolicy', 'AbstractAuthorizationPolicy',
           'AbstractAuthenticationPolicy',
           'CookiesIdentityPolicy', 'SessionIdentityPolicy',
           'JWTIdentityPolicy',
           'remember', 'forget', 'authorized_userid',
           'authenticate_user',
           'permits', 'setup', 'is_anonymous',
           'login_required', 'has_permission',
           'provide_user')
