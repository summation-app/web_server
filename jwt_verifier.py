import logging
from authlib.jose import JsonWebToken
from authlib.jose import jwt as authlib_jwt
from authlib.jose.errors import (
	MissingClaimError,
	InvalidClaimError,
	ExpiredTokenError,
	InvalidTokenError
)
from dataclasses import dataclass, field
import aiohttp
import json
import sys
import jwt #  library’s JWK support is undocumented, and won't work with firebase so we only use it for getting unverified header
from jwcrypto import jwk
import requests

logger = logging.getLogger(__name__)

# TODO: #@functools.lru_cache(maxsize=1)
# TODO: switch to aiohttp instead of requests to make async
# https://renzolucioni.com/verifying-jwts-with-jwks-and-pyjwt/
subclasses = {}

@dataclass
class JWTVerifier():
	key = None
	audience = None
	token: str

	def __init_subclass__(cls, **kwargs):
		super().__init_subclass__(**kwargs)
		subclasses[cls._protocol] = cls

	@classmethod
	def create(cls, protocol, **kwargs):
		#if protocol not in cls.subclasses:
		if protocol not in subclasses:
			raise ValueError('Bad protocol {}'.format(protocol))
		return subclasses[protocol](**kwargs)

	def get_key(self, url, header):
		r = requests.get(url)
		jwks = r.json()
		kid = header['kid']
		for key in jwks["keys"]:
			if key["kid"] == kid:
				return key

	def get_token_claims(self):
		claims = JsonWebToken(['RS256']).decode(
				self.token,
				self.key)
		return claims

	def verify_token(self, claims=None):
		if not claims:
			claims = self.get_token_claims()
		claims.validate()
		if self.audience:
			assert self.audience==claims.get('audience')
		return claims

@dataclass
class Firebase(JWTVerifier):
	_protocol = 'firebase'
	audience: str # equals the firebase Project ID

	def __post_init__(self):
		self.certificate_url= 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com'
		r = requests.get(self.certificate_url)
		certs = r.json()
		processed_token = jwt.get_unverified_header(self.token)
		kid = processed_token['kid']
		if kid not in certs:
			print('error unknown')
		self.key = jwk.JWK.from_pem(certs[kid].encode('ascii')).export_public(as_dict=True)

@dataclass
class Okta(JWTVerifier):
	_protocol = 'okta'
	domain: str
	client_id: str

	def __post_init__(self):
		jwks_url = f"https://{self.domain}/oauth2/default/v1/keys"
		self.key = self.get_key(jwks_url, jwt.get_unverified_header(self.token))
		self.audience = self.client_id # normalizing, for the audience check in verify_token

@dataclass
class Cognito(JWTVerifier):
	_protocol = 'cognito'
	region: str
	user_pool_id: str
	client_id: str
	
	def __post_init__(self):
		jwks_url = f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}/.well-known/jwks.json"
		self.key = self.get_key(jwks_url, jwt.get_unverified_header(self.token))
		self.audience = self.client_id # normalizing, for the audience check in verify_token

@dataclass
class Auth0(JWTVerifier):
	_protocol = 'auth0'
	domain: str
	client_id: str

	def __post_init__(self):
		issuer = f"https://{self.domain}/"
		jwks_url = f"https://{self.domain}/.well-known/jwks.json"
		self.key = self.get_key(jwks_url, jwt.get_unverified_header(self.token))
		self.audience = self.client_id # normalizing, for the audience check in verify_token