import pytest
import logging
import os
import asyncio
import sys
from threading import Thread

from aiohttp import ClientSession
import base64

os.environ['ENVIRONMENT'] = 'TEST'
from app import *
import test_server

logger = logging.getLogger(__name__)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

connect_to_test_database()

class TestDatabaseConnections:

	@classmethod
	def setup_class(cls):
		"""
		initialize SQLite database
		import data from test database
		"""
		pass

	@classmethod
	def teardown_class(cls):
		"""
		shutdown & delete SQLite database
		"""
		pass

	def setup_method(self, method):
		pass

	def teardown_method(self, method):
		pass

	def test_sqlite(self):
		pass

class TestCRUD:
	"""
	"""
	@pytest.mark.asyncio
	async def test_get(self):
		result = await db_classes[0]['test_database']['Album'].get(as_dict=True, AlbumId=1)
		assert result['Title'] == "For Those About To Rock We Salute You"

	@pytest.mark.asyncio
	async def test_update(self):
		result = await db_classes[0]['test_database']['Album'].get(as_dict=False, AlbumId=1)
		result = await result.update(as_dict=True, Title='Changed Title Update')
		assert result['Title'] == 'Changed Title Update'

	@pytest.mark.asyncio
	async def test_save(self):
		result = await db_classes[0]['test_database']['Album'].get(as_dict=False, AlbumId=1)
		result.Title = 'Changed Title Save'
		result = await result.save(as_dict=True)
		assert result['Title'] == 'Changed Title Save'

	@pytest.mark.asyncio
	async def test_delete(self):
		result = await db_classes[0]['test_database']['Album'].get(as_dict=False, AlbumId=1)
		await result.delete()
		record = await db_classes[0]['test_database']['Album'].get(as_dict=False, AlbumId=1)
		assert record is None

	@classmethod
	def teardown_class(cls):
		"""
		restore database record
		"""
		event_loop = asyncio.get_event_loop()
		result, created = event_loop.run_until_complete(get_or_create(0, 'test_database', db_classes[0]['test_database']['Album'], AlbumId=1, ArtistId=1, Title='For Those About To Rock We Salute You'))

class TestQueries:
	"""
	query
	get_or_create
	"""
	@pytest.mark.asyncio
	async def test_query(self):
		result = await query(0, 'test_database', "SELECT * FROM Album WHERE AlbumId=:id", parameters={'id': 5})
		assert result[0]['Title'] == "Big Ones"

	@pytest.mark.asyncio
	async def test_get_or_create(self):
		result, created = await get_or_create(0, 'test_database', db_classes[0]['test_database']['Album'], AlbumId=5)
		assert created == False

class TestSecurity:
	"""
	test for SQL injection
	"""
	pass

class TestJWT:
	"""
	"""
	def test_firebase_claims(self):
		token = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjNlNTQyN2NkMzUxMDhiNDc2NjUyMDhlYTA0YjhjYTZjODZkMDljOTMiLCJ0eXAiOiJKV1QifQ.eyJkaXNwbGF5TmFtZSI6Ikpvc2ggUmVldmVzIiwiZW1haWwiOiJhZG1pbkBvbmVwcmVzcy5hcHAiLCJvcmdhbml6YXRpb25zIjpbMzddLCJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vb25lcHJlc3MtMjc3NzE1IiwiYXVkIjoib25lcHJlc3MtMjc3NzE1IiwiYXV0aF90aW1lIjoxNjA1MDQ2NTM4LCJ1c2VyX2lkIjoiNDQyOTM5ODAzMjYiLCJzdWIiOiI0NDI5Mzk4MDMyNiIsImlhdCI6MTYwNjE3NjU4MiwiZXhwIjoxNjA2MTgwMTgyLCJmaXJlYmFzZSI6eyJpZGVudGl0aWVzIjp7fSwic2lnbl9pbl9wcm92aWRlciI6ImN1c3RvbSJ9fQ.uSxLsOxHGrwj9d3kUl5cWuIERp5NsOxC4-txyIGqv6-FNnbnylnM_IarkZ9SIWoHCh-r05QQJe38cBUzU_c326b4YwgPToKsCekhs8LOs3HNGzzWePXoP2qwpHR_ePUFymyolbsIZNhNv8twZhUj3hhjMNUlCz8whRRD_vScIXEWfXMKAW2GYLH3K0528sz6U4KgAAdat7jCV1wcrnIBdaTWkjSZmHZmj6r05Kgbwjcf30hwAyiZNCIM-xbeeRBmfEDjWmLSQoI5_f09ZggFCEJ7E4lhRMyLoMjFLzISl1l_x2HvRpsJrfsWAGIRVFGK2xE0YRUHm3vQP5ghclMjSQ' # copy from login to app.summation.app
		audience = 'onepress-277715'
		claims = JWTVerifier.create('firebase', token=token, audience=audience).get_token_claims()
		logger.debug(claims)
		assert claims['sub'] == '44293980326'

	def test_firebase_token_validity(self):
		token = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjNlNTQyN2NkMzUxMDhiNDc2NjUyMDhlYTA0YjhjYTZjODZkMDljOTMiLCJ0eXAiOiJKV1QifQ.eyJkaXNwbGF5TmFtZSI6Ikpvc2ggUmVldmVzIiwiZW1haWwiOiJhZG1pbkBvbmVwcmVzcy5hcHAiLCJvcmdhbml6YXRpb25zIjpbMzddLCJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vb25lcHJlc3MtMjc3NzE1IiwiYXVkIjoib25lcHJlc3MtMjc3NzE1IiwiYXV0aF90aW1lIjoxNjA1MDQ2NTM4LCJ1c2VyX2lkIjoiNDQyOTM5ODAzMjYiLCJzdWIiOiI0NDI5Mzk4MDMyNiIsImlhdCI6MTYwNjE3NjU4MiwiZXhwIjoxNjA2MTgwMTgyLCJmaXJlYmFzZSI6eyJpZGVudGl0aWVzIjp7fSwic2lnbl9pbl9wcm92aWRlciI6ImN1c3RvbSJ9fQ.uSxLsOxHGrwj9d3kUl5cWuIERp5NsOxC4-txyIGqv6-FNnbnylnM_IarkZ9SIWoHCh-r05QQJe38cBUzU_c326b4YwgPToKsCekhs8LOs3HNGzzWePXoP2qwpHR_ePUFymyolbsIZNhNv8twZhUj3hhjMNUlCz8whRRD_vScIXEWfXMKAW2GYLH3K0528sz6U4KgAAdat7jCV1wcrnIBdaTWkjSZmHZmj6r05Kgbwjcf30hwAyiZNCIM-xbeeRBmfEDjWmLSQoI5_f09ZggFCEJ7E4lhRMyLoMjFLzISl1l_x2HvRpsJrfsWAGIRVFGK2xE0YRUHm3vQP5ghclMjSQ' # copy from login to app.summation.app
		try:
			claims = JWTVerifier.create('firebase', token=token).verify_token()
		except ExpiredTokenError as e:
			assert e.description == 'expired_token: The token is expired'

	def test_okta_claims(self):
		token = 'eyJraWQiOiI1WjlaRlowdng2REFJbEJWbkRpZFNjcGNSMWJhT2FONDRaOTJLTEJaZ19RIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiIwMHViaHpwOEdXTzBXMHM1QjVkNSIsIm5hbWUiOiJKb3NoIFJlZXZlcyIsImVtYWlsIjoiYWRtaW5Ac3VtbWF0aW9uLmFwcCIsInZlciI6MSwiaXNzIjoiaHR0cHM6Ly9kZXYtMTQ1ODgwOS5va3RhLmNvbS9vYXV0aDIvZGVmYXVsdCIsImF1ZCI6IjBvYWJoenEzMERJcmFHUWFDNWQ1IiwiaWF0IjoxNjAyOTgzMzIzLCJleHAiOjE2MDI5ODY5MjMsImp0aSI6IklELlVVNjNSQmkyVUVGVXhDMzU3LU1WZUtLR0JQeGRxdVZveFdmVU9aTU1zVFkiLCJhbXIiOlsicHdkIl0sImlkcCI6IjAwb2JoemxncDNKMzF3YnZrNWQ1Iiwibm9uY2UiOiJBenNHWmZZcGN0bFp3QW4yVlpMcTl0UzByZ05xM2RzRTZERk12Z3I5c2NZaENwb2NoR3F5OUozTVBaT044SzVTIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWRtaW5Ac3VtbWF0aW9uLmFwcCIsImF1dGhfdGltZSI6MTYwMjk4MjUxNywiYXRfaGFzaCI6IkpYcThYbzJrcmU1NWNBeExVVWJyNHcifQ.Q4rYnsJgPdUGd-DSC3P3aAJFVQ2hAZrHyv2h0Fo1MLl7KD82DIZlbiw7SDYpnH3kIs_tZjY5kaugHtajwYITEbhQqTgPFelV4EkvfS2_AXt7qWRuOMr7BbhV5fa8p6mZYfqAAI29UAKHz7zX_wILL_XPQQifXAJY2HsSKagN0J41yaKtCMdgUoQ5ruYXki-Ui9j0Y8kCwnMmIA7-839Und10GWPtBoSxPJ3ETI6jzOBSUuHqP2YW_5OdFtzaWTgmO86gENZcNUSa5wAO986KMvfLV4v3KTx3nQKr5Y9_SUG5C-Do2CggRspsgLgqW0xQLDtlXf6YN00_g99QanofZg'
		domain = 'dev-1458809.okta.com'
		client_id = '0oabhzq30DIraGQaC5d5'
		claims = JWTVerifier.create('okta', token=token, domain=domain, client_id=client_id).get_token_claims()
		assert claims['sub'] == '00ubhzp8GWO0W0s5B5d5'

	def test_okta_token_validity(self):
		token = 'eyJraWQiOiI1WjlaRlowdng2REFJbEJWbkRpZFNjcGNSMWJhT2FONDRaOTJLTEJaZ19RIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiIwMHViaHpwOEdXTzBXMHM1QjVkNSIsIm5hbWUiOiJKb3NoIFJlZXZlcyIsImVtYWlsIjoiYWRtaW5Ac3VtbWF0aW9uLmFwcCIsInZlciI6MSwiaXNzIjoiaHR0cHM6Ly9kZXYtMTQ1ODgwOS5va3RhLmNvbS9vYXV0aDIvZGVmYXVsdCIsImF1ZCI6IjBvYWJoenEzMERJcmFHUWFDNWQ1IiwiaWF0IjoxNjAyOTgzMzIzLCJleHAiOjE2MDI5ODY5MjMsImp0aSI6IklELlVVNjNSQmkyVUVGVXhDMzU3LU1WZUtLR0JQeGRxdVZveFdmVU9aTU1zVFkiLCJhbXIiOlsicHdkIl0sImlkcCI6IjAwb2JoemxncDNKMzF3YnZrNWQ1Iiwibm9uY2UiOiJBenNHWmZZcGN0bFp3QW4yVlpMcTl0UzByZ05xM2RzRTZERk12Z3I5c2NZaENwb2NoR3F5OUozTVBaT044SzVTIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWRtaW5Ac3VtbWF0aW9uLmFwcCIsImF1dGhfdGltZSI6MTYwMjk4MjUxNywiYXRfaGFzaCI6IkpYcThYbzJrcmU1NWNBeExVVWJyNHcifQ.Q4rYnsJgPdUGd-DSC3P3aAJFVQ2hAZrHyv2h0Fo1MLl7KD82DIZlbiw7SDYpnH3kIs_tZjY5kaugHtajwYITEbhQqTgPFelV4EkvfS2_AXt7qWRuOMr7BbhV5fa8p6mZYfqAAI29UAKHz7zX_wILL_XPQQifXAJY2HsSKagN0J41yaKtCMdgUoQ5ruYXki-Ui9j0Y8kCwnMmIA7-839Und10GWPtBoSxPJ3ETI6jzOBSUuHqP2YW_5OdFtzaWTgmO86gENZcNUSa5wAO986KMvfLV4v3KTx3nQKr5Y9_SUG5C-Do2CggRspsgLgqW0xQLDtlXf6YN00_g99QanofZg'
		domain = 'dev-1458809.okta.com'
		client_id = '0oabhzq30DIraGQaC5d5'
		try:
			claims = JWTVerifier.create('okta', token=token, domain=domain, client_id=client_id).verify_token()
		except ExpiredTokenError as e:
			assert e.description == 'expired_token: The token is expired'

	def test_cognito_claims(self):
		token = 'eyJraWQiOiJHSXVEQlpHYzF2ejlFdytxaXE4dVJweWlhZXh2bFBDMlJ4Q29uYUFWaWZNPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJmYjA1YjUxOC0wMTVlLTRjZGItYmQwMC1mODY0MzdlZmU2YTkiLCJhdWQiOiI2ZWoxZjFtcjl0bXM4aWhtaDdoOGc0Z2FnOCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJldmVudF9pZCI6IjRlZTJhZThkLTk4MWEtNDRiNC04MjNmLTI3ZTcyMWYxMGFiNyIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNjAyOTgyMjI5LCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtd2VzdC0yLmFtYXpvbmF3cy5jb21cL3VzLXdlc3QtMl9MRXluajM0NDkiLCJjb2duaXRvOnVzZXJuYW1lIjoidGVzdF91c2VyIiwiZXhwIjoxNjAyOTg1ODI5LCJpYXQiOjE2MDI5ODIyMjksImVtYWlsIjoic2t1bmt3ZXJrQGdtYWlsLmNvbSJ9.g4NOkaDr_8Lg1P_XoJ4ekaZX4lZRL7xAaKdBsRnFshrqKwVo628YY3vRrw3N6q8CpiUFFO_1LMRa0HA-DmCVIrPLSip9bR-u7Us6TYgF6fezDGPyxZZ1bMCxcJsqTjXw3gK-W4Uq7TY7JboGLJX1y39EeeJuSPXlZCQB3OXf0wGibVyvhwybb_MuDqlOjvk7qbWdi4UMHDhIb6PhzJcxX6_dq7D0s1MntVAdeAYyH6XlAcVfNR7V-zvofQYw2oV3I6MWsalPs9L8hiYMMsdsqWjpkdKzFAIyFekS_5pVGO7KvVcbyd4BP1avuYy0t0A2OyDWnWn9lNco-9BYMJ34uA'
		region = 'us-west-2'
		user_pool_id = 'us-west-2_LEynj3449'
		client_id = '6ej1f1mr9tms8ihmh7h8g4gag8' # AUDIENCE
		claims = JWTVerifier.create('cognito', token=token, region=region, user_pool_id=user_pool_id).get_token_claims()
		assert claims['sub'] == 'fb05b518-015e-4cdb-bd00-f86437efe6a9'

	def test_cognito_token_validity(self):
		token = 'eyJraWQiOiJHSXVEQlpHYzF2ejlFdytxaXE4dVJweWlhZXh2bFBDMlJ4Q29uYUFWaWZNPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJmYjA1YjUxOC0wMTVlLTRjZGItYmQwMC1mODY0MzdlZmU2YTkiLCJhdWQiOiI2ZWoxZjFtcjl0bXM4aWhtaDdoOGc0Z2FnOCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJldmVudF9pZCI6IjRlZTJhZThkLTk4MWEtNDRiNC04MjNmLTI3ZTcyMWYxMGFiNyIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNjAyOTgyMjI5LCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtd2VzdC0yLmFtYXpvbmF3cy5jb21cL3VzLXdlc3QtMl9MRXluajM0NDkiLCJjb2duaXRvOnVzZXJuYW1lIjoidGVzdF91c2VyIiwiZXhwIjoxNjAyOTg1ODI5LCJpYXQiOjE2MDI5ODIyMjksImVtYWlsIjoic2t1bmt3ZXJrQGdtYWlsLmNvbSJ9.g4NOkaDr_8Lg1P_XoJ4ekaZX4lZRL7xAaKdBsRnFshrqKwVo628YY3vRrw3N6q8CpiUFFO_1LMRa0HA-DmCVIrPLSip9bR-u7Us6TYgF6fezDGPyxZZ1bMCxcJsqTjXw3gK-W4Uq7TY7JboGLJX1y39EeeJuSPXlZCQB3OXf0wGibVyvhwybb_MuDqlOjvk7qbWdi4UMHDhIb6PhzJcxX6_dq7D0s1MntVAdeAYyH6XlAcVfNR7V-zvofQYw2oV3I6MWsalPs9L8hiYMMsdsqWjpkdKzFAIyFekS_5pVGO7KvVcbyd4BP1avuYy0t0A2OyDWnWn9lNco-9BYMJ34uA'
		region = 'us-west-2'
		user_pool_id = 'us-west-2_LEynj3449'
		client_id = '6ej1f1mr9tms8ihmh7h8g4gag8' # AUDIENCE
		try:
			claims = JWTVerifier.create('cognito', token=token, region=region, user_pool_id=user_pool_id).verify_token()
		except ExpiredTokenError as e:
			assert e.description == 'expired_token: The token is expired'

	def test_auth0_claims(self):
		token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjFxcDRxNXllVTJzeVVCRWFDLXowSyJ9.eyJuaWNrbmFtZSI6InRlc3QiLCJuYW1lIjoidGVzdEBnbWFpbC5jb20iLCJwaWN0dXJlIjoiaHR0cHM6Ly9zLmdyYXZhdGFyLmNvbS9hdmF0YXIvMWFlZGI4ZDlkYzQ3NTFlMjI5YTMzNWUzNzFkYjgwNTg_cz00ODAmcj1wZyZkPWh0dHBzJTNBJTJGJTJGY2RuLmF1dGgwLmNvbSUyRmF2YXRhcnMlMkZ0ZS5wbmciLCJ1cGRhdGVkX2F0IjoiMjAyMC0xMC0xN1QyMTo1Mjo0NS40MTZaIiwiZW1haWwiOiJ0ZXN0QGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiaXNzIjoiaHR0cHM6Ly9kZXYtNjAyMmxoNHYudXMuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDVmODhiOGRjNGZmYWMzMDA2ZjJjM2JhZiIsImF1ZCI6IjhzbFdLamc0NVhITVVlQUlUSnFEZ3NRb3E2RWJNaVdEIiwiaWF0IjoxNjAyOTcxNTY1LCJleHAiOjE2MDMwMDc1NjV9.QAZVhTyjtsulU76OPBUGDsvWGgOpYnvISO3e3da7JSRZirAVke8NsiED6zYctpUvkO-mwCSqNZnVl9749OvdTZyAnMckoFX7ZhmtTrbRsG4fOkLBg58YHqWYBjCWlo6OTo9EtLDtYol3fFud_IcCWNeUYp8S-yOjZJG7mQDqXcdV76qLk-qrffUb9lfUfVq_zJWV0xy3PHL9ZvvE0e2OGOmldP8AwjEdh7l8XI_JlSsbMv25QNsTgZztl41zkSwodnNhkYk7MiO79svRznNKHtTj3ELtlys4b0lwT1ARkITOnmmbQLIV3DR0Q8wIEO3EpxrVaYew8WJBmDQV7pV06Q"
		domain = 'dev-6022lh4v.us.auth0.com'
		client_id='8slWKjg45XHMUeAITJqDgsQoq6EbMiWD'
		claims = JWTVerifier.create('auth0', token=token, domain=domain, client_id=client_id).get_token_claims()
		assert claims['sub'] == 'auth0|5f88b8dc4ffac3006f2c3baf'

	def test_auth0_token_validity(self):
		token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjFxcDRxNXllVTJzeVVCRWFDLXowSyJ9.eyJuaWNrbmFtZSI6InRlc3QiLCJuYW1lIjoidGVzdEBnbWFpbC5jb20iLCJwaWN0dXJlIjoiaHR0cHM6Ly9zLmdyYXZhdGFyLmNvbS9hdmF0YXIvMWFlZGI4ZDlkYzQ3NTFlMjI5YTMzNWUzNzFkYjgwNTg_cz00ODAmcj1wZyZkPWh0dHBzJTNBJTJGJTJGY2RuLmF1dGgwLmNvbSUyRmF2YXRhcnMlMkZ0ZS5wbmciLCJ1cGRhdGVkX2F0IjoiMjAyMC0xMC0xN1QyMTo1Mjo0NS40MTZaIiwiZW1haWwiOiJ0ZXN0QGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiaXNzIjoiaHR0cHM6Ly9kZXYtNjAyMmxoNHYudXMuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDVmODhiOGRjNGZmYWMzMDA2ZjJjM2JhZiIsImF1ZCI6IjhzbFdLamc0NVhITVVlQUlUSnFEZ3NRb3E2RWJNaVdEIiwiaWF0IjoxNjAyOTcxNTY1LCJleHAiOjE2MDMwMDc1NjV9.QAZVhTyjtsulU76OPBUGDsvWGgOpYnvISO3e3da7JSRZirAVke8NsiED6zYctpUvkO-mwCSqNZnVl9749OvdTZyAnMckoFX7ZhmtTrbRsG4fOkLBg58YHqWYBjCWlo6OTo9EtLDtYol3fFud_IcCWNeUYp8S-yOjZJG7mQDqXcdV76qLk-qrffUb9lfUfVq_zJWV0xy3PHL9ZvvE0e2OGOmldP8AwjEdh7l8XI_JlSsbMv25QNsTgZztl41zkSwodnNhkYk7MiO79svRznNKHtTj3ELtlys4b0lwT1ARkITOnmmbQLIV3DR0Q8wIEO3EpxrVaYew8WJBmDQV7pV06Q"
		domain = 'dev-6022lh4v.us.auth0.com'
		client_id='8slWKjg45XHMUeAITJqDgsQoq6EbMiWD'
		try:
			claims = JWTVerifier.create('auth0', token=token, domain=domain, client_id=client_id).verify_token()
		except ExpiredTokenError as e:
			assert e.description == 'expired_token: The token is expired'

class TestAPIs:

	@classmethod
	def setup_class(cls):
		"""
		start the test server
		have to pass it the virtualenv version of python with dependencies installed
		"""
		pass

	@classmethod
	def teardown_class(cls):
		"""
		shutdown test server
		"""
		pass

	def setup_method(self, method):
		pass

	def teardown_method(self, method):
		pass

	@pytest.mark.asyncio
	async def test_get(self):
		"""
		todo: call proxy_request
		"""
		result, status_code = await proxy_request('GET', "http://127.0.0.1:8000/get", {}, None, {}, {})
		assert result == True

	@pytest.mark.asyncio
	async def test_post(self):
		result, status_code = await proxy_request('POST', "http://127.0.0.1:8000/post", {}, None, {}, {})
		assert result == True

	@pytest.mark.asyncio
	async def test_put(self):
		result, status_code = await proxy_request('PUT', "http://127.0.0.1:8000/put", {}, None, {}, {})
		assert result == True

	@pytest.mark.asyncio
	async def test_patch(self):
		result, status_code = await proxy_request('PATCH', "http://127.0.0.1:8000/patch", {}, None, {}, {})
		assert result == True

	@pytest.mark.asyncio
	async def test_delete(self):
		result, status_code = await proxy_request('DELETE', "http://127.0.0.1:8000/delete", {}, None, {}, {})
		assert result == True

	@pytest.mark.asyncio
	async def test_basic_auth(self):
		"""
		"""
		user_pass = 'TEST_USER:TEST_KEY'
		encoded_user_pass = base64.b64encode(user_pass.encode('ascii'))
		api_headers = {'Authorization': 'Basic ' + encoded_user_pass.decode('ascii')}
		api_url, headers, parameters, auth = prepare_authentication({}, 'development', None, None, 'http://localhost:8000', {}, {}, {})
		parameters, headers = await bind_params(0, 'summation', {}, 'development', {}, headers=headers)
		url, headers, parameters, data = merge_request_data_with_parent_api(headers, {}, {}, 'http://localhost:8000/basic_auth', api_headers, 'http://localhost:8000', {})
		result, status_code = await proxy_request('POST', url, headers, auth, parameters, data)
		assert result == True

	@pytest.mark.asyncio
	async def test_bearer_token(self):
		"""
		"""
		api_headers = {'Authorization': 'Bearer ' + 'TEST_KEY'}
		api_url, headers, parameters, auth = prepare_authentication({}, 'development', None, None, 'http://localhost:8000', {}, {}, {})
		parameters, headers = await bind_params(0, 'summation', {}, 'development', {}, headers=headers)
		url, headers, parameters, data = merge_request_data_with_parent_api(headers, {}, {}, 'http://localhost:8000/bearer_token', api_headers, 'http://localhost:8000', {})
		result, status_code = await proxy_request('POST', url, headers, auth, parameters, data)
		assert result == True

	@pytest.mark.asyncio
	async def test_api_key_headers(self):
		"""
		"""
		api_headers = {'key': 'TEST_KEY'}
		api_url, headers, parameters, auth = prepare_authentication({}, 'development', None, None, 'http://localhost:8000', {}, {}, {})
		parameters, headers = await bind_params(0, 'summation', {}, 'development', {}, headers=headers)
		url, headers, parameters, data = merge_request_data_with_parent_api(headers, {}, {}, 'http://localhost:8000/api_key_headers_auth', api_headers, 'http://localhost:8000', {})
		result, status_code = await proxy_request('POST', url, headers, auth, parameters, data)
		assert result == True

	@pytest.mark.asyncio
	async def test_api_key_parameters(self):
		"""
		"""
		api_url, headers, parameters, auth = prepare_authentication({}, 'development', 'TEST_KEY', 'TEST_KEY', 'http://localhost:8000', {}, {}, {})
		parameters, headers = await bind_params(0, 'summation', {}, 'development', {}, headers={})
		url, headers, parameters, data = merge_request_data_with_parent_api(headers, {}, {}, 'http://localhost:8000/api_key_parameters_auth', {}, 'http://localhost:8000/?key=TEST_KEY', {})
		result, status_code = await proxy_request('GET', url, headers, auth, parameters, data)
		assert result == True

"""
async test_chain()
    {
      var sql = "SELECT * FROM settings LIMIT 1"
      var parameters = {};
      var database_name = 'summation';
      var headers = {'test': "_0[0]['key']"};
      var url = 'http://api.ipapi.com/98.33.28.214'
      console.log(await this.gw.chain.query(sql, parameters, database_name).get(url, parameters, headers).run());
    },
"""