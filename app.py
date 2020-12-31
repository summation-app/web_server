import os
import logging
import typing
from datetime import datetime, timezone, timedelta
import functools
import json
import uuid
import os.path
from asyncio import gather, create_task
import re
import urllib.parse
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlunparse
import time
from base64 import b64decode

from Cryptodome.PublicKey import RSA
from six.moves.urllib.parse import quote, unquote
from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse, Response, RedirectResponse
from starlette.background import BackgroundTask
from starlette.middleware import Middleware
from starlette.websockets import WebSocket
from starlette.endpoints import WebSocketEndpoint
from starlette.types import Message, Receive, Scope, Send
from starlette.requests import Request
from starlette.authentication import (
	AuthenticationBackend, AuthenticationError, SimpleUser, UnauthenticatedUser,
	AuthCredentials
)
from starlette.requests import Request
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.authentication import requires
from starlette_context import context, plugins
from starlette_context.middleware import RawContextMiddleware
from aiohttp import ClientSession
from aiohttp.helpers import BasicAuth

from db import *
from jwt_verifier import *
#from billing import *
from aiohttp import ClientSession, BasicAuth

ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
ENVIRONMENT = os.getenv('ENVIRONMENT', 'self_hosted') # 'self_hosted', 'cloud', 'test'
LOCAL_FILE_STORAGE_PATH = os.getenv('LOCAL_FILE_STORAGE_PATH')
url_regex = re.compile('(https?\:\/\/[a-zA-Z0-9\.-]*)\/?')
chain_regex = re.compile('^_\d')

logger = JSONLoggingAdapter(logging.getLogger(__name__))

async def startup():
	global session
	global log_server
	session = ClientSession()
	if ENVIRONMENT!='TEST':
		await connect_to_all_databases()
		generate_public_key_pair()
		await create_default_roles_apps()
		await setup_pgcrypto()
		if ENVIRONMENT=='self_hosted':
			log_server = LogServer(await Settings.get(organization_id=0, key='logging_env_vars'))
	else:
		logger.debug('skipping startup')

async def shutdown():
	await session.close()
	if ENVIRONMENT=='self_hosted':
		global log_server
		log_server.stop()

class User():
	def __init__(self, username, organization_id, billing_plan):
		self.username = username
		self.organization_id = organization_id
		self.billing_plan = billing_plan

class AuthBackend(AuthenticationBackend):
	"""
	authorization for the summation web app (not the gateway)
	uses JWT tokens in the header like:
	Authorization: Bearer token
	"""
	async def authenticate(self, request):
		if "Authorization" not in request.headers:
			logger.error('authorization key not in headers')
			return
		else:
			header_value = request.headers.get("Authorization")
			try:
				parts = header_value.split('Bearer ')
				if len(parts)>1:
					token = parts[1]
					token_info = await validate_token(token, 0, 0)
					if token_info['aud']!='summation': # self_hosted or cloud environments
						raise AuthenticationError('Invalid token - not issued by summation web app')
					organization_id = token_info['organization_id']
					uid = token_info['uid']
					billing_plan = None #TODO lookup
				else:
					raise AuthenticationError('Invalid Authorization Bearer in header')
			except Exception as e:
				raise AuthenticationError('Invalid Token')
		return AuthCredentials(["authenticated"]), User(uid, organization_id, billing_plan)

middleware = [
	Middleware(AuthenticationMiddleware, backend=AuthBackend()),
	Middleware(
		RawContextMiddleware,
		plugins=(
			plugins.RequestIdPlugin(),
			plugins.CorrelationIdPlugin(),
			plugins.ForwardedForPlugin(),
		)
	),
	Middleware(CORSMiddleware, allow_origins=['*'],allow_credentials=True,allow_methods=["*"],allow_headers=["*"])
]

app = Starlette(debug=True, middleware=middleware, on_startup=[startup], on_shutdown=[shutdown])

def request_validator_timer(func):
	@functools.wraps(func)
	async def wrapper_timer(*args, **kwargs):
		start_time = time.perf_counter()
		date = datetime.utcnow()
		request = args[0]
		organization_id, app_id = None, None
		context['start_time'] = start_time # duration will be added to context at the end of the function call itself, so it can also be logged
		if request.method=='POST':
			inputs = await request.json()
			gateway_token = inputs.get('gateway_token')
			organization_id, app_id = await validate_gateway_token(gateway_token)
			kwargs['organization_id'] = organization_id
			kwargs['app_id'] = app_id
			context['organization_id'] = organization_id
		value = await func(*args, **kwargs)
		status_code = None
		if isinstance(value, JSONResponse):
			status_code = value.status_code
		context['duration'] = round(time.perf_counter() - context['start_time'], 3)
		context['function_name'] = func.__name__
		logger.debug('request completed')
		# create_task to store metrics in database
		asyncio.create_task(save_metrics(date=date, duration=context.get('duration'), organization_id=organization_id, app_id=app_id, event_type=func.__name__, status_code=status_code)) # don't wait for it to finish
		return value
	return wrapper_timer

async def save_metrics(date, duration, organization_id, app_id, event_type, status_code):
	"""
	save timing & response code metrics to database
	"""
	try:
		await Events(organization_id=organization_id, application_id=app_id, date=date, duration_milliseconds=duration*1000, event_type=event_type, status_code=status_code).save()
	except Exception as e:
		logger.error(e, exc_info=True)

@app.route('/login', methods=['GET'])
async def login(request):
	"""
	login from the admin portal
	return the gateway_token for use in the summation JS client
	organization_id=0 for summation itself
	"""
	try:
		logger.debug('login')
		header = request.headers.get('Authorization')
		if header:
			split = header.strip().split(' ')

			# If split is only one element, try to decode the username and password
			# directly.
			if len(split) == 1:
				try:
					username, password = b64decode(split[0]).decode().split(':', 1)
				except:
					return JSONResponse(True, status_code=401)

			# If there are only two elements, check the first and ensure it says
			# 'basic' so that we know we're about to decode the right thing.
			elif len(split) == 2:
				if split[0].strip().lower() == 'basic':
					try:
						username, password = b64decode(split[1]).decode().split(':', 1)
					except:
						return JSONResponse(True, status_code=401)
				else:
					return JSONResponse(True, status_code=401)

			# If there are more than 2 elements, something crazy must be happening.
			else:
				return JSONResponse(True, status_code=401)

			username = unquote(username)
			password = unquote(password)
			if username=='admin' and password==ADMIN_PASSWORD:
				if settings := await Settings.get(key='gateway_token', organization_id=0, value={'scope': 'development'}):
					gateway_token = settings.value.get('key')
					jwt = generate_admin_jwt()
					return JSONResponse({'gateway_token': gateway_token, 'token': jwt}, status_code=200)
				else:
					logger.error('could not find gateway_token for organization_id 0')
					return JSONResponse(True, status_code=401)
			else:
				return JSONResponse(True, status_code=401)
		else:
			return JSONResponse(True, status_code=401)
	except Exception as e:
		logger.error(e, exc_info=True)
		return JSONResponse(True, status_code=401)

def generate_public_key_pair():
	"""
	"""
	try:
		# check if file exists
		if not os.path.exists(os.path.join(LOCAL_FILE_STORAGE_PATH, 'private_key.pem')):
			key = RSA.generate(2048)
			pv_key_string = key.exportKey()
			with open (os.path.join(LOCAL_FILE_STORAGE_PATH, 'private_key.pem'), "w") as prv_file:
				print("{}".format(pv_key_string.decode()), file=prv_file)

			pb_key_string = key.publickey().exportKey()
			with open (os.path.join(LOCAL_FILE_STORAGE_PATH, 'public_key.pem'), "w") as pub_file:
				print("{}".format(pb_key_string.decode()), file=pub_file)
		else:
			logger.debug('private key already exists - not creating')
	except Exception as e:
		logger.error(e, exc_info=True)

def generate_admin_jwt():
	"""
	keys generated as per: https://developers.yubico.com/PIV/Guides/Generating_keys_using_OpenSSL.html
	"""
	try:
		private_key = open(os.path.join(LOCAL_FILE_STORAGE_PATH, 'private_key.pem')).read()
		header = {'alg': 'RS256', 'typ': 'JWT'}
		payload = {'iss': 'summation', 'aud': 'summation', 'sub': 'admin', 'uid': 0, 'organization_id': 0, 'role_id': 0}
		s = authlib_jwt.encode(header, payload, private_key)
		return s.decode('ascii')
	except Exception as e:
		logger.error(e, exc_info=True)

@app.route('/databases', methods=['POST'])
@requires('authenticated')
async def get_databases(request):
	"""
	"""
	try:
		databases = []
		organization_id = request.user.organization_id
		if results := await Databases.filter(organization_id=organization_id).all():
			for result in results:
				databases.append({'engine': result.engine, 'url': result.url, 'port': result.port, 'username': result.username, 'database_name': result.database_name})
		return JSONResponse(databases, status_code=200)
	except Exception as e:
		logger.error(e, exc_info=True)

@app.route('/auth_method', methods=['GET','POST'])
@requires('authenticated')
async def auth_method(request):
	"""
	"""
	try:
		organization_id = request.user.organization_id
		if request.method=='GET':
			auth_method = None
			if results := await Settings.get(organization_id=organization_id, key='authentication_method'):
				auth_method = result.value
			return JSONResponse(auth_method, status_code=200)
		elif request.method=='POST':
			data = await request.json()
			values = data.get('values')
			setting, created = await get_or_create(0, 'summation', Settings, organization_id=organization_id, key='authentication_method')
			setting.value = values
			await setting.save()
			return JSONResponse(True, status_code=200)
	except Exception as e:
		logger.error(e, exc_info=True)


@app.route('/apis', methods=['POST'])
@requires('authenticated')
async def get_apis(request):
	"""
	"""
	try:
		apis = []
		organization_id = request.user.organization_id
		if results := await APIs.filter(organization_id=organization_id).all():
			for result in results:
				apis.append({'name': result.name, 'url': result.url, 'method': result.method, 'authentication': result.authentication})
		return JSONResponse(apis, status_code=200)
	except Exception as e:
		logger.error(e, exc_info=True)

@app.route('/logging', methods=['POST'])
@requires('authenticated')
async def get_logging_config(request):
	"""
	"""
	try:
		organization_id = request.user.organization_id
		logging_vendor, logging_config = None, None
		if results := await Settings.get(organization_id=organization_id, key='logging_config'):
			logging_config = results.value
		if results := await Settings.get(organization_id=organization_id, key='logging_vendor'):
			logging_vendor = results.value
		return JSONResponse({'logging_config': logging_config, 'logging_vendor': logging_vendor}, status_code=200)
	except Exception as e:
		logger.error(e, exc_info=True)

@app.route('/save_logging', methods=['POST'])
@requires('authenticated')
async def generate_vector_config(request):
	"""
	save the log settings to a vector config file
	then restart vector
	"""
	try:
		data = await request.json()
		logging_config = data.get('logging_config')
		destination = data.get('destination')
		settings = logging_config.get(destination)

		organization_id = request.user.organization_id

		env_vars = {}# for saving to the database

		# load default settings
		with open('vector_config.json') as json_file:
			config = json.load(json_file)
			config["sources"]["docker_logs"]["include"] = [LOCAL_FILE_LOG_PATH]

			if destination=='aws_cloudwatch':
				# https://vector.dev/docs/reference/sinks/aws_cloudwatch_logs/
				env_vars["AWS_ACCESS_KEY_ID"] = settings.get('aws_access_key_id')
				env_vars["AWS_SECRET_ACCESS_KEY"] = settings.get('aws_secret_access_key')
				
				config["sinks"][destination] = {
					"compression" : "none",
					"create_missing_group" : True,
					"create_missing_stream" : True,
					"encoding" : {
						"codec" : "json"
					},
					"group_name" : settings.get('log_group'),
					"healthcheck" : True,
					"inputs" : [
						"docker_logs"
					],
					"region" : settings.get("region","us-west-2"),
					"stream_name" : "{{ host }}",
					"type" : "aws_cloudwatch_logs"
				}

			elif destination=='gcp_stackdriver':
				# https://vector.dev/docs/reference/sinks/gcp_stackdriver_logs/
				# save credentials to a JSON file
				credentials_json = settings.get('credentials_json')
				with open(os.path.join(LOCAL_FILE_STORAGE_PATH, 'gcp_stackdriver_credentials.json'), 'w') as f:
					f.write(json.dumps(credentials_json))

				config["sinks"][destination] = {
					"credentials_path" : os.path.join(LOCAL_FILE_STORAGE_PATH, 'gcp_stackdriver_credentials.json'),
					"healthcheck" : True,
					"inputs" : [
						"docker_logs"
					],
					"log_id" : "summation_logs",
					"project_id" : settings.get('project_id'),
					"type" : "gcp_stackdriver_logs",
					"resource":
					{
						"type": "global"
					}
				}
			elif destination=='azure_monitor_logs':
				# https://vector.dev/docs/reference/sinks/azure_monitor_logs/
				config["sinks"][destination] = {
					"azure_resource_id" : settings.get('resource_id'),
					"customer_id" : settings.get('customer_id'),
					"healthcheck" : True,
					"host" : settings.get('host', "ods.opinsights.azure.com"),
					"inputs" : [
						"docker_logs"
					],
					"log_type" : "summation_logs",
					"shared_key" : settings.get('api_key'),
					"type" : "azure_monitor_logs"
				}
			elif destination=='splunk':
				# https://vector.dev/docs/reference/sinks/splunk_hec/
				config['sinks'][destination] = {
					"compression" : "none",
					"encoding" : {
						"codec" : "json"
					},
					"healthcheck" : True,
					"host_key" : settings.get('url'),
					"indexed_fields" : [],
					"inputs" : [
						"docker_logs"
					],
					"token" : settings.get('api_key'),
					"type" : "splunk_hec"
				}
			elif destination=='elasticsearch':
				# https://vector.dev/docs/reference/sinks/elasticsearch/
				config['sinks'][destination] = {
					"compression" : "none",
					"endpoint" : settings.get('url'),
					"healthcheck" : True,
					"index" : "vector-%F",
					"inputs" : [
						"docker_logs"
					],
					"auth":
					{
						"user": settings.get('username'),
						"password": settings.get('password'),
						"strategy": "basic"
					},
					"pipeline" : "summation_logs",
					"type" : "elasticsearch"
				}
			elif destination=='datadog':
				# https://vector.dev/docs/reference/sinks/datadog_logs/
				config['sinks'][destination] = {
					"api_key" : settings.get('api_key'),
					"compression" : "gzip",
					"encoding" : {
						"codec" : "json"
					},
					"healthcheck" : True,
					"inputs" : [
						"docker_logs"
					],
					"type" : "datadog_logs"
				}
			elif destination=='new_relic':
				# https://vector.dev/docs/reference/sinks/new_relic_logs/
				config['sinks'][destination] = {
					"compression" : "none",
					"healthcheck" : True,
					"inputs" : [
						"docker_logs"
					],
					"insert_key" : settings.get('insert_key'),
					"license_key" : settings.get('license_key'),
					"type" : "new_relic_logs"
				}
			elif destination=='kafka':
				# https://vector.dev/docs/reference/sinks/kafka/
				config['sinks'][destination] = {
					"bootstrap_servers" : settings.get('url'),
					"compression" : "none",
					"encoding" : {
						"codec" : "json"
					},
					"healthcheck" : True,
					"inputs" : [
						"docker_logs"
					],
					"key_field" : "user_id",
					"topic" : "summation_logs",
					"type" : "kafka"
				}
			elif destination=='http':
				# https://vector.dev/docs/reference/sinks/http/
				config['sinks'][destination] = {
					"batch" : {
						"max_bytes" : 1049000,
						"timeout_secs" : 1
					},
					"compression" : "none",
					"encoding" : {
						"codec" : "json"
					},
					"healthcheck" : True,
					"inputs" : [
						"docker_logs"
					],
					"type" : "http",
					"uri" : settings.get('url')
				}
		with open(os.path.join(LOCAL_FILE_STORAGE_PATH, 'vector_config.json'), 'w') as f:
			f.write(json.dumps(config))

		# save to database
		settings, created = await get_or_create(0, 'summation', Settings, organization_id=organization_id, key='logging_config')
		settings.value = logging_config
		await settings.save()

		settings, created = await get_or_create(0, 'summation', Settings, organization_id=organization_id, key='logging_env_vars')
		settings.value = env_vars
		await settings.save()

		settings, created = await get_or_create(0, 'summation', Settings, organization_id=organization_id, key='logging_vendor')
		settings.value = destination
		await settings.save()

		result = True
		if ENVIRONMENT=='self_hosted':
			result = log_server.restart()

		return JSONResponse(result)
	except Exception as e:
		logger.error(e, exc_info=True)

@app.route('/generate_gateway_tokens_for_new_app', methods=['POST'])
@requires('authenticated')
async def generate_gateway_tokens_for_new_app(request):
	"""
	"""
	try:
		data = await request.json()
		organization_id = request.user.organization_id
		name = data.get('name')

		app, created = await get_or_create(0, 'summation', Applications, organization_id=organization_id, name=name)
		tokens = await generate_gateway_tokens(organization_id, force=True, app_id=app.id)
		return JSONResponse({'dev_key': tokens['development'], 'prod_key': tokens['production']})
	except Exception as e:
		logger.error(e, exc_info=True)

async def create_default_roles_apps():
	"""
	app
	gateway_tokens for app
	roles for app
	"""
	try:
		app, created = await get_or_create(0, 'summation', Applications, id=0, organization_id=0, name='Summation')
		await generate_gateway_tokens(0, force=False, app_id=app.id)
		# roles
		roles = ['admins', 'users']
		for role in roles:
			role_row, created = await get_or_create(0, 'summation', Roles, organization_id=0, application_id=app.id, name=role, enabled=True)
		# create org_id 0 if not exists
		org_id, created = await get_or_create(0, 'summation', Organizations, id=0, name='summation')
		if created:
			org_id.date_created=datetime.utcnow()
			await org_id.save()
	except Exception as e:
		logger.error(e, exc_info=True)

async def setup_pgcrypto():
	"""
	PGP_SYM_ENCRYPT('John','AES_KEY')
	PGP_SYM_ENCRYPT('marco stuff', 'key')::text
	PGP_SYM_DECRYPT(name::bytea, 'AES_KEY')
	PGP_SYM_DECRYPT(column_name::bytea, 'key')
	"""
	try:
		results = await query(0, 'summation', "CREATE EXTENSION IF NOT EXISTS pgcrypto")
		logger.debug(results)
	except Exception as e:
		logger.error(e, exc_info=True)

async def generate_gateway_tokens(organization_id, force=True, app_id=None):
	"""
	generates new gateway token, unless Force=False in which case we use get_or_create

	should have different keys for every app
	so can see analytics broken out by app
	and can rotate one without impacting others
	"""
	try:
		tokens = {}
		for scope in ['development', 'production']:
			private_key = open(os.path.join(LOCAL_FILE_STORAGE_PATH, 'private_key.pem'),'rb').read()
			header = {'alg': 'RS256', 'typ': 'JWT'}
			payload = {'iss': 'summation', 'sub': 'admin', 'uid': 0, 'organization_id': organization_id, 'application_id': app_id, 'role_id': 0, 'scope': scope}
			current_time = datetime.now(timezone.utc)
			unix_timestamp = current_time.timestamp() # works if Python >= 3.3
			unix_timestamp_plus_20_years = int(unix_timestamp + (20 * 31556952)) # 20 * 31556952 seconds/year
			payload['exp'] = unix_timestamp_plus_20_years
			s = authlib_jwt.encode(header, payload, private_key)
			tokens[scope] = s.decode()
			if force:
				await Settings(organization_id=organization_id, application_id=app_id, key='gateway_token', value={'scope': scope, 'key': tokens[scope]}).save()
			else:
				if results := await query(0, 'summation', "SELECT * FROM settings WHERE organization_id=:organization_id AND application_id=:application_id AND key=:key", {'organization_id': organization_id, 'application_id': app_id, 'key': 'gateway_token'}):# TODO and value->scope==scope
					if len(results) < 2:
						settings, created = await get_or_create(0, 'summation', Settings, organization_id=organization_id, application_id=app_id, key='gateway_token', value={'scope': scope, 'key': tokens[scope]}) # TODO will always create new token
					else:
						logger.debug('gateway tokens already exist - not creating')
		return tokens
	except Exception as e:
		logger.error(e, exc_info=True)

@app.route("/add_api", methods=['POST'])
@requires('authenticated')
async def add_api(request):
	"""
	normally we could save directly to the database from the admin app,
	but because we need to encrypt credentials this has to be done server-side
	"""
	try:
		data = await request.json()
		method = data.get('method')
		url = data.get('url')
		body = data.get('body')
		header_key = data.get('header_key')
		production_key = data.get('production_key')
		development_key = data.get('development_key')
		authentication = data.get('authentication')
		bearer_token = data.get('bearer_token')
		basic_auth = data.get('basic_auth')

		organization_id = request.user.organization_id

		# parse data based on authentication method
		if auth_method := authentication.get('auth_method'):
			if auth_method=='API Key in Headers':
				headers = {header_key: '_KEY_'}
			elif auth_method=='API Key in URL parameters':
				pass
			elif auth_method=='Basic Auth':
				authentication['basic_auth'] = basic_auth # TODO for use in generating the BasicAuth hash when used
				if password_production := basic_auth.get('password_production'):
					production_key = password_production
				if password_development := basic_auth.get('password_development'):
					development_key = password_development
			elif auth_method=='Bearer Token':
				headers = {'Authentication': 'Bearer _KEY_'} # TODO have to replace this value
				if token := bearer_token.get('production'):
					production_key = token
				if token := bearer_token.get('development'):
					development_key = token

		sql = "INSERT INTO \"APIs\"(organization_id, method, url, body, headers, authentication, production_key, development_key) VALUES(:organization_id, :method, :url, :body, :headers, :authentication, PGP_SYM_ENCRYPT(:production_key, :admin_password)\:\:text, PGP_SYM_ENCRYPT(:development_key, :admin_password)\:\:text)"
		result = await query(0, 'summation', sql, {
			'organization_id': organization_id,
			'admin_password': ADMIN_PASSWORD, 
			'method': method,
			'url': url,
			'body': None,
			'headers': json.dumps(headers),
			'production_key': production_key,
			'development_key': development_key,
			'authentication': json.dumps(authentication)})
		logger.debug(result)
		return JSONResponse(True)
	except Exception as e:
		logger.error(e, exc_info=True)
		return JSONResponse(False)

@app.route("/add_database", methods=['POST'])
@requires('authenticated')
async def add_database(request):
	"""
	normally we could save directly to the database from the admin app,
	but because we need to encrypt credentials this has to be done server-side
	"""
	try:
		data = await request.json()
		engine = data.get('engine')
		url = data.get('url')
		port = data.get('port')
		username = data.get('username')
		password = data.get('password')
		database_name = data.get('database_name')
		schema = data.get('schema')
		name = data.get('name')

		organization_id = request.user.organization_id

		sql = "INSERT INTO databases (organization_id, engine, url, port, username, password, database_name, schema, name) VALUES(:organization_id, :engine, :url, :port, :username, PGP_SYM_ENCRYPT(:password, :admin_password)\:\:text, :database_name, :schema, :name) RETURNING id"
		database_record = {
			'organization_id': organization_id,
			'engine': engine,
			'url': url,
			'port': port,
			'username': username,
			'password': password,
			'admin_password': ADMIN_PASSWORD, 
			'database_name': database_name,
			'schema': schema,
			'name': name
		}
		result = await query(0, 'summation', sql, database_record)
		logger.debug(result)

		# attempt to connect to the database
		# and add it to the 'db_connections' dictionary
		database_record['id'] = result
		try:
			connection = connect_to_database(database_record)
		except Exception as e:
			return JSONResponse({'status': False, 'error': str(e)})
		return JSONResponse({'status': True})
	except Exception as e:
		logger.error(e, exc_info=True)
		return JSONResponse({'status': False, 'error': str(e)})

@app.route('/api', methods=['GET','POST'])
@request_validator_timer
async def api_gateway(request, organization_id, app_id):
	"""
	validate JWT
	get key from header, and check if development or production
	check if API is whitelisted & enabled
	for APIs, get the URL & credentials
	return the result to client

	all methods come in as POST, even if they're get, so that we can pass along the token without worrying about GET URL parameter length limits
	"""
	try:
		if request.method=='POST':
			inputs = await request.json()
			method = inputs.get('method')
			token = inputs.get('token')
			url = inputs.get('url')
			parameters = inputs.get('parameters')
			data = inputs.get('data')
			gateway_token = inputs.get('gateway_token')

			token_info = await validate_token(token, organization_id, app_id)
			role_id = token_info.get('role_id')
			user_id = token_info.get('uid')

			if settings := await Settings.get(organization_id=organization_id, key='gateway_token', value={'key': gateway_token}):
				scope = settings.value.get('scope')
				result, status = await api(scope, organization_id, method, url, data, role_id, parameters, token_info)
				return JSONResponse(result, status_code=status)
			else:
				logger.debug('no token info')
			return JSONResponse(None, status_code=500)
	except Exception as e:
		logger.error(e, exc_info=True)

async def api(scope, organization_id, method, url, data, role_id, parameters, jwt_claims, headers={}):
	"""
	"""
	try:
		if scope=='production':
			sql = "SELECT t1.*, PGP_SYM_DECRYPT(t2.production_key\:\:bytea, :admin_key) AS production_key, t2.authentication, t2.body, t2.headers, t2.url FROM summation.requests t1 INNER JOIN \"APIs\" t2 ON (t1.api_id=t2.id) WHERE t2.organization_id=:organization_id AND t1.method=:method AND t1.url=:url AND t2.role_id=:role_id"
			if request_results := await query(0, 'summation', sql, {'organization_id': organization_id, 'admin_key': ADMIN_PASSWORD, 'method': method, 'url': url, 'role_id': role_id}):
				request = request_results[0]
				auth = None
				request_url, headers, parameters, auth = prepare_authentication(request['authentication'], scope, request['production_key'], None, request['url'], headers, data, parameters)
				parameters, headers = await bind_params(organization_id, 'summation', parameters, scope, jwt_claims, headers=headers)
				url, headers, parameters, data = merge_request_data_with_parent_api(headers, parameters, data, url, request['headers'], request_url, request['body'])
				result = await proxy_request(method, url, headers, auth, parameters, data)
				return result
			else:
				logger.error('not authorized')
		elif scope=='development':
			# we can't extract authentication information directly from an API call,
			# as we don't know if it's in the header, body, what keys, etc.
			# so new APIs have to be created through the admin UI
			# here, all we can do is see if this API request matches the URL prefix of an already-added API
			# and if so, add it to the requests table
			# 					
			# overkill to use https://github.com/john-kurkowski/tldextract, as we only need the prefix before any third '/'
			regex_results = re.findall(url_regex, url)
			if regex_results:
				url_prefix = regex_results[0] + '%'
				logger.debug(url_prefix)
				logger.debug(f'organization_id: {organization_id}')
				# check if matches the URL prefix of any added API
				sql = "SELECT id, PGP_SYM_DECRYPT(production_key\:\:bytea, :admin_key) AS production_key, PGP_SYM_DECRYPT(development_key\:\:bytea, :admin_key) AS development_key, authentication, body, headers, url FROM \"APIs\" WHERE url LIKE :url AND organization_id=:organization_id"
				if api_match := await query(0, 'summation', sql, {'admin_key': ADMIN_PASSWORD, 'url': url_prefix, 'organization_id': organization_id}):
					api = api_match[0]
					# add full URL to requests table, link to apis.id
					record, created = await get_or_create(0, 'summation', Requests, role_id=role_id, method=method, url=url, api_id=api['id'])
					auth = None
					api_url, headers, parameters, auth = prepare_authentication(api['authentication'], scope, api['production_key'], api['development_key'], api['url'], headers, data, parameters)
					parameters, headers = await bind_params(organization_id, 'summation', parameters, scope, jwt_claims, headers=headers)
					url, headers, parameters, data = merge_request_data_with_parent_api(headers, parameters, data, url, api['headers'], api_url, api['body'])
					result = await proxy_request(method, url, headers, auth, parameters, data)
					return result
				else:
					logger.error("no matching API found - please add via summation admin app")
					return None, 500
			else:
				logger.error(f"could not extract URL prefix from: {url}")
				return None, 500
		else: # not authorized
			logger.error('not authorized')
			return None, 403
	except Exception as e:
		logger.error(e, exc_info=True)

def merge_request_data_with_parent_api(headers, parameters, data, url, api_headers, api_url, api_body):
	"""
	headers <-> api_headers
	data <-> api_body
	url & parameters <-> api_url
	"""
	try:
		logger.debug(f"merge with headers: {headers}, parameters: {parameters}, data: {data}, url: {url}, api_headers: {api_headers}, api_url: {api_url}, api_body: {api_body}")
		# parse both the url & the api_url
		# use the url from url, but merge query strings of api_url
		# then merge query strings with parameters dict if not empty
		parsed_api_url = urlparse(api_url)
		parsed_url = urlparse(url)
		api_url_query_string, url_query_string = None, None
		combined_query_strings, combined_parameters = {}, {}
		if parsed_api_url.query:
			api_url_query_string = parse_qs(parsed_api_url.query)
		if parsed_url.query:
			url_query_string = parse_qs(parsed_url.query)
		if api_url_query_string and url_query_string:
			combined_query_strings = {**api_url_query_string, **url_query_string}
		elif url_query_string:
			combined_query_strings = url_query_string
		elif api_url_query_string:
			combined_query_strings = api_url_query_string
		# flatten query strings dict
		flat_combined_query_strings = {}
		for key, val in combined_query_strings.items():
			if isinstance(val, list):
				flat_combined_query_strings[key] = val[0]
			else:
				flat_combined_query_strings[key] = val
		if parameters:
			combined_parameters = {**flat_combined_query_strings, **parameters}
		else:
			combined_parameters = flat_combined_query_strings
		combined_headers = headers
		combined_data = data
		if headers and api_headers:
			combined_headers = {**api_headers, **headers}
		elif api_headers:
			combined_headers = api_headers
		if api_body and data:
			combined_data = {**api_body, **data}
		parsed_url_list = list(parsed_url)
		parsed_url_list[4] = '' # set query to empty, as we've moved any query string to params
		url_without_query_string = urlunparse(parsed_url_list)
		return url_without_query_string, combined_headers, combined_parameters, combined_data
	except Exception as e:
		logger.error(e, exc_info=True)

async def validate_token(token, organization_id, app_id):
	"""
	open source version uses the built-in Authlib-issued JWT, uses organization_id=0
	cloud version uses JWT tokens issued by Firebase/Auth0, etc., uses organization_id>0
	TODO: cache this
	"""
	try:
		logger.debug(f"validating token: {token}")
		unverified_claims = jwt.decode(token, verify=False, algorithms=["HS256","RS256"]) # decode claims without validating
		if unverified_claims['iss']=='summation':
			claims = authlib_jwt.decode(token, open(os.path.join(LOCAL_FILE_STORAGE_PATH, 'public_key.pem'),'rb').read())
			claims.validate()
			# role_record = await Roles.get(name=role, enabled=True, organization_id=claims.get('organization_id'))
			# TODO: verify role exists in database for that org_id/app_id
		elif ENVIRONMENT=='cloud':
			# token for cloud version of summation issued by firebase
			claims = JWTVerifier.create('firebase', token=token).verify_token()
		else: # a token generated for app users, by the app itself
			# the gateway_token tells us which organization_id/app_id this is for
			if method := await Settings.get(key='authentication_method', application_id=app_id):
				if method.value.get('selected_auth_method')=='jwt':
					if vendor := method.value.get('selected_jwt_method'):
						# validate with app's choice of Firebase, Cognito, Okta, Auth0, etc. from settings
						parameters = method.value.get('jwt_parameters')
						claims = JWTVerifier.create(vendor, token=token, **parameters).verify_token()
						# if token doesn't contain a 'role', set the role to 'users' by default
						role_search_path = method.value.get('role_search_path')
						if claims.get('role'):
							pass
						elif not claims.get('role') and not role_search_path:
							claims['role'] = 'users'
						elif role_search_path:
							try:
								role = eval(role_search_path)
								claims['role'] = role
							except:
								logger.error(f"could not evaluate role_search_path on token: {token}")
						# if the role doesn't exist, create a record in the database for it
						row, created = get_or_create(0, 'summation', Roles, organization_id=organization_id, name=claims['role'], application_id=app_id, enabled=True)
						claims['role_id'] = row.id
				else:
					logger.error("unsupported auth method")
			else:
				logger.error(f"no authentication_method established for app_id: {app_id}")
		return claims
	except Exception as e:
		logger.error(e, exc_info=True)

async def validate_gateway_token(token):
	"""
	claims will include: organization_id, app_id
	"""
	try:
		logger.debug(f"validating gateway token: {token}")
		claims = authlib_jwt.decode(token, open(os.path.join(LOCAL_FILE_STORAGE_PATH, 'public_key.pem'),'rb').read())
		claims.validate()
		return claims.get('organization_id'), claims.get('application_id')
	except Exception as e:
		logger.error(e, exc_info=True)

@app.route('/database_tables_with_access_controls', methods=['POST'])
async def database_tables_with_access_controls(request):
	"""
	merge with any rules in the summation database
	for that database_id/table_name
	"""
	try:
		data = await request.json()
		token = data.get('token')
		organization_id = await validate_token(token).get('organization_id')
		role_id = data.get('role_id')
		results = {}
		databases = await Databases.filter(organization_id=organization_id)
		#databases = db_classes[organization_id].keys()
		list_permissions = ['create_permission', 'read_permission', 'update_permission', 'delete_permission']
		default_permissions = {key: None for key in list_permissions}
		results = {database.name: default_permissions for database in databases}
		for database in databases:
			results[database.name]['database_name'] = database.name
			results[database.name]['database_id'] = database.id
		
		for database in databases:
			list_tables = list(db_classes[organization_id][database.name].keys())
			sql = "SELECT t1.* FROM access_controls t1 INNER JOIN databases t2 ON (t1.database_id=t2.id) WHERE t1.scope='database' AND t2.name=:database AND t1.role_id=:role_id"
			rows = await query(organization_id, 'summation', sql, {'database': database.name, 'role_id': role_id})
			
			# merge the results
			rules_list = []
			rules = {table_name: default_permissions for table_name in list_tables}
			for row in rows or []:
				rules[row['table_name']] = {key: row.get(key) for key in list_permissions}
			for key, val in rules.items():
				name_dict = {'table_name': key}
				rules_list.append({**name_dict, **val}) # merge
			results[database.name]['table_data'] = rules_list
		return JSONResponse(list(results.values()))
	except Exception as e:
		logger.error(e, exc_info=True)

@app.websocket_route('/logs')
class WebSocketLogs(WebSocketEndpoint):
	def __init__(self, scope: Scope, receive: Receive, send: Send) -> None:
		super().__init__(scope, receive, send)

	async def on_connect(self, websocket: WebSocket) -> None:
		try:
			"""token = websocket.query_params.get('auth')
			if token:
				await websocket.accept()
			else:
				await websocket.close()"""
			await websocket.accept()
			await self.tail(websocket)
		except Exception as e:
			logger.error(e, exc_info=True)

	async def on_disconnect(self, websocket: WebSocket, close_code: int) -> None:
		try:
			logger.debug("disconnected")
		except Exception as e:
			logger.error(e, exc_info=True)

	async def on_receive(self, websocket: WebSocket, data: typing.Any) -> None:
		try:
			logger.debug(data)
			data = json.loads(data)
			#if data.get('event')=='send_message':
			#	await self.send_message(websocket, data)
		except Exception as e:
			logger.error(e, exc_info=True)
		
	async def send_message(self, websocket, message_data):
		try:
			websocket.send_json({'event': 'error', 'text': 'This group has 0 members subscribed to it - please join or invite others before sending a message.'})
		except Exception as e:
			logger.error(e, exc_info=True)

	async def tail(self, websocket):
		with open(LOCAL_FILE_LOG_PATH, 'rt') as file:
			seek = 0
			sleep_duration = None

			while True:
				file.seek(seek)
				line = file.readline()
				where = file.tell()

				if line:
					if seek != where:
						sleep_duration = None
						await websocket.send_json({'event': 'logs', 'data': line.strip()})
				else:
					sleep_duration = 0.05

				seek = where

				if sleep_duration:
					await asyncio.sleep(sleep_duration)

@app.route('/save_access_controls', methods=['POST'])
async def save_access_controls(request):
	try:
		data = await request.json()
		token = data.get('token')
		organization_id = validate_token(token).get('organization_id')
		role_id = data.get('role_id')
		controls = data.get('controls') # list of dictionaries
		for control in controls:
			# if the database-level controls are set, save it at a databse level (let the UI manage copying it to table-level)
			if control['create_permission'] or control['delete_permission'] or control['read_permission'] or control['update_permission']:
				record, created = await get_or_create(organization_id, control['database_name'], AccessControls, role_id=role_id, database_id=control['database_id'], table_name=None, scope='database')
				record.create_permission = control['create_permission']
				record.delete_permission = control['delete_permission']
				record.read_permission = control['read_permission']
				record.update_permission = control['update_permission']
				await record.save()
			table_controls = control['table_data']
			for table in table_controls: # list of dictionaries
				if table['create_permission'] or table['delete_permission'] or table['read_permission'] or table['update_permission']:
					record, created = await get_or_create(organization_id, control['database_name'], AccessControls, role_id=role_id, database_id=control['database_id'], table_name=table['table_name'])
					record.create_permission = table['create_permission']
					record.delete_permission = table['delete_permission']
					record.read_permission = table['read_permission']
					record.update_permission = table['update_permission']
					await record.save()
		return JSONResponse(True)
	except Exception as e:
		logger.error(e, exc_info=True)

def prepare_authentication(auth_settings, scope, production_key, development_key, url, headers, body, params):
	"""
	replace references to _KEY_ with the actual key in the URL & headers
	"""
	try:
		auth = None
		key = production_key
		if scope=='development':
			key = development_key or production_key
		if url and key and isinstance(url, str):
			url = re.sub('_KEY_', key, url)
		if headers and isinstance(headers, dict):
			for key in headers.keys():
				if headers[key]=='_KEY_':
					headers[key] = key
				elif isinstance(headers[key], str):
					headers[key] = re.sub('_KEY_', key, headers[key])
		if auth_settings and auth_settings.get('auth_method')=='Basic Auth':
			auth = BasicAuth(auth_settings.get('Basic Auth').get('username'), production_key)
		return url, headers, params, auth
	except Exception as e:
		logger.error(e, exc_info=True)

async def proxy_request(method, url, headers, auth, parameters, data):
	"""
	"""
	try:
		result = None
		global session
		if ENVIRONMENT=='TEST':
			session = ClientSession()
			logger.debug('IN PROXY REQUEST')
		if method=='GET':
			async with session.get(url, headers=headers, auth=auth, params=parameters) as resp:
				if resp.status==200:
					logger.debug(f"url: {url}, headers: {headers}, auth: {auth}, params: {parameters}, data: {data}")
					result = await resp.json()
				else:
					result = await resp.text()
					logger.error(result)
					logger.debug(f"url: {url}, headers: {headers}, auth: {auth}, params: {parameters}, data: {data}")
				return result, resp.status
		elif method=='POST':
			async with session.post(url, headers=headers, auth=auth, json=data) as resp:
				if resp.status==200:
					logger.debug(f"url: {url}, headers: {headers}, auth: {auth}, params: {parameters}, data: {data}")
					result = await resp.json()
				else:
					result = await resp.text()
					logger.error(result)
					logger.debug(f"url: {url}, headers: {headers}, auth: {auth}, params: {parameters}, data: {data}")
				return result, resp.status
		elif method=='PUT':
			async with session.put(url, headers=headers, auth=auth, json=data) as resp:
				if resp.status==200:
					logger.debug(f"url: {url}, headers: {headers}, auth: {auth}, params: {parameters}, data: {data}")
					result = await resp.json()
				else:
					result = await resp.text()
					logger.error(result)
					logger.debug(f"url: {url}, headers: {headers}, auth: {auth}, params: {parameters}, data: {data}")
				return result, resp.status
		elif method=='PATCH':
			async with session.patch(url, headers=headers, auth=auth, json=data) as resp:
				if resp.status==200:
					logger.debug(f"url: {url}, headers: {headers}, auth: {auth}, params: {parameters}, data: {data}")
					result = await resp.json()
				else:
					result = await resp.text()
					logger.error(result)
					logger.debug(f"url: {url}, headers: {headers}, auth: {auth}, params: {parameters}, data: {data}")
				return result, resp.status
		elif method=='DELETE':
			async with session.delete(url, headers=headers, auth=auth, json=data) as resp:
				if resp.status==200:
					logger.debug(f"url: {url}, headers: {headers}, auth: {auth}, params: {parameters}, data: {data}")
					result = await resp.json()
				else:
					result = await resp.text()
					logger.error(result)
					logger.debug(f"url: {url}, headers: {headers}, auth: {auth}, params: {parameters}, data: {data}")
				return result, resp.status
		else:
			logger.error('unknown method')
	except Exception as e:
		logger.error(e, exc_info=True)

@app.route('/database', methods=['GET','POST'])
@request_validator_timer
async def database_gateway(request, organization_id, app_id):
	"""
	validate JWT
	get key from header, and check if development or production
	check if API/query is whitelisted
	for APIs, get the URL & credentials
	return the result to client

	https://security.openstack.org/guidelines/dg_parameterize-database-queries.html
	"""
	try:
		if request.method=='POST':
			# to allow the webapp to use summation itself:
			# docker runs a shell command which:
			# creates random env variable
			# runs python & web app
			# or have 2 services, one that listens just on localhost, another for public

			inputs = await request.json()
			token = inputs.get('token')
			gateway_token = inputs.get('gateway_token')
			params = inputs.get('parameters')
			sql = inputs.get('sql')
			table = inputs.get('table','').capitalize() # class names are capitalized
			method = inputs.get('method')
			database_name = inputs.get('database_name')

			token_info = await validate_token(token, organization_id, app_id)
			role_id = token_info.get('role_id')

			settings = await Settings.get(key='gateway_token', value={'key': gateway_token})
			results = None
			if settings:
				scope = settings.value.get('scope')
				logger.debug(scope)

				if ENVIRONMENT=='cloud' and ((database_name=='summation' and scope=='development') or (database_name=='summation' and token_info.get('aud')!='summation')):
					# development tokens aren't allowed to query the summation database / add whitelisted queries in the cloud
					# only production tokens with whitelisted queries
					# end-users of applications also aren't allowed to query the summation database themselves
					return JSONResponse(None, status_code=403)

				params, headers = await bind_params(organization_id, 'summation', params, scope, token_info)
				if sql:
					if scope=='development':
						# save to queries table if not already there
						record, created = await get_or_create(organization_id, database_name, Queries, value=sql, enabled=True, role_id=role_id, organization_id=organization_id)
						# execute query
						results = await query(organization_id, database_name, sql, params)
					elif scope=='production':
						# check if in queries table
						if record := await Queries.get(value=sql, enabled=True, role_id=role_id, organization_id=organization_id):
							# if present, execute query
							results = await query(organization_id, database_name, sql, params)
						else:
							# else, return error
							logger.error(f"query is not in allow list, blocking")
							return JSONResponse(None, status_code=500)
				elif method and table:
					if scope=='development':
						# save to queries table if not already there
						record, created = await get_or_create(organization_id, database_name, Queries, table_name=table, method=method, parameters=list(params.keys()), enabled=True, role_id=role_id, organization_id=organization_id)
						# execute query
						return await execute_crud_query(method, table, params, organization_id, database_name)
					elif scope=='production':
						# check if in queries table
						if record := await Queries.get(table_name=table, method=method, parameters=list(params.keys()), enabled=True, role_id=role_id, organization_id=organization_id):
							# if present, execute query
							return await execute_crud_query(method, table, params, organization_id, database_name)
						else:
							# else, return error
							return JSONResponse(None, status_code=500)
				else:
					# missing params
					return JSONResponse(None, status_code=500)
			else:
				# gateway_token not valid
				return JSONResponse(None, status_code=500)
			return JSONResponse(results)
	except Exception as e:
		logger.error(e, exc_info=True)

async def execute_crud_query(method, table, params, organization_id, database_name):
	try:
		if database_name=='summation' and table in globals().keys():
			# for connecting to non-summation databases, don't import all classes
			# instead introspect tables, and add classes to a dict to avoid naming clashes
			table_class = globals()[table]
			get_method = getattr(table_class, 'get') # class method, not instance method
		else:
			table_class = db_classes.get(organization_id,{}).get(database_name,{}).get(table)
			if table_class:
				get_method = getattr(table_class, 'get') # class method, not instance method
			else:
				logger.error('no such database class found')
				return JSONResponse(None, status_code=500)
		if method=='create':
			results = await table_class(**params).save(as_dict=True)
			return JSONResponse(results)
		elif method=='read':
			results = await get_method(as_dict=True, **params)
			return JSONResponse(results)
		elif method=='update':
			# use primary key of table to lookup, then use other params to update
			# TODO how see in sqlalchemy primary key of class/table?
			# for now, assume 'id' is primary_key
			if params.get('id'):
				result = await get_method(id=params.get('id'))
				if result:
					params.pop('id')
					results = await result.update(as_dict=True, **params)
				else:
					logger.error('no matching record to update')
					return JSONResponse(None, status_code=500)
			else:
				logger.error('no ID in update query')
				return JSONResponse(None, status_code=500)
		elif method=='delete':
			result = await get_method(**params)
			if result:
				results = await result.delete()
			else:
				logger.error('could not find record to delete')
				return JSONResponse(None, status_code=500)
		elif method=='upsert':
			# use primary key of table to lookup, then use other params to update
			# TODO how see in sqlalchemy primary key of class/table?
			# for now, assume 'id' is primary_key
			if params.get('id'):
				result = await get_method(id=params.get('id'))
				if result:
					params.pop('id')
					results = await result.update(as_dict=True, **params)
				else:
					logger.error('no matching record to update, doing upsert')
					results = await table_class(**params).save(as_dict=True)
			else:
				logger.warning('ID not passed in, doing upsert')
				results = await table_class(**params).save(as_dict=True)
			return JSONResponse(results)
		else:
			logger.error('class name does not exist')
			return JSONResponse(None, status_code=500)
	except Exception as e:
		logger.error(e, exc_info=True)

@app.route('/chain', methods=['POST'])
@request_validator_timer
async def chain(request):
	"""
	run steps of the chain in series
	if any step fails, stop there and return
	add the results of previous step as inputs available to next step with prefix '_1', '_2', etc.
	each step may be database (query or CRUD) or an API request
	TODO: put into a DAG and run in parallel
	"""
	try:
		inputs = await request.json()
		token = inputs.get('token')
		gateway_token = inputs.get('gateway_token')
		default_database_name = inputs.get('default_database_name')
		queue = inputs.get('queue')

		organization_id, app_id = await validate_gateway_token(gateway_token)
		token_info = await validate_token(token, organization_id, app_id)
		role_id = token_info.get('role_id')

		settings = await Settings.get(key='gateway_token', value={'key': gateway_token})
		results = None
		if settings:
			scope = settings.value.get('scope')
			logger.debug(scope)
			if scope=='development':
				record, created = await get_or_create(0, 'summation', Chains, organization_id=organization_id, value=queue, role_id=role_id, enabled=True)
			elif scope=='production':
				record = await Chains.get(organization_id=organization_id, value=queue, role_id=role_id, enabled=True)
				if not record:
					logger.error(f"chain is not in allow list, blocking")
					return JSONResponse(None, status_code=500)
			all_results = {}
			for index, step in enumerate(queue):
				params, headers = await bind_params(organization_id, 'summation', step['parameters'], scope, token_info, headers=step.get('headers'), chain_results=all_results)
				if step['method']=='query':
					# database query method
					sql = step['sql']
					database_name = step['database_name']
					results = await query(organization_id, database_name, sql, params)
				elif step['method'] in ['upsert','update','read','create']:
					# CRUD methods
					table = step['table']
					database_name = step['database_name']
					results  = await execute_crud_query(step['method'], table, params, organization_id, database_name)
				elif step['method'] in ['GET','POST','PUT','PATCH']:
					# API methods
					url = step['url']
					data = step.get('data')
					results, status = await api(scope, organization_id, step['method'], url, data, role_id, params, token_info, headers)
				else:
					logger.error('unknown method in chain')
				all_results[f"_{index}"] = results # starts at index 0
			return JSONResponse(all_results)
	except Exception as e:
		logger.error(e, exc_info=True)

async def bind_params(organization_id, database_name, params, scope, jwt_claims, headers=None, chain_results=None):
	"""
	jwt.uid -> get uid from JWT token of logged-in user
	"""
	try:
		d = {'params': params, 'headers': headers}
		for name, dictionary in d.items():
			if dictionary:
				final_params = {}
				for key, val in dictionary.items():
					if isinstance(val, str) and val.find('jwt')==0:
						if scope=='development':
							# add the val to the database if it doesn't already exist
							record, created = await get_or_create(0, 'summation', Settings, organization_id=organization_id, key='jwt_param', string_value=val)
							try:
								jwt_val = eval(val, jwt_claims)
								if jwt_val:
									final_params[key] = jwt_val
								else:
									logger.warning(f"no JWT val for key: {val}") # OK in development, but don't fstring user-supplied {val} in production!
								jwt_claims.pop('__builtins__')
								# If the globals object is passed in, but doesn't specify __builtins__ key, 
								# then Python built-in functions and names are automatically added to the global scope
							except Exception as e:
								logger.error(e, exc_info=True)
						elif scope=='production':
							# check if in settings table
							if record := await Settings.get(organization_id=organization_id, key='jwt_param', string_value=val):
								try:
									jwt_val = eval(val, jwt_claims)
									if jwt_val:
										final_params[key] = jwt_val
									else:
										logger.warning("no JWT val for key") # don't fstring user-supplied {val} in production
									jwt_claims.pop('__builtins__')
									# If the globals object is passed in, but doesn't specify __builtins__ key, 
									# then Python built-in functions and names are automatically added to the global scope
								except Exception as e:
									logger.error(e, exc_info=True)
							else:
								logger.error("no JWT param listed in database")
					elif chain_results and re.findall(chain_regex, val):
						# replace the value with the result from previous steps of the chain
						# TODO check dev/prod allowance of 'val', as don't want to run arbitrary eval
						try:
							chain_val = eval(val, chain_results)
							if chain_val:
								final_params[key] = chain_val
							else:
								logger.warning(f"no chain val for key: {val}")
							# If the globals object is passed in, but doesn't specify __builtins__ key, 
							# then Python built-in functions and names are automatically added to the global scope
							chain_results.pop('__builtins__')
						except Exception as e:
							logger.error(e, exc_info=True)
					else:
						final_params[key] = val
				d[name] = final_params
		return d['params'], d['headers']
	except Exception as e:
		logger.error(e, exc_info=True)

async def get_settings(organization_id, keys=[]):
	"""
	"""
	try:
		settings = await Settings.filter(organization_id=organization_id, key__in=keys).all()
		return settings
	except Exception as e:
		logger.error(e, exc_info=True)

@app.route("/analytics", methods=['GET'])
@requires('authenticated')
async def analytics(request):
	"""
	summary analytics
	subscriber analytics
	messages analytics
	funnel analytics
	"""
	try:
		organization_id = request.user.organization_id
		duration = int(request.query_params.get('duration'))
		website_id = await get_website_id_of_organization(organization_id)
		if website_id:
			summary_stats = await get_analytics_summary(website_id, duration)
			protocol_stats = await get_protocol_stats(website_id, duration)
			#subscriber_stats = await get_subscriber_stats(website_id, duration)
			no_data = False
			if not summary_stats or not protocol_stats or summary_stats['impressions']==0:
				no_data = True # will display demo dashboard
			data = {'summary_stats': summary_stats, 'protocol_stats': protocol_stats, 'no_data': no_data}
			return JSONResponse(data)
		else:
			logger.error('could not get website id of org')
			data = {'no_data': True}
			return JSONResponse(data)
	except Exception as e:
		logger.error(e, exc_info=True)

@app.route('/ping', methods=['GET'])
@request_validator_timer
async def ping(request: Request):
	context['duration'] = round(time.perf_counter() - context['start_time'], 3)
	logger.debug('from ping')
	return PlainTextResponse("hello")