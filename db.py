import os
import logging
import json
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from functools import wraps, partial
import asyncio
import copy
import uuid

from sqlalchemy import create_engine  
from sqlalchemy import Column, String, Table, MetaData
from sqlalchemy.types import Integer, DateTime, Float, Boolean
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.ext.declarative import declarative_base  
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy import text
from sqlalchemy.ext.declarative import declarative_base

from json_logging import *

logger = JSONLoggingAdapter(logging.getLogger(__name__))

ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
ENVIRONMENT = os.getenv('ENVIRONMENT')

"""
SQLalchemy
https://github.com/RazerM/sqlalchemy_aio
https://github.com/yifeikong/aioify

use this approach to make SQLalchemy async, regardless of driver:
https://dev.to/0xbf/turn-sync-function-to-async-python-tips-58nn
then later, use actual async drivers for mysql/postgresql

solves the issue here:
https://www.aeracode.org/2018/02/19/python-async-simplified/
if you call a blocking function, like the Django ORM, the code inside the async function will look identical, but now it's dangerous code that might block the entire event loop as it's not awaiting

core is a query builder. Its purpose is to provide a programmatic means to generate SQL queries (and DDL) -- but the results of those queries are just tuples (with a little extra magic), not objects of your own
want the orm, so that returns variables, types, etc.
"""

"""
async_sleep = async_wrap(time.sleep)

# or use decorator style
@async_wrap
def my_async_sleep(duration):
	time.sleep(duration)
"""

Base = declarative_base()
DATABASE_CONNECTION_STRING = os.getenv('DATABASE_CONNECTION_STRING', f"postgresql+psycopg2://postgres:{ADMIN_PASSWORD}@db:5432/postgres")
logger.debug(f"database connection string: {DATABASE_CONNECTION_STRING}")
#schemas = 'summation,public'
db = create_engine(DATABASE_CONNECTION_STRING)#, connect_args={'options': '-csearch_path={}'.format(schemas)})
metadata = MetaData()

# use declarative mapping, so we can create mixins
# https://docs.sqlalchemy.org/en/13/orm/mapping_styles.html
# https://docs.sqlalchemy.org/en/13/orm/extensions/declarative/mixins.html
# https://github.com/absent1706/sqlalchemy-mixins#active-record

def async_wrap(func):
	@wraps(func)
	async def run(*args, loop=None, executor=None, **kwargs):
		if loop is None:
			loop = asyncio.get_event_loop()
		pfunc = partial(func, *args, **kwargs)
		return await loop.run_in_executor(executor, pfunc) # runs in ThreadPool
	return run

class Mixins(object):
	_organization_id = 0
	_database_name = 'summation'

	@classmethod
	def settable_attributes(cls):
		return cls.columns + cls.hybrid_properties + cls.settable_relations
		
	def fill(self, **kwargs):
		for name in kwargs.keys():
			#if name in self.settable_attributes:
			setattr(self, name, kwargs[name])
			#else:
			#	raise KeyError("Attribute '{}' doesn't exist".format(name))
		return self

	@classmethod
	@async_wrap
	def all(cls):
		return cls.query.all()

	@classmethod
	@async_wrap
	def first(cls):
		return cls.query.first()

	@async_wrap
	def save(self, as_dict=False, return_id=False):
		"""
		"""
		try:
			session, session_factory = get_database_session(self._organization_id, self._database_name)
			session.add(self)
			session.commit()
			if as_dict:
				return self.to_dict()
			elif return_id:
				return self.id
			return self
		except:
			session.rollback()
			raise
		finally:
			session_factory.remove()

	def update(self, as_dict=False, **kwargs):
		"""
		"""
		return self.fill(**kwargs).save(as_dict)

	@async_wrap
	def delete(self):
		"""
		"""
		try:
			session, session_factory = get_database_session(self._organization_id, self._database_name)
			session.delete(self)
			session.commit()
		except:
			session.rollback()
			raise
		finally:
			session_factory.remove()

	@classmethod
	@async_wrap
	def get(cls, as_dict=False, **kw):
		try:
			session, session_factory = get_database_session(cls._organization_id, cls._database_name)
			result = session.query(cls)
			clean_kw = {}
			for key, val in kw.items():
				#if key.find('__json')!=-1:
				# .filter(Resources.data["lastname"].astext == "Doe")
				#session.query(cls).filter(cls.key)
				if isinstance(val, dict) or isinstance(val, list):
					# or if you pass in a dictionary or list, assume you want a JSON contains
					# .filter(Bargain.info.contains({"animal_info": {"eye_color": "green"}}))
					# .filter(text("CAST(json_field->>'id' AS INTEGER) = 1")
					result = result.filter(getattr(cls, key).contains(json.dumps(val)))
				else:
					clean_kw[key] = val
			result = result.filter_by(**clean_kw).first()
			if not result:
				logger.debug(f"no database result for get with class: {cls.__name__} and filters: {kw}")
				return None
			if as_dict:
				return to_dict(result)
			return result
		except:
			session.rollback()
			raise
		finally:
			session_factory.remove()

	@classmethod
	@async_wrap
	def filter(cls, **kw):
		try:
			session, session_factory = get_database_session(cls._organization_id, cls._database_name)
			result = session.query(cls)
			clean_kw = {}
			for key, val in kw.items():
				#if key.find('__json')!=-1:
				# .filter(Resources.data["lastname"].astext == "Doe")
				#session.query(cls).filter(cls.key)
				if isinstance(val, dict) or isinstance(val, list):
					# or if you pass in a dictionary or list, assume you want a JSON contains
					# .filter(Bargain.info.contains({"animal_info": {"eye_color": "green"}}))
					# .filter(text("CAST(json_field->>'id' AS INTEGER) = 1")
					result = result.filter(getattr(cls, key).contains(json.dumps(val)))
				else:
					clean_kw[key] = val
			result = result.filter_by(**clean_kw).all()
			if not result:
				logger.debug(f"no database result for get with class: {cls.__name__} and filters: {kw}")
			return result
		except:
			session.rollback()
			raise
		finally:
			session_factory.remove()

	def to_dict(self):
		"""
		Return dict object with model's data.
		"""
		result = dict()
		for key in self.__mapper__.c.keys():
			result[key] = getattr(self, key)
		return result

# TODO: https://amercader.net/blog/beware-of-json-fields-in-sqlalchemy/

class Settings(Base, Mixins):
	__tablename__ = 'settings'
	id = Column(Integer, primary_key=True)
	organization_id = Column(Integer, nullable=True)
	application_id = Column(Integer, nullable=True)
	key = Column(String, nullable=True)
	value = Column(JSONB, nullable=True)
	string_value = Column(String, nullable=True)
	integer_value = Column(Integer, nullable=True)

class Applications(Base, Mixins):
	__tablename__ = 'applications'
	id = Column(Integer, primary_key=True)
	organization_id = Column(Integer, nullable=True)
	authentication = Column(JSONB, nullable=True)
	name = Column(String, nullable=True)

class AccessControls(Base, Mixins):
	__tablename__ = 'access_controls'
	id = Column(Integer, primary_key=True)
	scope = Column(String, nullable=True)
	role_id = Column(Integer, nullable=True)
	api_id = Column(Integer, nullable=True)
	database_id = Column(Integer, nullable=True)
	create_permission = Column(Boolean, nullable=True)
	read_permission = Column(Boolean, nullable=True)
	update_permission = Column(Boolean, nullable=True)
	delete_permission = Column(Boolean, nullable=True)
	get_permission = Column(Boolean, nullable=True)
	post_permission = Column(Boolean, nullable=True)
	patch_permission = Column(Boolean, nullable=True)
	table_name = Column(String, nullable=True)

class APIs(Base, Mixins):
	__tablename__ = 'APIs'
	id = Column(Integer, primary_key=True)
	name = Column(String, nullable=True)
	organization_id = Column(Integer, nullable=True)
	url = Column(String, nullable=True)
	development_key = Column(String, nullable=True)
	production_key = Column(String, nullable=True)
	version = Column(String, nullable=True)
	method = Column(String, nullable=True)
	value = Column(JSONB, nullable=True)
	authentication = Column(JSONB, nullable=True)
	body = Column(JSONB, nullable=True)
	headers = Column(JSONB, nullable=True)

class Events(Base, Mixins):
	__tablename__ = 'events'
	id = Column(Integer, primary_key=True)
	organization_id = Column(Integer, nullable=True)
	application_id = Column(Integer, nullable=True)
	data = Column(JSONB, nullable=True)
	event_type = Column(String, nullable=True)
	date = Column(DateTime, nullable=True)
	duration_milliseconds = Column(Integer, nullable=True)
	status_code = Column(Integer, nullable=True)

class Requests(Base, Mixins):
	__tablename__ = 'requests'
	id = Column(Integer, primary_key=True)
	url = Column(String, nullable=True)
	method = Column(String, nullable=True)
	value = Column(JSONB, nullable=True)
	api_id = Column(Integer, nullable=True)
	role_id = Column(Integer, nullable=True)

class Chains(Base, Mixins):
	__tablename__ = 'chains'
	id = Column(Integer, primary_key=True)
	organization_id = Column(Integer, nullable=True)
	application_id = Column(Integer, nullable=True)
	value = Column(JSONB, nullable=True)
	role_id = Column(Integer, nullable=True)
	enabled = Column(Boolean, nullable=True)
	
class Roles(Base, Mixins):
	__tablename__ = 'roles'
	id = Column(Integer, primary_key=True)
	name = Column(String, nullable=True)
	organization_id = Column(Integer, nullable=True)
	enabled = Column(Boolean, nullable=True)
	application_id = Column(Integer, nullable=True)

class Queries(Base, Mixins):
	__tablename__ = 'queries'
	id = Column(Integer, primary_key=True)
	description = Column(String, nullable=True)
	organization_id = Column(Integer, nullable=True)
	value = Column(String, nullable=True)
	enabled = Column(Boolean, nullable=True)
	method = Column(String, nullable=True)
	table_name = Column(String, nullable=True)
	parameters = Column(JSONB, nullable=True)
	role_id = Column(Integer, nullable=True)

class Databases(Base, Mixins):
	__tablename__ = 'databases'
	id = Column(Integer, primary_key=True)
	engine = Column(String, nullable=True)
	organization_id = Column(Integer, nullable=True)
	url = Column(String, nullable=True)
	port = Column(Integer, nullable=True)
	username = Column(String, nullable=True)
	password = Column(String, nullable=True)
	database_name = Column(String, nullable=True)
	schema = Column(String, nullable=True)
	name = Column(String, nullable=True)

class Organizations(Base, Mixins):
	__tablename__ = 'organizations'
	id = Column(Integer, primary_key=True)
	name = Column(String, nullable=True)
	date_created = Column(DateTime, nullable=True)
	domain_name = Column(String, nullable=True)

class Customers(Base, Mixins):
	__tablename__ = 'customers'
	id = Column(String, primary_key=True)
	organization_id = Column(Integer, nullable=True)
	display_name = Column(String, nullable=True)
	date_created = Column(DateTime, nullable=True)
	profile_picture_url = Column(String, nullable=True)
	email = Column(String, nullable=True)
	email_verified = Column(Boolean, nullable=True)

class Subscriptions(Base, Mixins):
	__tablename__ = 'subscriptions'
	id = Column(Integer, primary_key=True)
	organization_id = Column(Integer, nullable=True)
	plan = Column(String, nullable=True)
	active_flag = Column(Boolean, nullable=True)

db_connections = defaultdict(dict)
db_classes = defaultdict(lambda: defaultdict(dict))
db_schemas = defaultdict(dict)	
if ENVIRONMENT!='TEST':
	session_factory = sessionmaker(db, expire_on_commit=False)
	Session = scoped_session(session_factory) # thread-local
	db_connections[0]['summation'] = Session

	Base.metadata.create_all(db)
else:
	logger.debug('not doing db setup')

def connect_to_test_database():
	"""
	SQLite database stored in tests/test_database.sqlite
	"""
	try:
		connection_string = "sqlite:///tests/test_database.sqlite"
		db = create_engine(connection_string)#, connect_args=args)
		meta = MetaData()
		Mixins._organization_id = 0
		Mixins._database_name = 'test_database'
		automapper = automap_base(cls=Mixins, metadata=meta)
		automapper.prepare(db, reflect=True) # could also pass schema=database.schema?
		session_factory = sessionmaker(db, expire_on_commit=False)
		Session = scoped_session(session_factory) # thread-local
		db_connections[0]['test_database'] = Session
		logger.debug(automapper.__subclasses__()) # has class variables
		for class_variable in automapper.__subclasses__():
			db_classes[0]['test_database'][class_variable.__name__] = class_variable
		#ses = Session()
		#result = ses.execute(text("SELECT * FROM Album WHERE AlbumId=5"))
		#for row in result:
		#	logger.debug(row)
	except Exception as e:
		logger.error(e, exc_info=True)

def connect_to_database(database):
	"""
	automapped classes need to have the Mixin as well
	method 1: 
	for class_variable in automapper.__subclasses__():
		new_class = type(class_variable.__name__, (class_variable, Mixins), {})
	results in warnings:
	class _ is a subclass of AutomapBase.  Mappings are not produced until the .prepare() method is called on the class hierarchy.

	method 2: 
	infinite loop if call .prepare() again:
	SAWarning: This declarative base already contains a class with the same class name and module name as sqlalchemy.ext.automap.payments, and will be replaced in the string-lookup table.

	method 3 (the solution that's implemented):
	automapper = automap_base(cls=MySpecialBaseClass)
	This works because automap_base passes most of its arguments on to
	declarative_base:
	https://docs.sqlalchemy.org/en/13/orm/extensions/automap.html#sqlalchemy.ext.automap.automap_base
	...and declarative_base accepts a "cls" argument which is used as the
	base class:
	https://docs.sqlalchemy.org/en/13/orm/extensions/declarative/api.html#sqlalchemy.ext.declarative.declarative_base
	"""
	try:
		if database['engine']=='postgresql':
			connection_string = f"postgresql+psycopg2://{database['username']}:{database['password']}@{database['url']}:{database['port']}/{database['database_name']}"
			#won't work with pgbouncer
			#args = {}
			#if database.schema:
			#	search_path = database.schema + ",public"
			#	args={'options': f"-csearch_path={search_path}"}
		elif database['engine']=='mysql':
			connection_string = f"mysql+mysqldb://{database['username']}:{database['password']}@{database['url']}:{database['port']}/{database['database_name']}"
		elif database['engine']=='oracle':
			connection_string = f"oracle+cx_oracle://{database['username']}:{database['password']}@{database['url']}:{database['port']}/{database['database_name']}"
		elif database['engine']=='sql_server':
			# URL is DSN
			connection_string = f"mssql+pyodbc://{database['username']}:{database['password']}@{database['url']}"
		elif database['engine']=='sqlite':
			# URL is file path
			connection_string = f"sqlite://{database['url']}"
		elif database.engine=='snowflake':
			# URL is 'account'
			connection_string = f"snowflake://{database['username']}:{database['password']}@{database['url']}"
		elif database['engine']=='teradata':
			connection_string = f"teradatasql://{database['url']}:{database['port']}?user={database['username']}&password={database['password']}"
		elif database['engine']=='db2':
			connection_string = f"db2+ibm_db://{database['username']}:{database['password']}@{database['url']}:{database['port']}/{database['database_name']}"
		elif database['engine']=='sap_hana':
			connection_string = f"hana://{database['username']}:{database['password']}@{database['url']}:{database['port']}"
		elif database['engine']=='access':
			# URL is DSN
			connection_string = f"access+pyodbc://@{database['url']}"
		elif database['engine']=='bigquery':
			# URL is credentials path to JSON file
			connection_string = f"bigquery://', credentials_path='{database['url']}"
		elif database['engine']=='cockroachdb':
			connection_string = f"cockroachdb://{database['username']}@{database['url']}:{database['port']}/{database['database_name']}"
		elif database['engine']=='redshift':
			connection_string = f"redshift+psycopg2://{database['username']}@host.amazonaws.com:5439/{database['database_name']}"
		elif database['engine']=='presto':
			connection_string = f"presto://{database['url']}:{database['port']}/hive/default"
		
		db = create_engine(connection_string)#, connect_args=args)
		meta = MetaData()
		if database['schema']:
			meta = MetaData(schema=database['schema'])
			db_schemas[database['organization_id']][database['name']] = database['schema']
		#deepcopy doesn't work for class objects
		Mixins_copy = type('Mixins_' + str(database['name']), (Mixins,), {'_organization_id': database['organization_id'], '_database_name': database['name']})
		automapper = automap_base(cls=Mixins_copy, metadata=meta)
		automapper.prepare(db, reflect=True) # could also pass schema=database.schema?
		session_factory = sessionmaker(db, expire_on_commit=False)
		Session = scoped_session(session_factory) # thread-local
		db_connections[database['organization_id']][database['name']] = Session
		#logger.debug(dir(automapper.classes.keys()))
		logger.debug(automapper.__subclasses__()) # has class variables
		for class_variable in automapper.__subclasses__():
			db_classes[database['organization_id']][database['name']][class_variable.__name__] = class_variable
	except Exception as e:
		logger.error(e, exc_info=True)

async def connect_to_all_databases():
	"""
	for each row in the 'databases' table

	automap, then create new classes for each by manually mixing in (a,b)
	don't need to keep creating new classes for mixin, just create one mixin class and then keep changing its class variables from outside: Class._organization_id = 2
	
	we use SQL instead of the ORM, as we have to use pgcrypto decryption for the database passwords
	"""
	try:
		sql = "SELECT organization_id, id, engine, url, port, username, PGP_SYM_DECRYPT(password\:\:bytea, :admin_password) AS password, database_name, schema, name FROM databases WHERE password IS NOT NULL"
		results = await query(0, 'summation', sql, parameters={'admin_password': ADMIN_PASSWORD})
		if results:
			with ThreadPoolExecutor() as executor:
				result = executor.map(connect_to_database, results)
			logger.debug(db_classes)
	except Exception as e:
		logger.error(e, exc_info=True)

def get_database_session(organization_id, database_name):
	"""
	"""
	try:
		if database_name=='summation':
			if organization_id!=0:
				organization_id = 0 # force any queries going to the summation app itself to use the default connection
				logger.debug("forcing organization_id=0 for database_name='summation'")
		db_session = db_connections.get(organization_id, {}).get(database_name)
		if db_session:
			session = db_session()
			if schema := db_schemas[organization_id].get(database_name):
				session.execute(f"SET search_path TO {schema}, public") # only happens for databases with schemas, like PostgreSQL
			return session, db_session
		else:
			logger.error(f"could not get database session for organization_id: {organization_id}, database_name: {database_name}")
			raise Exception
	except Exception as e:
		logger.error(e, exc_info=True)

@async_wrap
def get_or_create(org_id, database_name, model, **kwargs):
	"""
	the database table itself can't contain the columns 'org_id' or 'database_name'
	"""
	try:
		session, session_factory = get_database_session(org_id, database_name)
		instance = session.query(model).filter_by(**kwargs).first()
		if instance:
			session.expunge_all() # or expunge(instance)
			return instance, False
		else:
			instance = model(**kwargs)
			session.add(instance)
			session.commit()
			session.expunge_all() # or expunge(instance)
			return instance, True
	except:
		session.rollback()
		raise
	finally:
		session_factory.remove()

def to_dict(row):
	"""
	"""
	try:
		result = dict()
		for key in row.__mapper__.c.keys():
			result[key] = getattr(row, key)
		return result
	except Exception as e:
		logger.error(e, exc_info=True)

@async_wrap
def query(org_id, database_name, sql, parameters={}):
	try:
		session, session_factory = get_database_session(org_id, database_name)
		compiled_query = text(sql)
		bind_params = compiled_query._bindparams
		if bind_params and set(bind_params.keys())!=set(parameters.keys()):
			# didn't explicitly pass in each required parameter
			# got lazy, and passed in locals() with more or less values than we need
			required_params = {}
			for key in bind_params.keys():
				logger.debug(key)
				if param := parameters.get(key):
					required_params[key] = param
				else:
					logger.error(f"missing key: {key} for parameters of query: {sql}")
					return []
			parameters = required_params
		result = session.execute(compiled_query, parameters)
		if result.returns_rows: # is a SELECT query, etc.
			result_dict = [dict(zip(row.keys(), row)) for row in result]
			return result_dict
	except:
		session.rollback()
		raise
	finally:
		session.commit() # sometimes SQLalchemy will close the connection when this is called
		session_factory.remove()