import logging
from dataclasses import dataclass, field
from functools import lru_cache
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import json
import os
from asyncio import create_task
import copy

from db import query, Settings

logger = logging.getLogger(__name__)
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
ENVIRONMENT = os.getenv('ENVIRONMENT', 'self_hosted') # 'self_hosted', 'cloud', 'test'

subclasses = {}

class SecretsManager():

	def __init__(self):
		self.connections_for_orgs_apps = defaultdict(dict) # separate manager for each org/app
		self.connections_for_orgs = {} # a single manager for each org

	async def initialize(self):
		"""
		populate org_secrets for every org & app that's configured in the database
		"""
		try:
			self.connections_for_orgs[0] = Secrets.create_manager('database_pgp') # default
			if ENVIRONMENT=='cloud':
				if results := await Settings.filter(key='credential_storage'):
					with ThreadPoolExecutor() as executor:
						result = executor.map(self.create_connection, results)
		except Exception as e:
			logger.error(e, exc_info=True)

	def create_connection(self, result):
		"""
		"""
		try:
			settings = copy.deepcopy(result.value)
			protocol = settings.pop('protocol')
			if result.application_id:
				logger.debug(f"creating secrets connection for org_id: {result.organization_id} application_id: {result.application_id}")
				self.connections_for_orgs_apps[result.organization_id][result.application_id] = Secrets.create_manager(protocol, **settings)
			elif result.organization_id:
				logger.debug(f"creating secrets connection for org_id: {result.organization_id}")
				logger.debug("before creating manager, dict is:")
				logger.debug(self.connections_for_orgs)
				self.connections_for_orgs[result.organization_id] = Secrets.create_manager(protocol, **settings)
				logger.debug("after creating manager, dict is:")
				logger.debug(self.connections_for_orgs)
		except Exception as e:
			logger.error(e, exc_info=True)

	def get_manager(self, organization_id, application_id=None):
		"""
		"""
		try:
			if application_id:
				manager = self.connections_for_orgs_apps.get(organization_id).get(application_id)
				if not manager:
					# try a credential store for the whole org
					logger.warning(f"trying credential store for whole org, as none exists for org_id: {organization_id} application_id: {application_id}")
					manager = self.connections_for_orgs.get(organization_id)
			else:
				manager = self.connections_for_orgs.get(organization_id)
			if not manager:
				logger.error(f"no secrets manager exists for organization_id:{organization_id} application_id:{application_id}")
				return None
			return manager
		except Exception as e:
			logger.error(e, exc_info=True)

	def change_protocol(self, organization_id, new_protocol, application_id=None, **kwargs):
		"""
		"""
		try:
			if application_id:
				self.connections_for_orgs_apps[organization_id][application_id] = Secrets.create_manager(new_protocol, **kwargs)
			else:
				self.connections_for_orgs[organization_id] = Secrets.create_manager(new_protocol, **kwargs)
			return True
		except Exception as e:
			logger.error(e, exc_info=True)

	async def get(self, **kwargs):
		"""
		"""
		try:
			if manager := self.get_manager(kwargs.get('organization_id'), kwargs.get('application_id')):
				logger.debug('got manager in get with kwargs:' + str(kwargs) + ' and manager dir ' + str(dir(manager)))
				result = await manager.get(kwargs['organization_id'], kwargs['table_name'], kwargs['id'], kwargs['key'])
				logger.debug('result:' + str(result))
				return result
		except Exception as e:
			logger.error(e, exc_info=True)

	async def set(self, **kwargs):
		"""
		"""
		try:
			if manager := self.get_manager(kwargs.get('organization_id'), kwargs.get('application_id')):
				await manager.set(kwargs['organization_id'], kwargs['table_name'], kwargs['id'], kwargs['key'], kwargs.get('value'))
				return True
		except Exception as e:
			logger.error(e, exc_info=True)

@dataclass
class Secrets():

	def __init_subclass__(cls, **kwargs):
		super().__init_subclass__(**kwargs)
		subclasses[cls.protocol] = cls

	@classmethod
	def create_manager(cls, protocol, **kwargs):
		#if protocol not in cls.subclasses:
		if protocol not in ['database_pgp','aws','azure','gcp']:
			raise ValueError('Bad secrets protocol {}'.format(protocol))
		return subclasses[protocol](**kwargs)

@dataclass
class DatabasePGP(Secrets):
	protocol = 'database_pgp'

	#@lru_cache()
	async def get(self, organization_id, table_name, id, key):
		"""
		"""
		try:
			if table_name not in ['databases', 'APIs']:
				logger.error('table_name parameter is not one of the approved tables for DatabasePGP class')
				return None
			sql = f"SELECT PGP_SYM_DECRYPT({key}\:\:bytea, :admin_password) AS value FROM \"{table_name}\" WHERE organization_id=:organization_id AND id=:id"
			result = await query(0, 'summation', sql, {
				'admin_password': ADMIN_PASSWORD, 
				'organization_id': organization_id,
				'id': id,
				}
			)
			if result:
				return result[0].get('value')
			else:
				logger.error(f"could not get credentials for: table: {table_name}, id: {id}, column: {key}")
				return None
		except Exception as e:
			logger.error(e, exc_info=True)

	async def set(self, organization_id, table_name, id, key, value):
		"""
		"""
		try:
			if table_name not in ['databases', 'APIs']:
				logger.error('table_name parameter is not one of the approved tables for DatabasePGP class')
				return None
			sql = f"UPDATE \"{table_name}\" SET {key}=PGP_SYM_ENCRYPT(:value, :admin_password)\:\:text WHERE organization_id=:organization_id AND id=:id"
			result = await query(0, 'summation', sql, {
				'admin_password': ADMIN_PASSWORD, 
				'organization_id': organization_id,
				'id': id,
				'value': value
				}
			)
			return True
		except Exception as e:
			logger.error(e, exc_info=True)
			logger.error(f"could not get credentials for: table: {table_name}, id: {id}, column: {key}")
			return False

	async def get_all(self, organization_id):
		"""
		return a list of all secrets [{table_name: '', id: '', ....}]
		"""
		try:
			all_results = []
			# APIs first
			sql = """SELECT id, 'APIs' AS table_name, 'production_key' AS key, PGP_SYM_DECRYPT(:production_key\:\:bytea, :admin_key) AS value FROM \"APIs\" WHERE organization_id=:organization_id AND production_key IS NOT NULL
			UNION ALL
			SELECT id, 'APIs' AS table_name, 'development_key' AS key, PGP_SYM_DECRYPT(:development_key\:\:bytea, :admin_key) AS value FROM \"APIs\" WHERE organization_id=:organization_id AND development_key IS NOT NULL"""
			results = await query(0, 'summation', sql, {
				'admin_password': ADMIN_PASSWORD, 
				'organization_id': organization_id
				}
			)
			if results:
				all_results = all_results + results
			else:
				logger.debug(f"could not get any API credentials for: organization_id: {organization_id}")

			# Databases next
			sql = "SELECT id, 'databases' AS table_name, 'password' AS key, PGP_SYM_DECRYPT(:password\:\:bytea, :admin_key) AS value FROM databases WHERE organization_id=:organization_id AND password IS NOT NULL"
			results = await query(0, 'summation', sql, {
				'admin_password': ADMIN_PASSWORD, 
				'organization_id': organization_id
				}
			)
			if results:
				all_results = all_results + results
			else:
				logger.debug(f"could not get any database credentials for: organization_id: {organization_id}")
			return all_results
		except Exception as e:
			logger.error(e, exc_info=True)