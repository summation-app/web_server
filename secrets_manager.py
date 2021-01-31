import logging
from dataclasses import dataclass, field
from functools import lru_cache
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import json
import os
from asyncio import create_task

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
		self.connections_for_orgs[0] = Secrets.create_manager('database_pgp') # default
		if ENVIRONMENT=='cloud':
			if results := await Settings.filter(key='credential_storage'):
				with ThreadPoolExecutor() as executor:
					result = executor.map(self.create_connection, results)

	def create_connection(self, result):
		if result.application_id:
			self.connections_for_orgs_apps[result.organization_id][result.application_id] = Secrets.create_manager(result.value.get('protocol'), **result.value)
		elif result.organization_id:
			self.connections_for_orgs[result.organization_id] = Secrets.create_manager(result.value.get('protocol'), **result.value)

	def get_manager(self, organization_id, application_id=None):
		"""
		"""
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

	def change_protocol(self, organization_id, new_protocol, application_id=None, **kwargs):
		"""
		"""
		if application_id:
			self.connections_for_orgs_apps[organization_id][application_id] = Secrets.create_manager(new_protocol, **kwargs)
		else:
			self.connections_for_orgs[organization_id] = Secrets.create_manager(new_protocol, **kwargs)
		return True

	async def get(self, **kwargs):
		"""
		"""
		if manager := self.get_manager(kwargs.get('organization_id'), kwargs.get('application_id')):
			return await manager.get(kwargs['organization_id'], kwargs['table_name'], kwargs['id'], kwargs['key'])

	async def set(self, **kwargs):
		"""
		"""
		if manager := self.get_manager(kwargs.get('organization_id'), kwargs.get('application_id')):
			await manager.set(kwargs['organization_id'], kwargs['table_name'], kwargs['id'], kwargs['key'], kwargs.get('value'))
			return True

@dataclass
class Secrets():
	_protocol: str

	def __init_subclass__(cls, **kwargs):
		super().__init_subclass__(**kwargs)
		subclasses[cls._protocol] = cls

	@classmethod
	def create_manager(cls, protocol, **kwargs):
		#if protocol not in cls.subclasses:
		if protocol not in ['database_pgp','aws','azure','gcp']:
			raise ValueError('Bad secrets protocol {}'.format(protocol))
		return subclasses[protocol](**kwargs)

@dataclass
class DatabasePGP(Secrets):
	_protocol = 'database_pgp'

	@lru_cache()
	async def get(self, organization_id, table_name, id, key):
		"""
		"""
		try:
			sql = "SELECT PGP_SYM_DECRYPT(:column_name\:\:bytea, :admin_key) AS value FROM \":table_name\" WHERE organization_id=:organization_id AND id=:id"
			result = await query(0, 'summation', sql, {
				'admin_password': ADMIN_PASSWORD, 
				'organization_id': organization_id,
				'id': id,
				'column_name': key
				}
			)
			if result:
				return result[0].value
			else:
				logger.error(f"could not get credentials for: table: {table_name}, id: {id}, column: {key}")
				return None
		except Exception as e:
			logger.error(e, exc_info=True)

	async def set(self, organization_id, table_name, id, key, value):
		"""
		"""
		try:
			sql = "UPDATE :table_name SET :column_name=PGP_SYM_ENCRYPT(:value, :admin_password)\:\:text WHERE organization_id=:organization_id AND id=:id"
			result = await query(0, 'summation', sql, {
				'admin_password': ADMIN_PASSWORD, 
				'organization_id': organization_id,
				'id': id,
				'column_name': key,
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