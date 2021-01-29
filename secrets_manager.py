import logging
from dataclasses import dataclass, field
from functools import lrucache
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import json
import os

from db import query, Settings

logger = logging.getLogger(__name__)
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

subclasses = {}

class SecretsManager():

	def __init__(self):
		self.connections_for_orgs_apps = defaultdict(dict) # separate manager for each org/app
		self.connections_for_orgs = {} # a single manager for each org
		self.connections_for_orgs[0] = Secrets.create('database_pgp') # default

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
		return manager

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
	def create(cls, protocol, **kwargs):
		#if protocol not in cls.subclasses:
		if protocol not in ['database_pgp','aws','azure','gcp']:
			raise ValueError('Bad secrets protocol {}'.format(protocol))
		return subclasses[protocol](**kwargs)

@dataclass
class DatabasePGP(Secrets):
	_protocol = 'database_pgp'

	@lrucache()
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