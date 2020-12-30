import logging
import os
import sys
import asyncio
import datetime
from pathlib import Path

from starlette_context import context
from pythonjsonlogger import jsonlogger

ENVIRONMENT = os.getenv('ENVIRONMENT', 'self_hosted') # 'self_hosted', 'cloud', 'test'
LOCAL_FILE_LOG_PATH = os.getenv('LOCAL_FILE_LOG_PATH')
VECTOR_BIN_PATH = os.getenv('VECTOR_BIN_PATH')
LOCAL_FILE_STORAGE_PATH = os.getenv('LOCAL_FILE_STORAGE_PATH')

class JSONLoggingAdapter(logging.LoggerAdapter):
	def __init__(self, logger, extra=None):
		if extra is None:
			extra = {}
		super(JSONLoggingAdapter, self).__init__(logger, extra)

	def process(self, msg, kwargs):
		extra = self.extra.copy()
		try:
			extra.update(context.data) # add starlette context data to the log
		except Exception as e:
			pass
		kwargs["extra"] = extra
		return msg, kwargs

if ENVIRONMENT!='cloud':
	json_formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s')
	handlers = [logging.FileHandler(LOCAL_FILE_LOG_PATH, mode='w'),
				logging.StreamHandler(sys.stdout)]
	for handler in handlers:
		handler.setFormatter(json_formatter)
	logging.basicConfig(level=logging.DEBUG,
		handlers=handlers)
	logging.getLogger('websockets.server').setLevel(logging.WARNING) # to allow log tailing to browser without infinite loop
	logging.getLogger('websockets.protocol').setLevel(logging.WARNING) # to allow log tailing to browser without infinite loop
	logger = JSONLoggingAdapter(logging.getLogger(__name__))
else:
	import google.cloud.logging
	from google.cloud.logging.handlers import CloudLoggingHandler, setup_logging
	from google.cloud.logging.handlers.transports import BackgroundThreadTransport

	class JSONLogTransport(BackgroundThreadTransport):
		"""
		This code is adapted from here:
		https://github.com/snickell/google_structlog/blob/master/google_structlog/setup_google.py
		"""

		def send(self, record, message, **kwargs):
			info = {
				"message": message,
				"file_path": record.filename,
				"line_number": record.lineno,
			}
			if record.args:
				info["args"] = record.args
			try:
				info.update(context.data) # add starlette context data to the log
			except Exception as e:
				pass
			self._worker_enqueue(record, info, **kwargs)

		def _worker_enqueue(self, record, info, resource=None, labels=None, trace=None, span_id=None):
			queue_entry = {
				"info": info,
				"severity": record.levelno,
				"resource": resource,
				"labels": labels,
				"trace": trace,
				"span_id": span_id,
				"timestamp": datetime.datetime.utcfromtimestamp(record.created),
			}
			self.worker._queue.put_nowait(queue_entry)

	client = google.cloud.logging.Client()
	handler = CloudLoggingHandler(client, transport=JSONLogTransport)
	setup_logging(handler, log_level=logging.DEBUG, excluded_loggers=('google.cloud', 'google.auth', 'google_auth_httplib2','urllib3.connectionpool'))
	logger = logging.getLogger(__name__)
class LogServer(object):
	"""
	Manage the Vector log router
	https://vector.dev
	"""

	def __init__(self, settings):
		self.vector_process = None
		self.settings = settings
		self.task = asyncio.create_task(self.start()) # don't wait for it to finish

	async def read_stream(self, stream):
		"""
		https://kevinmccarthy.org/2016/07/25/streaming-subprocess-stdin-and-stdout-with-asyncio-in-python/
		"""
		while True:
			line = await stream.readline()
			if line:
				print(line)
			else:
				break

	async def start(self):
		try:
			env_vars = {}
			# read environment variables from the database settings
			if self.settings:
				env_vars = self.settings.value

			vector_path = os.path.join(LOCAL_FILE_STORAGE_PATH, 'vector_config.json')
			vector_config_path = Path(vector_path)
			if vector_config_path.is_file():
				self.vector_process = await asyncio.create_subprocess_exec(VECTOR_BIN_PATH, '--config', vector_path,
				stdout=asyncio.subprocess.PIPE,
				env=env_vars)

				await self.read_stream(self.vector_process.stdout)
				await self.vector_process.wait()
				self.vector_process = None # if you press Ctrl-C, vector will kill itself
				#stdout, stderr = await self.vector_process.communicate()
			else:
				logger.debug('vector config file not found - skipping starting of log server')
		except Exception as e:
			logger.error(e, exc_info=True)

	def stop(self):
		try:
			if self.vector_process:
				self.vector_process.kill()
			else:
				logger.error('no vector process initialized')
		except Exception as e:
			logger.error(e, exc_info=True)

	def restart(self):
		try:
			self.stop()
			self.task = asyncio.create_task(self.start()) # don't wait for it to finish
			return True
		except Exception as e:
			logger.error(e, exc_info=True)