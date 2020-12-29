import logging

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