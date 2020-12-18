import os
import logging
import typing
from datetime import datetime, timezone, timedelta
import dateutil.parser
import functools
import json
import uuid
import os.path
from asyncio import gather, create_task
import re
import urllib.parse
import asyncio
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from hashlib import sha256
from urllib.parse import urlparse, parse_qs, urlunparse
import functools
from base64 import b64decode
import base64
import binascii

import uvicorn
from six.moves.urllib.parse import quote, unquote
from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse, Response, RedirectResponse
from starlette.background import BackgroundTask
from starlette.middleware import Middleware
from starlette.types import Message, Receive, Scope, Send
from starlette.authentication import (
	AuthenticationBackend, AuthenticationError, SimpleUser, UnauthenticatedUser,
	AuthCredentials
)
from starlette.requests import Request
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.authentication import requires

from aiohttp import ClientSession
from aiohttp.helpers import BasicAuth
from aiohttp import ClientSession, BasicAuth

ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
ENVIRONMENT = os.getenv('ENVIRONMENT')
LOCAL_FILE_STORAGE_PATH = os.getenv('LOCAL_FILE_STORAGE_PATH')

async def startup():
    pass

async def shutdown():
	pass

app = Starlette(debug=True, on_startup=[startup], on_shutdown=[shutdown])

"""
if "auth" in request.query_params:
			# websocket auth handled separately
			return
		if "authorization" not in request.headers and "api_key" not in request.headers:
			#logger.error('authorization/api_key key not in headers for url: ' + str(request.url))
			return

		if "authorization" in request.headers:
			return
		elif "api_key" in request.headers:
"""

@app.route('/get', methods=['GET'])
async def get(request):
    return JSONResponse(True)

@app.route('/post', methods=['POST'])
async def post(request):
    return JSONResponse(True)

@app.route('/put', methods=['PUT'])
async def put(request):
    return JSONResponse(True)

@app.route('/patch', methods=['PATCH'])
async def patch(request):
    return JSONResponse(True)

@app.route('/delete', methods=['DELETE'])
async def delete(request):
    return JSONResponse(True)

@app.route('/basic_auth', methods=['POST'])
async def basic_auth(request):
    if "Authorization" not in request.headers:
        return JSONResponse(False, status_code=403)

    auth = request.headers["Authorization"]
    try:
        scheme, credentials = auth.split()
        if scheme.lower() != 'basic':
            return JSONResponse(False, status_code=403)
        decoded = base64.b64decode(credentials).decode("ascii")
    except (ValueError, UnicodeDecodeError, binascii.Error) as e:
        raise AuthenticationError('Invalid basic auth credentials')

    username, _, password = decoded.partition(":")
    if username=='TEST_USER' and password=='TEST_KEY':
        return JSONResponse(True)
    return JSONResponse(False, status_code=403)

@app.route('/api_key_parameters_auth', methods=['GET'])
async def api_key_parameters_auth(request):
    key = request.query_params['key']
    if key == 'TEST_KEY':
        return JSONResponse(True)
    return JSONResponse(False, status_code=403)

@app.route('/api_key_headers_auth', methods=['POST'])
async def api_key_headers_auth(request):
    key = request.headers['key']
    if key == 'TEST_KEY':
        return JSONResponse(True)
    return JSONResponse(False, status_code=403)

@app.route('/bearer_token', methods=['POST'])
async def bearer_token(request):
    if "Authorization" not in request.headers:
        return JSONResponse(False, status_code=403)

    auth = request.headers["Authorization"]
    scheme, credentials = auth.split()
    if scheme.lower() != 'bearer':
        return JSONResponse(False, status_code=403)
    if credentials=='TEST_KEY':
        return JSONResponse(True)
    return JSONResponse(False, status_code=403)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)