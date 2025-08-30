

import sys
import unicodedata
import base64
import re
import math
import json
import jwt
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.serialization import pkcs12
from datetime import datetime, timezone, timedelta
from typing import TypeVar
import uuid
import requests
import functools
import struct
import pyodbc
import numpy
import pandas
import threading
import time
import logging
import random, string
from xml.dom.minidom import parseString as xmlStringParser
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import io
import select
import ssl
from socket import SocketIO
from socket import error as SocketError
from socket import timeout
from typing import Tuple, Optional
from io import BytesIO
from functools import partial
import OpenSSL.SSL
from OpenSSL.crypto import PKCS12, X509, PKey
from cryptography import x509
from cryptography.hazmat.backends.openssl import backend as openssl_backend
#
try:
	from time import monotonic
except ImportError:
	from time import time as monotonic
from pyspark.sql import SparkSession
from azure.identity import DefaultAzureCredential
from applicationinsights import TelemetryClient
from difflib import SequenceMatcher
import urllib
import math
from dateutil import parser
#
import urllib3.contrib.pyopenssl as SOAR_Custom_PyOpenSSLContext


# In[ ]:


# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •
##
# @brief	Global Member Variables
#
strGlobalErrorOrExceptionMessagesAsList	=	[]
bGlobalErrorOrExceptionMessage			=	False


# In[ ]:


def _is_key_file_encrypted(keyfile):
	"""In memory key is not encrypted"""
	if isinstance(keyfile, PKey):
		return False
	return _is_key_file_encrypted.original(keyfile)

class PyOpenSSLContext(SOAR_Custom_PyOpenSSLContext.PyOpenSSLContext):
	##
	# @brief	SOAR_OpenSSLContext Constructor
	def __init__(self, protocol):
		self._ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
		self._options = 0
		self.check_hostname = False
		self._minimum_version: int = ssl.TLSVersion.MINIMUM_SUPPORTED
		self._maximum_version: int = ssl.TLSVersion.MAXIMUM_SUPPORTED

	### -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	### -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	### -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	def load_cert_chain(self, certfile, keyfile=None, password=None):
		##
		#	@brief ....
		#
		#	Keyword arguments:
		#	@param _... -- ...
		"""Support loading certs from memory"""
		if isinstance(certfile, X509) and isinstance(keyfile, PKey):
			self._ctx.use_certificate(certfile)
			self._ctx.use_privatekey(keyfile)
		else:
			super().load_cert_chain(certfile, keyfile=keyfile, password=password)

	### -•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+
	### -•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+
	### -•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+

	## ## ## 2024/11/12 FIX : AttributeError: 'SOAR_OpenSSLContext' object has no attribute 'set_alpn_protocols'
	def set_alpn_protocols(self, alpn_protocols):
		self._alpn_protocols = alpn_protocols

	### -•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+
	### -•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+
	### -•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+-•-+

	# end class SOAR_OpenSSLContext
	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •

class SOAR_HTTPAdapter(requests.adapters.HTTPAdapter):
	"""Handle a variety of cert types"""
	def cert_verify(self, conn, url, verify, cert):
		if cert:
			# PKCS12
			if isinstance(cert, PKCS12):
				conn.cert_file = cert.get_certificate()
				conn.key_file = cert.get_privatekey()
				cert = None
			elif isinstance(cert, tuple) and len(cert) == 2:
				# X509 and PKey
				if isinstance(cert[0], X509) and hasattr(cert[1], PKey):
					conn.cert_file = cert[0]
					conn.key_file = cert[1]
					cert = None
				# cryptography objects
				elif hasattr(cert[0], 'public_bytes') and hasattr(cert[1], 'private_bytes'):
					conn.cert_file = X509.from_cryptography(cert[0])
					conn.key_file = PKey.from_cryptography_key(cert[1])
					cert = None
		super().cert_verify(conn, url, verify, cert)

def SOAR_Patch_Request(adapter=True):
	if hasattr(requests.packages.urllib3.util.ssl_, '_is_key_file_encrypted'):
		_is_key_file_encrypted.original = requests.packages.urllib3.util.ssl_._is_key_file_encrypted
		requests.packages.urllib3.util.ssl_._is_key_file_encrypted = _is_key_file_encrypted
	requests.packages.urllib3.util.ssl_.SSLContext = PyOpenSSLContext
	if adapter:
		requests.sessions.HTTPAdapter = SOAR_HTTPAdapter


# In[ ]:


class ShaOneHashAlgorithm:

	def __init__(		self			\
					,	data:	bytes	=	None):
		self.data = data
		self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

	@staticmethod
	def rotate(		n:	int
				,	b:	int) -> int:
		return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

	def padding(self) -> bytes:
		padding = b'\x80' + b'\x00' * (63 - (len(self.data) + 8) % 64)
		padded_data = self.data + padding + struct.pack('>Q', 8 * len(self.data))
		return padded_data

	def split_blocks(self) -> list:
		return	[
					self.padded_data[i : i + 64] for i in range(0, len(self.padded_data), 64)
				]

	def expand_block(		self			\
						,	block:	bytes	=	None) -> list:
		w = list(struct.unpack('>16L', block)) + [0] * 64
		for i in range(16, 80):
			w[i] = self.rotate((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1)
		return w

	def GetHashValueAsString(self) -> str:
		self.padded_data = self.padding()
		self.blocks = self.split_blocks()
		for block in self.blocks:
			expanded_block = self.expand_block(block)
			a, b, c, d, e = self.h
			for i in range(80):
				if 0 <= i < 20:
					f = (b & c) | ((~b) & d)
					k = 0x5A827999
				elif 20 <= i < 40:
					f = b ^ c ^ d
					k = 0x6ED9EBA1
				elif 40 <= i < 60:
					f = (b & c) | (b & d) | (c & d)
					k = 0x8F1BBCDC
				elif 60 <= i < 80:
					f = b ^ c ^ d
					k = 0xCA62C1D6
				a, b, c, d, e =	(
									self.rotate(a, 5) + f + e + k + expanded_block[i] & 0xFFFFFFFF,
									a,
									self.rotate(b, 30),
									c,
									d,
								)
			self.h = (
				self.h[0] + a & 0xFFFFFFFF,
				self.h[1] + b & 0xFFFFFFFF,
				self.h[2] + c & 0xFFFFFFFF,
				self.h[3] + d & 0xFFFFFFFF,
				self.h[4] + e & 0xFFFFFFFF,
			)
		return ('{:08x}' * 5).format(*self.h)


# In[ ]:


class Base(object):

	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •
	##
	# @brief	Protected Member Variables
	#
	__debugMode						=	False
	_arg							=	{}
	_maxRetries						=	int(5)
	_sleepTimeAsMiliseconds			=	int(8000)
	_levelFORMAT					=	str('%(asctime)s - %(levelname)s\t- %(message)s') ### format deprecated 2023/05/04 '%(asctime)s - %(name)s - %(levelname)s\t- %(message)s'
	_GUIDregExPattern				=	str('^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$')
	_GUID_REGEX_Pattern				=	str('^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$)')
	_soarGlobalSettings				=	{}

	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •
	##
	# @brief	Public Member Variables
	#
	T							=	TypeVar('T')
	SQL_COPT_SS_ACCESS_TOKEN	=	int(1256)

	##
	# @brief	Base Constructor
	def __init__(		self										\
					,	arg					:	T		=	None	\
					,	soarGlobalSettings	:	dict	=	None):
		self._soarGlobalSettings = soarGlobalSettings
		self._arg = arg

	def CoalesceEmptyNorNoneThenNone(self, _text: str) -> str:
		##
		#	@brief verify if text is empty or null, if nor, return striped text.
		#
		#	Keyword arguments:
		#	@param _text -- the text to verify and strip
		""" verify if text is empty or null, if nor, return striped text """
		return functools.reduce(lambda x, y: x.strip() if	(											\
																	type(x) is str						\
																and	not x is None						\
																and	bool(x) == True						\
																and	not not x							\
																and	not bool(x.strip()) == False		\
																and	x.lower().casefold() != 'none'		\
															) else y, (_text, None))

	def CoalesceExistsOnDictionaryThenEmptyList(self, _dictionary: dict, _keyValue: str) -> T:
		##
		#	@brief verify if value exists by key in dictionary, if yes, return value, if not, return null.
		#
		#	Keyword arguments:
		#	@param _dictionary	-- Dictionary to be verified
		#	@param _keyValue	-- Key-Value to check on Dictionary
		""" verify if text is empty or null, if nor, return striped text """
		return functools.reduce(lambda x, y: x[y] if (y in x) else (), (_dictionary, _keyValue))

	def NFD(self, _text: str) -> str:
		##
		#	@brief normalize a text.
		#
		#	Keyword arguments:
		#	@param _text -- the text to normalize
		""" normalize a text """
		return unicodedata.normalize('NFD', _text)

	def canonical_caseless(self, _text: str) -> str:
		##
		#	@brief casefolding is similar to lowercasing but more aggressive because it is intended to remove all case distinctions in a string.
		#
		#	Keyword arguments:
		#	@param _text -- the text to be casefolded
		""" casefolding is similar to lowercasing but more aggressive because it is intended to remove all case distinctions in a string """
		return self.NFD(self.NFD(_text).casefold())

	def fold_text(self, _text: str) -> str:
		##
		#	@brief transforming/folding text into a single canonical form for comparison.
		#
		#	Keyword arguments:
		#	@param _text -- the text to be fold
		""" transforming/folding text into a single canonical form for comparison """
		if	self.CoalesceEmptyNorNoneThenNone(_text)	!=	None:
			return self.canonical_caseless(_text)
		else:
			return None

	def get_similarity(self, a: str, b: str) -> float:
		##
		#	@brief get string similarity or distance.
		#
		#	Keyword arguments:
		#	@param a -- first string text to compare
		#	@param a -- second string text to compare
		""" transforming/folding text into a single canonical form for comparison """
		if		self.CoalesceEmptyNorNoneThenNone(a)	!=	None	\
			and	self.CoalesceEmptyNorNoneThenNone(b)	!=	None:
			return SequenceMatcher(None, self.fold_text(self.CoalesceEmptyNorNoneThenNone(a)), self.fold_text(self.CoalesceEmptyNorNoneThenNone(b))).ratio()
		else:
			return float(-1)

	def mask_text(self, style: str, length: int, _text: str, HideLength: bool = False, MaskChar: str = 'x') -> str:
		##
		#	@brief mask function should receive a style (left, right, both) and the length of the "unmasked" values.
		#
		#	Keyword arguments:
		#	@param _text -- the text to be masked
		""" masks a given string according to the specified masking style and length """
		if self.CoalesceEmptyNorNoneThenNone(_text) != None:
			masked = ''
			original_length = len(self.CoalesceEmptyNorNoneThenNone(_text))
			#
			if HideLength:
				mask_length = original_length - (2 * length) if style == 'both' else original_length - length
				masked = MaskChar * mask_length
			else:
				masked = MaskChar * original_length

			if		self.fold_text(self.CoalesceEmptyNorNoneThenNone(style))	==	'left':
				unmasked = self.CoalesceEmptyNorNoneThenNone(_text)[:length]
				return unmasked + masked[length:]
			elif	self.fold_text(self.CoalesceEmptyNorNoneThenNone(style))	==	'right':
				unmasked = self.CoalesceEmptyNorNoneThenNone(_text)[-length:]
				return masked[:-length] + unmasked
			elif	self.fold_text(self.CoalesceEmptyNorNoneThenNone(style))	==	'both':
				unmasked_left = self.CoalesceEmptyNorNoneThenNone(_text)[:length]
				unmasked_right = self.CoalesceEmptyNorNoneThenNone(_text)[-length:]
				if HideLength:
					return unmasked_left + masked + unmasked_right
				else:
					return unmasked_left + masked[length:-length] + unmasked_right
			else:
				raise ValueError('Invalid style')
		else:
			return None

	def ParseJWTtoken(self, _token: str) -> dict:
		##
		#	@brief Parse JWT Token.
		#
		#	Keyword arguments:
		#	@param _token -- token to be parsed
		""" Parse JWT Token """
		if _token is None:
			raise ValueError('token is none')
		elif															\
				_token == ''											\
			or	not _token												\
			or	_token.strip() == False:
			raise ValueError('token is empty')
		elif															\
				_token.count('.') != 2									\
			or	'.' in _token == False									\
			or	_token.startswith('eyJ') == False:
			raise ValueError('token is invalid')
		else:
			_token_header = (_token.split('.')[0]).replace('-', '+').replace('_', '/')
			while len(_token_header) % 4:
				_token_header += '='
			_token_payload = (_token.split('.')[1]).replace('-', '+').replace('_', '/')
			while len(_token_payload) % 4:
				_token_payload += '='
			_tokenString = base64.b64decode(_token_payload).decode('utf-8')
			_payloadAsPythonDictionary = json.loads(_tokenString)
			return _payloadAsPythonDictionary

	def GetAccessTokenForSPNbyCertAuthenticationThroughPost(	self																	\
															,	_SPN_ApplicationId:		str		=	None								\
															,	_TenantId:				str		=	None								\
															,	_P12certBytes:			bytes	=	None								\
															,	_P12certKy:				bytes	=	None								\
															,	_ScopeAudienceGUID:		str		=	None								\
															,	_ScopeAudienceDomain:	str		=	'https://graph.microsoft.com'		\
															,	_TimeOutInSeconds:		int		=	int(15)								\
															) -> dict:
		##
		#	@brief Get Access Token For SPN by Cert Authentication Through Post
		#
		#	Keyword arguments:
		#	@param _SPN_ApplicationId -- Service Principal Name (SPN) Application Id
		#	@param _TenantId -- Tenant Id
		#	@param _P12certBytes -- P12 Certificate bytes
		#	@param _P12certKy -- P12 Certificate Key
		#	@param _ScopeAudienceGUID -- Scope Audience GUID
		#	@param _ScopeAudienceDomain -- Scope Audience Domain
		""" Get Access Token For SPN by Cert Authentication Through Post """
		if _SPN_ApplicationId is None:
			raise ValueError('SPN_ApplicationId is none')
		elif															\
				_SPN_ApplicationId == ''								\
			or	not _SPN_ApplicationId									\
			or	_SPN_ApplicationId.strip() == False:
			raise ValueError('SPN_ApplicationId is empty')
		elif															\
			not re.fullmatch(self._GUIDregExPattern, _SPN_ApplicationId):
			raise ValueError('SPN_ApplicationId is invalid')
		#
		if _TenantId is None:
			raise ValueError('TenantId is none')
		elif															\
				_TenantId == ''											\
			or	not _TenantId											\
			or	_TenantId.strip() == False:
			raise ValueError('TenantId is empty')
		elif															\
			not re.fullmatch(self._GUIDregExPattern, _TenantId):
			raise ValueError('TenantId is invalid')
		#
		if _P12certBytes is None:
			raise ValueError('P12certBytes is none')
		elif															\
			len(_P12certBytes) <= 0:									\
			raise ValueError('P12certBytes is empty')
		#
		if _P12certKy is None:
			raise ValueError('token is none')
		elif															\
				_P12certKy == ''										\
			or	not _P12certKy											\
			or	_P12certKy.strip() == False:
			raise ValueError('P12certKy is empty')
		#
		if																\
				not _ScopeAudienceGUID is None							\
			and	not _ScopeAudienceGUID == ''							\
			and not	not _ScopeAudienceGUID								\
			and	not _ScopeAudienceGUID.strip() == False					\
			and not re.fullmatch(self._GUIDregExPattern, _ScopeAudienceGUID):
			raise ValueError('ScopeAudienceGUID is invalid')
		#
		if																\
				not _ScopeAudienceDomain is None						\
			and	not _ScopeAudienceDomain == ''							\
			and not	not _ScopeAudienceDomain							\
			and	not _ScopeAudienceDomain.strip() == False				\
			and	not	(													\
							self.fold_text(_ScopeAudienceDomain.strip())		==		self.fold_text('https://graph.microsoft.com')								\
						or	self.fold_text(_ScopeAudienceDomain.strip())		==		self.fold_text('https://help.kusto.windows.net')							\
						or	self.fold_text(_ScopeAudienceDomain.strip())		==		self.fold_text('https://database.windows.net/')								\
						or	self.fold_text(_ScopeAudienceDomain.strip())		==		self.fold_text('https://storage.azure.com/')								\
						or	self.fold_text(_ScopeAudienceDomain.strip())		==		self.fold_text('https://api.securitycenter.microsoft.com/')					\
						or	self.fold_text(_ScopeAudienceDomain.strip())		==		self.fold_text('https://management.azure.com/')								\
						or	self.fold_text(_ScopeAudienceDomain.strip())		==		self.fold_text('https://management.core.windows.net/')						\
					):
			raise ValueError('_copeAudienceDomain is invalid')
		#
		if																\
			_TimeOutInSeconds	<=	int(1):
			raise ValueError('TimeOutInSeconds is invalid')
		#
		if																\
			(															\
					not _SPN_ApplicationId is None						\
				and	not _SPN_ApplicationId == ''						\
				and not	not _SPN_ApplicationId							\
				and	not _SPN_ApplicationId.strip() == False				\
			) and														\
			(															\
					not _TenantId is None								\
				and	not _TenantId == ''									\
				and not	not _TenantId									\
				and	not _TenantId.strip() == False						\
			) and														\
			(															\
					not _P12certBytes is None							\
				and	len(_P12certBytes) > 0								\
			) and														\
			(															\
					not _P12certKy is None								\
				and	not _P12certKy == ''								\
				and not	not _P12certKy									\
				and	not _P12certKy.strip() == False						\
			) and														\
			(															\
				(														\
						not _ScopeAudienceDomain is None				\
					and	not _ScopeAudienceDomain == ''					\
					and not	not _ScopeAudienceDomain					\
					and	not _ScopeAudienceDomain.strip() == False		\
				) or													\
				(														\
						not _ScopeAudienceGUID is None					\
					and	not _ScopeAudienceGUID == ''					\
					and not	not _ScopeAudienceGUID						\
					and	not _ScopeAudienceGUID.strip() == False			\
				)														\
			):
			# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •
			#	 \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \_
			#	_/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/ 
			#	 \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \_
			#	_/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/ 
			#	 \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \_
			#	_/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/ 
			#	 \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \_
			#	_/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/ 
			#	 \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \_
			#	_/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/ 
			#	 \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \_
			#	_/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/ 
			#	 \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \_
			#	_/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/ 
			# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •
			#
			_ReturnArrayList	=	{}
			#
			for currentTry in range(self._maxRetries):
				#
				currentTry_ProcessResult	=	False
				#
				#
				#
				#
				#
				try:
					#
					_p12PK, _p12C											=	pkcs12.load_key_and_certificates(_P12certBytes, _P12certKy)[:2]
					#
					# # # # # # deprecated 2023/03/08, Re-Enabled after GuardianV2 findings 2023/12/13
					# # # # # # deprecated 2024/01/02
					# # # # _p12													=	OpenSSL.crypto.load_pkcs12(_P12certBytes, _P12certKy)
					# # # # _sha1Fingerprint										=	_p12._cert.digest('sha1')				
					#
					# # # # Remove OpenSSL reference to gather fingerprint
					_certOnPemFormat										=	_p12C.public_bytes(encoding = serialization.Encoding.PEM)
					_certOnPemFormatDecoded									=	_certOnPemFormat.decode('utf-8')
					_certOnPemCleanFormat									=	_certOnPemFormatDecoded.removeprefix('-----BEGIN CERTIFICATE-----\n').removesuffix('-----END CERTIFICATE-----\n').replace('\n', '').strip()
					_certOnPemCleanB64Decoded								=	base64.b64decode(_certOnPemCleanFormat)
					_certOnPemCleanHashLower								=	ShaOneHashAlgorithm(_certOnPemCleanB64Decoded).GetHashValueAsString()
					_certOnPemCleanHashUpper								=	_certOnPemCleanHashLower.upper()
					_sha1Fingerprint										=	(':'.join(_certOnPemCleanHashUpper[i : i + 2] for i in range(0, len(_certOnPemCleanHashUpper), 2))).encode('utf-8')
					#
					_sha1FingerprintHexArray								=	(_sha1Fingerprint.decode()).split(':')
					_sha1FingerprintCDT										=	bytes([int(_h,16) for _h in _sha1FingerprintHexArray])
					_sha1FingerprintX5T										=	base64.b64encode(_sha1FingerprintCDT)
					_sha1FingerprintX5TasString								=	_sha1FingerprintX5T.decode()
					_sha1FingerprintAsString								=	_sha1FingerprintX5TasString
					#
					# # # # # # Deprecated after GuardianV2 findings 2023/12/13
					# # # # _sha1Fingerprint										=	_p12C.fingerprint(hashes.SHA1())
					# # # # _sha1FingerprintAsString								=	(base64.b64encode(_sha1Fingerprint)).decode()
					#
					_AccessTokenByPost_TokenCertificateBase64Hash			=	re.sub('=', '', re.sub('/', '_', re.sub('\+', '-', _sha1FingerprintAsString)))
					#
					# Create JWT timestamp for expiration
					_AccessTokenByPost_TokenStartDate						=	datetime(1970, 1, 1, 0, 0, 0, 0)
					_AccessTokenByPost_TokenStartDate						=	_AccessTokenByPost_TokenStartDate.replace(tzinfo=timezone.utc)
					_AccessTokenByPost_TokenEndDate							=	datetime.now(timezone.utc) + timedelta(minutes=2)
					_AccessTokenByPost_TokenDeltaDate						=	_AccessTokenByPost_TokenEndDate - _AccessTokenByPost_TokenStartDate
					_AccessTokenByPost_TokenDeltaTimeSpan					=	_AccessTokenByPost_TokenDeltaDate.total_seconds()
					_AccessTokenByPost_TokenJWTExpiration					=	round(_AccessTokenByPost_TokenDeltaTimeSpan, 0)
					_AccessTokenByPost_TokenJWTExpiration					=	math.trunc(_AccessTokenByPost_TokenDeltaTimeSpan)
					# Create JWT validity start timestamp
					_AccessTokenByPost_TokenNotBeforeExpirationTimeSpan		=	(datetime.now(timezone.utc) - _AccessTokenByPost_TokenStartDate).total_seconds()
					_AccessTokenByPost_TokenNotBefore						=	math.trunc(_AccessTokenByPost_TokenNotBeforeExpirationTimeSpan)
					#
					## on the first attempt, we'll try to send SNI + Cert info
					#
					if	currentTry	<=	0:
						#
						#
						# Create JWT header w/x5c for SubjectName+Issuer
						## ## ref : https://datatracker.ietf.org/doc/html/rfc7515#appendix-B
						_AccessTokenByPost_TokenJWTHeader						=	{																			\
																							'x5t'	:	_AccessTokenByPost_TokenCertificateBase64Hash			\
																						,	'typ'	:	'JWT'													\
																						,	'alg'	:	'RS256'													\
																						,	'x5c'	:	_certOnPemCleanFormat									\
																					}
						#
						#
					else:
						#
						#
						# Create JWT header
						_AccessTokenByPost_TokenJWTHeader						=	{																			\
																							'x5t'	:	_AccessTokenByPost_TokenCertificateBase64Hash			\
																						,	'typ'	:	'JWT'													\
																						,	'alg'	:	'RS256'													\
																					}
						#
						#
						#
					# Define Token URI (aud)
					_AccessTokenByPost_TokenUrl								=		'https://login.microsoftonline.com/'	\
																				+	_TenantId								\
																				+	'/oauth2/v2.0/token'
					# Create JWT payload
					_AccessTokenByPost_TokenJWTPayload						=	{
																						'aud'	:	_AccessTokenByPost_TokenUrl					# What endpoint is allowed to use this JWT
																					,	'exp'	:	_AccessTokenByPost_TokenJWTExpiration		# Expiration timestamp
																					,	'iss'	:	_SPN_ApplicationId							# Issuer = your application
																					,	'jti'	:	str(uuid.uuid4())							# JWT ID: random guid
																					,	'nbf'	:	_AccessTokenByPost_TokenNotBefore			# Not to be used before
																					,	'sub'	:	_SPN_ApplicationId							# JWT Subject
																				}
					# Create a signature of the JWT
					# # # # # # deprecated 2023/03/08
					# # # # _p12PrivateKeyBytes										=	OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, _p12.get_privatekey())
					# # # # _p12Ky													=	_p12PrivateKeyBytes.decode('utf-8')
					#
					_p12PrivateKeyBytes										=	_p12PK.private_bytes(																						\
																											encoding				=	serialization.Encoding.PEM							\
																										,	format					=	serialization.PrivateFormat.TraditionalOpenSSL		\
																										,	encryption_algorithm	=	serialization.NoEncryption()						\
																									)
					_p12Ky													=	_p12PrivateKeyBytes.decode('utf-8')
					#
					_AccessTokenByPost_TokenSignature						=	jwt.encode(																					\
																										payload			=	_AccessTokenByPost_TokenJWTPayload				\
																									,	key				=	_p12Ky											\
																									,	algorithm		=	'RS256'											\
																									,	headers			=	_AccessTokenByPost_TokenJWTHeader				\
																							)
					# Join the signature to the JWT with '.'
					_AccessTokenByPost_TokenJWT								=	_AccessTokenByPost_TokenSignature
					#
					if															\
						(														\
								not _ScopeAudienceGUID is None					\
							and	not _ScopeAudienceGUID == ''					\
							and not	not _ScopeAudienceGUID						\
							and	not _ScopeAudienceGUID.strip() == False			\
						):
						_AccessTokenByPost_TokenRequestBody		=	{
																			'client_id'					:	_SPN_ApplicationId																	\
																		,	'client_assertion'			:	_AccessTokenByPost_TokenJWT															\
																		,	'client_assertion_type'		:	'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'							\
																		,	'scope'						:	'{audicene}/.default'.format(audicene = _ScopeAudienceGUID)							\
																		,	'grant_type'				:	'client_credentials'																\
																		,	'ContentType'				:	'application/x-www-form-urlencoded'													\
																	}
					elif														\
						(														\
								not _ScopeAudienceDomain is None				\
							and	not _ScopeAudienceDomain == ''					\
							and not	not _ScopeAudienceDomain					\
							and	not _ScopeAudienceDomain.strip() == False		\
						):
						_AccessTokenByPost_TokenRequestBody		=	{
																			'client_id'					:	_SPN_ApplicationId																	\
																		,	'client_assertion'			:	_AccessTokenByPost_TokenJWT															\
																		,	'client_assertion_type'		:	'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'							\
																		,	'scope'						:	'{audicene_domain}/.default'.format(audicene_domain = _ScopeAudienceDomain)			\
																		,	'grant_type'				:	'client_credentials'																\
																	}
					else:
						raise ValueError('Error : [ScopeAudienceDomain] or [ScopeAudienceGUID] is required, you need to include at least one of them.')
					# Use the self-generated JWT as Authorization
					_AccessTokenByPost_TokenHeader		=	{
																'Authorization'		:		'Bearer {TokenJWT}'.format(TokenJWT = _AccessTokenByPost_TokenJWT)
															}
					#
					_AccessTokenByPost_Token_Response	=		requests.post(																	\
																					url				=	_AccessTokenByPost_TokenUrl				\
																				,	data			=	_AccessTokenByPost_TokenRequestBody		\
																				,	headers			=	_AccessTokenByPost_TokenHeader			\
																				,	timeout			=	_TimeOutInSeconds						\
																			)
					#
					if not _AccessTokenByPost_Token_Response is None:
						if		_AccessTokenByPost_Token_Response.status_code >= int(200)	\
							and	_AccessTokenByPost_Token_Response.status_code <= int(299):
							_responseContentAsJson									=		json.loads(_AccessTokenByPost_Token_Response.text)
							if 'access_token' in _responseContentAsJson:
								_AccessTokenByPost_Token_Info						=		self.ParseJWTtoken(_responseContentAsJson['access_token'])
								_ReturnArrayList	=			{																																					\
																		'token_type'			:			str(self.CoalesceEmptyNorNoneThenNone(_responseContentAsJson['token_type']))							\
																	,	'expires_in'			:			int(_responseContentAsJson['expires_in'])																\
																	,	'ext_expires_in'		:			int(_responseContentAsJson['ext_expires_in'])															\
																	,	'access_token'			:			str(self.CoalesceEmptyNorNoneThenNone(_responseContentAsJson['access_token']))							\
																	,	'aud'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByPost_Token_Info['aud']))							\
																	,	'iss'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByPost_Token_Info['iss']))							\
																	,	'iat'					:			int(_AccessTokenByPost_Token_Info['iat'])																\
																	,	'nbf'					:			int(_AccessTokenByPost_Token_Info['nbf'])																\
																	,	'exp'					:			int(_AccessTokenByPost_Token_Info['exp'])																\
																	,	'aio'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByPost_Token_Info['aio']))							\
																	,	'appid'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByPost_Token_Info['appid']))							\
																	,	'appidacr'				:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByPost_Token_Info['appidacr']))						\
																	,	'groups'				:			tuple(self.CoalesceExistsOnDictionaryThenEmptyList(_AccessTokenByPost_Token_Info,	'groups'))			\
																	,	'idp'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByPost_Token_Info['idp']))							\
																	,	'oid'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByPost_Token_Info['oid']))							\
																	,	'rh'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByPost_Token_Info['rh']))								\
																	,	'roles'					:			tuple(self.CoalesceExistsOnDictionaryThenEmptyList(_AccessTokenByPost_Token_Info,	'roles'))			\
																	,	'sub'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByPost_Token_Info['sub']))							\
																	,	'tid'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByPost_Token_Info['tid']))							\
																	,	'uti'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByPost_Token_Info['uti']))							\
																	,	'ver'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByPost_Token_Info['ver']))							\
																}
								#
								#
								#
								currentTry_ProcessResult	=	True
								break
								#
								#
								#
							else:
								_ReturnArrayList	=	{}
						else:
							_ReturnArrayList	=	{}
					else:
						_ReturnArrayList	=	{}
					#
				except requests.exceptions.HTTPError as httpEerr_:
					self.HandleGLobalException(httpEerr_)
				except requests.exceptions.ConnectionError as cnEerr_:
					self.HandleGLobalException(cnEerr_)
				except requests.exceptions.Timeout as toEerr_:
					self.HandleGLobalException(toEerr_)
				except requests.exceptions.RequestException as reqEx_:
					self.HandleGLobalException(reqEx_)
				except Exception as _exInst:
					self.HandleGLobalException(_exInst)
				#
				#
				#
				#
				#
				if	currentTry_ProcessResult	==	True:
					break
				else:
					time.sleep(int(self._sleepTimeAsMiliseconds/2000))
					continue
				#
				#
				#
				#
				#
			# # # end for currentTry in range(super()._maxRetries):
			#
			#
			if	currentTry_ProcessResult	==	True:
				return	dict(_ReturnArrayList)
			else:
				return	{}
			#
			#
			# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •
			#	 \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \_
			#	_/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/ 
			#	 \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \_
			#	_/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/ 
			#	 \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \_
			#	_/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/ 
			#	 \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \_
			#	_/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/ 
			#	 \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \_
			#	_/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/ 
			#	 \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \_
			#	_/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/ 
			#	 \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \_
			#	_/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/  \__/ 
			# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •
		else:
			# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •
			return None
			# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •

	def HandleGLobalPostRequestError(												\
											self									\
										,	_reason:		str		=	None		\
										,	_status_code:	int		=	-1			\
										,	_text:			str		=	None		\
										,	_content:		bytes	=	None		\
									):
		##
		#	@brief Handle Post Request Error as Global Function
		#
		#	Keyword arguments:
		#	@param _reason				-- reason
		#	@param _status_code			-- status code
		#	@param _text				-- text
		#	@param _content				-- content
		"""Handle Post Request Error as Global Function"""
		global strGlobalErrorOrExceptionMessagesAsList
		global bGlobalErrorOrExceptionMessage
		bGlobalErrorOrExceptionMessage			=	True
		if	self.CoalesceEmptyNorNoneThenNone(_text)	!=	None:
			strGlobalErrorOrExceptionMessagesAsList.append('Reason : {0} - StatusCode : {1} - Text : {2}'.format(str(_reason), str(_status_code), self.CoalesceEmptyNorNoneThenNone(_text)))
			self.HandleGLobalException(_errorOrException = 'Reason : {0} - StatusCode : {1} - Text : {2}'.format(str(_reason), str(_status_code), self.CoalesceEmptyNorNoneThenNone(_text)))
		else:
			strGlobalErrorOrExceptionMessagesAsList.append('Reason : {0} - StatusCode : {1} - Content : {2}'.format(str(_reason), str(_status_code), str(_content.decode('utf-8'))))
			self.HandleGLobalException(_errorOrException = 'Reason : {0} - StatusCode : {1} - Content : {2}'.format(str(_reason), str(_status_code), str(_content.decode('utf-8'))))
		#

	def HandleGLobalException(		self											\
								,	_errorOrException:				T	=	None	\
								,	_stack_trace:					T	=	None):
		##
		#	@brief Handle Exception as Global Function
		#
		#	Keyword arguments:
		#	@param _errorOrException -- Exception
		"""Handle Exception as Global Function"""
		if	  _errorOrException		!=	  None:
			global strGlobalErrorOrExceptionMessagesAsList
			global bGlobalErrorOrExceptionMessage
			if			type(_errorOrException)	 is		pyodbc.Error								\
					or	type(_errorOrException)	 is		pyodbc.ProgrammingError:
				sqlstate_	=	None
				if		len(_errorOrException.args)		>	1:
					sqlstate_								=	_errorOrException.args[1]
				elif	len(_errorOrException.args)		==	1:
					sqlstate_								=	_errorOrException.args[0]
				sqlstate_								=	sqlstate_.split('.')
				if	len(sqlstate_)	>=	3:
					strGlobalErrorOrExceptionMessagesAsList.append('Type : {0} - Exception : {1} - Args : {2}'.format(str(type(_errorOrException)), sqlstate_[-3], _errorOrException.args))
				elif len(sqlstate_)	<=	2:
					strGlobalErrorOrExceptionMessagesAsList.append('Type : {0} - Exception : {1} - Args : {2}'.format(str(type(_errorOrException)), sqlstate_[-2], _errorOrException.args))
				bGlobalErrorOrExceptionMessage			=	True
			elif		type(_errorOrException)	 is		requests.exceptions.HTTPError				\
					or	type(_errorOrException)	 is		requests.exceptions.ConnectionError			\
					or	type(_errorOrException)	 is		requests.exceptions.Timeout					\
					or	type(_errorOrException)	 is		requests.exceptions.RequestException		\
					or	type(_errorOrException)	 is		Exception									\
					or	type(_errorOrException)	 is		BaseException								\
					or	type(_errorOrException)	 is		KeyError									\
					or	type(_errorOrException)	 is		TypeError									\
					or	type(_errorOrException)	 is		json.decoder.JSONDecodeError:
				bGlobalErrorOrExceptionMessage			=	True
				strGlobalErrorOrExceptionMessagesAsList.append('Type : {0} - Exception : {1} - Args : {2}'.format(str(type(_errorOrException)), str(_errorOrException), _errorOrException.args))
			else:
				strGlobalErrorOrExceptionMessagesAsList.append('Type : {0} - Exception : {1}'.format(str(type(_errorOrException)), str(_errorOrException)))
			#
			#
			#
			if	self._soarGlobalSettings	!=	None:
				if	'AppInsightInstrumentationKey'		in	self._soarGlobalSettings:
					if	self.CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AppInsightInstrumentationKey'])	!=	None:
						if	re.fullmatch(self._GUIDregExPattern, self.CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AppInsightInstrumentationKey']))	!=	None:
							guidMatch	=	re.search(self._GUIDregExPattern, self.CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AppInsightInstrumentationKey']))
							if	len(guidMatch.group(0))	==	36:
								appInsightInstrumentationKey_AsGUID		=	guidMatch.group(0)
								#
								for currentTry in range(self._maxRetries):
									#
									currentTry_ProcessResult = False
									#
									try:
										#
										_exception_data	=	{
																	'name'	:	'Microsoft.ApplicationInsights.Exception'
																,	'time'	:	datetime.utcnow().isoformat() + 'Z'
																,	'iKey'	:	appInsightInstrumentationKey_AsGUID
																,	'data'	:	{
																						'baseType'	:	'ExceptionData'
																					,	'baseData'	:	{
																												'ver'			:	2
																											,	'exceptions'	:	[
																																		{
																																				'typeName'		:	str(type(_errorOrException).__name__)
																																			,	'message'		:	str(_errorOrException)
																																			,	'hasFullStack'	:	{True: bool(True), False: bool(False)} [_stack_trace != None]
																																			,	'stack'			:	_stack_trace
																																		}
																																	]
																											,	'properties'	:	{
																																		'className'	:	self.CoalesceEmptyNorNoneThenNone(str(type(self)))
																																	}
																										}
																				}
															}
										#
										_applicationInsightsEndpointURL		=	'https://dc.services.visualstudio.com/v2/track'
										_headers							=	{'Content-Type':'application/json'}
										_response							=	requests.post(														\
																									url		=	_applicationInsightsEndpointURL		\
																								,	headers	=	_headers							\
																								,	json	=	_exception_data						\
																							)
										#
										if	not	_response is None:
											if		_response.status_code >= int(200)	\
												and	_response.status_code <= int(299):
												currentTry_ProcessResult = True
										#
									except requests.RequestException as e:
										self.HandleGLobalException(e)
									#
									if currentTry_ProcessResult == True:
										break
									else:
										time.sleep(int(self._sleepTimeAsMiliseconds / 1000))
										continue
									#
								#
			#
			#
			### If still want to raise the exception afterward, please uncommend next segment
			# if	isinstance(_errorOrException, BaseException):
			# 	raise	_errorOrException
			# else:
			# 	raise ValueError(f"Invalid error or exception: {_errorOrException}")

	def debugger_is_active(self) -> bool:
		##
		#	@brief Return if the debugger is currently active
		"""Return if the debugger is currently active"""
		return hasattr(sys, 'gettrace') and sys.gettrace() is not None

	def logging_debug(self, _text: str):
		##
		#	@brief Write debug output (if the debugger is currently active)
		"""Write debug output (if the debugger is currently active)"""
		if		self.CoalesceEmptyNorNoneThenNone(_text)	!=	None	\
			and	self.debugger_is_active()	==	True						\
			and	self.__debugMode	==	True:
				logging.basicConfig(format=self._levelFORMAT, encoding='utf-8', level=logging.DEBUG)
				logging.debug(self.CoalesceEmptyNorNoneThenNone(_text))

	def logging_error(self, _text: str):
		##
		#	@brief Write error output (if the debugger is currently active)
		"""Write debug output (if the debugger is currently active)"""
		if		self.CoalesceEmptyNorNoneThenNone(_text)	!=	None	\
			and	self.debugger_is_active()	==	True						\
			and	self.__debugMode	==	True:
				logging.basicConfig(format=self._levelFORMAT, encoding='utf-8', level=logging.ERROR)
				logging.error(self.CoalesceEmptyNorNoneThenNone(_text))

	def logging_info(self, _text: str):
		##
		#	@brief Write info output (if the debugger is currently active)
		"""Write info output (if the debugger is currently active)"""
		if		self.CoalesceEmptyNorNoneThenNone(_text)	!=	None	\
			and	self.debugger_is_active()	==	True						\
			and	self.__debugMode	==	True:
				logging.basicConfig(format=self._levelFORMAT, encoding='utf-8', level=logging.INFO)
				logging.info(self.CoalesceEmptyNorNoneThenNone(_text))

	def ParseColumnsListAndRowsListToStronglyTypedPandasDataFrame(		self									\
																	,	columnsList:		list	=	[]		\
																	,	rowsList:			list	=	[]		\
																	) -> pandas.DataFrame:
		##
		#	@brief Parse Columns-List and Rows-List to Strongly-Typed Pandas DataFrame
		#
		#	Keyword arguments:
		#	@param columnsList	-- List of Columns, should be as dictionaries' list in format [{'name':'ColumnName01','type':'string'},{'name':'ColumnName02','type':'int'},{'name':'ColumnName03','type':'guid'}]
		#	@param rowsList		-- List of Rows
		""" Parse Columns-List and Rows-List to Strongly-Typed Pandas DataFrame """
		#
		_tmpReturnCastedPandasDataFrame				=	pandas.DataFrame(None).dropna()
		_returnCastedPandasDataFrame				=	pandas.DataFrame(None).dropna()
		#
		if		len(columnsList)	>	int(0)	\
			and	len(rowsList)		>	int(0):
			if		len(list(filter(lambda x: 'name' in x, columnsList)))	>	int(0)	\
				and	len(list(filter(lambda x: 'type' in x, columnsList)))	>	int(0):
				if	len(list(filter(lambda x: 'name' in x, columnsList)))	==	len(rowsList[0]):
					#
					#
					try:
						returnTableColumns_AsDataFrame			=	pandas.DataFrame(data = columnsList)
						_tmpReturnCastedPandasDataFrame			=	pandas.DataFrame(																		\
																							data	=	rowsList											\
																						,	columns	=	returnTableColumns_AsDataFrame['name'].tolist()		\
																					)
						## let's try to force column data-types
						tableColumns_DataTypes_Casting_AsDict	=	{}
						for rowIndex, rowColumnDataFrame in returnTableColumns_AsDataFrame.iterrows():
							#
							###
							### pandas
							###	dtype 			character_code 	description
							### --------------------------------------------------------------------------------------------------
							###	int8 			i1 				8-bit signed integer
							###	int16 			i2 				16-bit signed integer
							###	int32 			i4 				32-bit signed integer
							###	int64 			i8 				64-bit signed integer
							###	uint8 			u1 				8-bit unsigned integer
							###	uint16 			u2 				16-bit unsigned integer
							###	uint32 			u4 				32-bit unsigned integer
							###	uint64 			u8 				64-bit unsigned integer
							###	float16 		f2 				16-bit floating-point number
							###	float32 		f4 				32-bit floating-point number
							###	float64 		f8 				64-bit floating-point number
							###	float128 		f16 			128-bit floating-point number
							###	complex64 		c8 				64-bit complex floating-point number
							###	complex128 		c16 			128-bit complex floating-point number
							###	complex256 		c32 			256-bit complex floating-point number
							###	bool 			? 				Boolean (True or False)
							###	unicode 		U 				Unicode string
							###	object 			O 				Python objects
							###	datetime64
							###	timedelta[ns]					differece between two datetimes
							###	category						finite list of text values
							###
							###	• numpy.float64		[s = pd.Series([0, 1, 2], dtype=numpy.float64)]
							###	• 'float64'			[s = pd.Series([0, 1, 2], dtype='float64')]
							###	• 'f8'				[s = pd.Series([0, 1, 2], dtype='f8')]
							###
							###	Kusto
							### Type 			Additional name(s) 		Equivalent .NET type 				gettype()
							### --------------------------------------------------------------------------------------------------
							### bool 			boolean 				System.Boolean 						int8
							### datetime 		date 					System.DateTime 					datetime
							### dynamic 								System.Object 						array or dictionary or any of the other values
							### guid 									System.Guid 						guid
							### int 									System.Int32 						int
							### long 									System.Int64 						long
							### real 			double 					System.Double 						real
							### string 									System.String 						string
							### timespan 		time 					System.TimeSpan 					timespan
							### decimal 								System.Data.SqlTypes.SqlDecimal 	decimal
							#
							if		self.fold_text(self.CoalesceEmptyNorNoneThenNone(rowColumnDataFrame['type']))			==		'bool'		\
								or	self.fold_text(self.CoalesceEmptyNorNoneThenNone(rowColumnDataFrame['type']))			==		'boolean':
								tableColumns_DataTypes_Casting_AsDict[rowColumnDataFrame['name']]	=	'bool'
							elif	self.fold_text(self.CoalesceEmptyNorNoneThenNone(rowColumnDataFrame['type']))			==		'datetime'	\
								or	self.fold_text(self.CoalesceEmptyNorNoneThenNone(rowColumnDataFrame['type']))			==		'date':
								tableColumns_DataTypes_Casting_AsDict[rowColumnDataFrame['name']]	=	'datetime64[ns, UTC]'
							elif		self.fold_text(self.CoalesceEmptyNorNoneThenNone(rowColumnDataFrame['type']))		==		'dynamic'	\
									or	self.fold_text(self.CoalesceEmptyNorNoneThenNone(rowColumnDataFrame['type']))		==		'guid'		\
									or	self.fold_text(self.CoalesceEmptyNorNoneThenNone(rowColumnDataFrame['type']))		==		'string':
								tableColumns_DataTypes_Casting_AsDict[rowColumnDataFrame['name']]	=	'unicode'
							elif		self.fold_text(self.CoalesceEmptyNorNoneThenNone(rowColumnDataFrame['type']))		==		'int'		\
									or	self.fold_text(self.CoalesceEmptyNorNoneThenNone(rowColumnDataFrame['type']))		==		'integer'	\
									or	self.fold_text(self.CoalesceEmptyNorNoneThenNone(rowColumnDataFrame['type']))		==		'long':
								tableColumns_DataTypes_Casting_AsDict[rowColumnDataFrame['name']]	=	'int64'
							elif		self.fold_text(self.CoalesceEmptyNorNoneThenNone(rowColumnDataFrame['type']))		==		'real'		\
									or	self.fold_text(self.CoalesceEmptyNorNoneThenNone(rowColumnDataFrame['type']))		==		'decimal':
								tableColumns_DataTypes_Casting_AsDict[rowColumnDataFrame['name']]	=	'float64'
							else:
								tableColumns_DataTypes_Casting_AsDict[rowColumnDataFrame['name']]	=	'object'
							#
							# end for rowColumnDataFrame
						#
						### shape[1] = number columns, shape[0] = number of rows
						if			len(tableColumns_DataTypes_Casting_AsDict)		>		0	\
							and		_tmpReturnCastedPandasDataFrame.shape[1]			>		0	\
							and		len(tableColumns_DataTypes_Casting_AsDict)		==		_tmpReturnCastedPandasDataFrame.shape[1]:
							#
							####	let's try to parse datetime64 before parsing the rest of values, because is incoming with timezone
							for	_n,	_v	in	tableColumns_DataTypes_Casting_AsDict.items():
								if	_v	==	'datetime64[ns, UTC]':
									_tmpReturnCastedPandasDataFrame[_n]	=	pandas.to_datetime(_tmpReturnCastedPandasDataFrame[_n])
							#
							_tmpReturnCastedPandasDataFrame	=	_tmpReturnCastedPandasDataFrame.astype(tableColumns_DataTypes_Casting_AsDict)
							#
						#
						if	_tmpReturnCastedPandasDataFrame.empty	!=	True:
							_returnCastedPandasDataFrame	=	_tmpReturnCastedPandasDataFrame.copy()
							del _tmpReturnCastedPandasDataFrame
						#
					except Exception as _exsInst:
						self.HandleGLobalException(_exsInst)
					#
					#
		#
		return _returnCastedPandasDataFrame
		#

	def GetAccessTokenThroughMSI(		self												\
									,	_linkedServiceNameAsString:		str		=	None	\
								) -> dict:
		##
		#	@brief Get Access Token Through MSI
		#
		#	Keyword arguments:
		#	@param _linkedServiceNameAsString -- _Linked Service Name As String
		""" Get Access Token Through MSI """
		if _linkedServiceNameAsString is None:
			raise ValueError('_linkedServiceNameAsString is none')
		elif													\
				_linkedServiceNameAsString == ''				\
			or	not _linkedServiceNameAsString					\
			or	_linkedServiceNameAsString.strip() == False:
			raise ValueError('_linkedServiceNameAsString is empty')
		#
		try:
			_tmpLinkedServiceTokenByMSI		=	mssparkutils.credentials.getConnectionStringOrCreds(linkedService=_linkedServiceNameAsString)
			if	mssparkutils.credentials.isValidToken(token=_tmpLinkedServiceTokenByMSI)	==	True:
				_AccessTokenByMSI_Token_Info	=	self.ParseJWTtoken(str(self.CoalesceEmptyNorNoneThenNone(_tmpLinkedServiceTokenByMSI)))
				_ReturnArrayList	=			{																																				\
														'access_token'			:			str(self.CoalesceEmptyNorNoneThenNone(_tmpLinkedServiceTokenByMSI))									\
													,	'aud'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByMSI_Token_Info['aud']))							\
													,	'iss'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByMSI_Token_Info['iss']))							\
													,	'iat'					:			int(_AccessTokenByMSI_Token_Info['iat'])															\
													,	'nbf'					:			int(_AccessTokenByMSI_Token_Info['nbf'])															\
													,	'exp'					:			int(_AccessTokenByMSI_Token_Info['exp'])															\
													,	'aio'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByMSI_Token_Info['aio']))							\
													,	'appid'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByMSI_Token_Info['appid']))						\
													,	'appidacr'				:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByMSI_Token_Info['appidacr']))					\
													,	'groups'				:			tuple(self.CoalesceExistsOnDictionaryThenEmptyList(_AccessTokenByMSI_Token_Info,	'groups'))		\
													,	'idp'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByMSI_Token_Info['idp']))							\
													,	'oid'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByMSI_Token_Info['oid']))							\
													,	'rh'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByMSI_Token_Info['rh']))							\
													,	'roles'					:			tuple(self.CoalesceExistsOnDictionaryThenEmptyList(_AccessTokenByMSI_Token_Info,	'roles'))		\
													,	'sub'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByMSI_Token_Info['sub']))							\
													,	'tid'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByMSI_Token_Info['tid']))							\
													,	'uti'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByMSI_Token_Info['uti']))							\
													,	'ver'					:			str(self.CoalesceEmptyNorNoneThenNone(_AccessTokenByMSI_Token_Info['ver']))							\
												}
				del	_AccessTokenByMSI_Token_Info
				del	_tmpLinkedServiceTokenByMSI
				return	dict(_ReturnArrayList)
			else:
				return {}
		except Exception as eX:
			self.HandleGLobalException(eX)

	def HandleTrackEvent(		self												\
							,	_messageAsString:				str		=	None	\
							,	_customAsDict:					dict	=	None):
		##
		#	@brief Handle Track Event on ApplicationInsights
		#
		#	Keyword arguments:
		#	@param _messageAsString	--	Message As String
		#	@param _customAsDict	--	Custom Message as Dictionary
		"""Handle Track Event on ApplicationInsights"""
		if	  self.CoalesceEmptyNorNoneThenNone(_messageAsString) != None:
			if	self._soarGlobalSettings	!=	None:
				if	'AppInsightInstrumentationKey'		in	self._soarGlobalSettings:
					if	self.CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AppInsightInstrumentationKey'])	!=	None:
						if	re.fullmatch(self._GUIDregExPattern, self.CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AppInsightInstrumentationKey']))	!=	None:
							guidMatch	=	re.search(self._GUIDregExPattern, self.CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AppInsightInstrumentationKey']))
							if	len(guidMatch.group(0))	==	36:
								appInsightInstrumentationKey_AsGUID		=	guidMatch.group(0)
								#
								for currentTry in range(self._maxRetries):
									#
									currentTry_ProcessResult = False
									#
									try:
										### ref : https://shipit.dev/python-appinsights/#usage-sample-17
										#
										_dictionaryIsEmpty	=	True
										#
										if _customAsDict != None:
											if len(_customAsDict)	>	int(0):
												_dictionaryIsEmpty	=	False
										#
										_telemetryClient	=	TelemetryClient(appInsightInstrumentationKey_AsGUID)
										#
										if	_dictionaryIsEmpty	==	True:
											_telemetryClient.track_event(self.CoalesceEmptyNorNoneThenNone(_messageAsString))
										else:
											_telemetryClient.track_event(															\
																				self.CoalesceEmptyNorNoneThenNone(_messageAsString)	\
																			,	_customAsDict										\
																		)
										#
										_telemetryClient.flush()
										#
										currentTry_ProcessResult = True
										#
									except Exception as _exInst:
										self.HandleGLobalException(_exInst)
									#
									if currentTry_ProcessResult == True:
										break
									else:
										time.sleep(int(self._sleepTimeAsMiliseconds / 1000))
										continue
									#
								#
			
	def HandleTrackTrace(		self												\
							,	_messageAsString:				str		=	None	\
							,	_customAsDict:					dict	=	None):
		##
		#	@brief Handle Track Trace on ApplicationInsights
		#
		#	Keyword arguments:
		#	@param _messageAsString	--	Message As String
		#	@param _customAsDict	--	Custom Message as Dictionary
		"""Handle Track Trace on ApplicationInsights"""
		if	  self.CoalesceEmptyNorNoneThenNone(_messageAsString) != None:
			if	self._soarGlobalSettings	!=	None:
				if	'AppInsightInstrumentationKey'		in	self._soarGlobalSettings:
					if	self.CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AppInsightInstrumentationKey'])	!=	None:
						if	re.fullmatch(self._GUIDregExPattern, self.CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AppInsightInstrumentationKey']))	!=	None:
							guidMatch	=	re.search(self._GUIDregExPattern, self.CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AppInsightInstrumentationKey']))
							if	len(guidMatch.group(0))	==	36:
								appInsightInstrumentationKey_AsGUID		=	guidMatch.group(0)
								#
								for currentTry in range(self._maxRetries):
									#
									currentTry_ProcessResult = False
									#
									try:
										### ref : https://shipit.dev/python-appinsights/#usage-sample-17
										#
										_dictionaryIsEmpty	=	True
										#
										if _customAsDict != None:
											if len(_customAsDict)	>	int(0):
												_dictionaryIsEmpty	=	False
										#
										_telemetryClient	=	TelemetryClient(appInsightInstrumentationKey_AsGUID)
										#
										if	_dictionaryIsEmpty	==	True:
											_telemetryClient.track_trace(self.CoalesceEmptyNorNoneThenNone(_messageAsString))
										else:
											_telemetryClient.track_trace(															\
																				self.CoalesceEmptyNorNoneThenNone(_messageAsString)	\
																			,	_customAsDict										\
																		)
										#
										_telemetryClient.flush()
										#
										currentTry_ProcessResult = True
										#
									except Exception as _exInst:
										self.HandleGLobalException(_exInst)
									#
									if currentTry_ProcessResult == True:
										break
									else:
										time.sleep(int(self._sleepTimeAsMiliseconds / 1000))
										continue
									#
								#

	def Retrieve_P12_AsString_FromSOARdb(											\
												self								\
											,	settingName:			str			\
											,	tmpSettingsAsDict:		dict		\
										) -> str:
		##
		#	@brief Retrieve IcMP12 AsString From SOAR DB.
		#
		""" Retrieve IcMP12 AsString From SOAR DB """
		if	self.CoalesceEmptyNorNoneThenNone(settingName)	!=	None:
			returnStringValue			=	None
			ReadedDataRowsAsDataFrame	=	pandas.DataFrame(None).dropna()
			dal_AzSQL					=	AzSQL_DAL(tmpSettingsAsDict)
			ReadedDataRowsAsDataFrame	=	dal_AzSQL._Execute_usp_GetP12sBytes_AsPandas(SettingName	=	settingName)
			if			ReadedDataRowsAsDataFrame.empty	!=	True	\
				and		len(ReadedDataRowsAsDataFrame)		>	int(0):
				if	'P12Bytes'	in	ReadedDataRowsAsDataFrame.columns:
					if	self.CoalesceEmptyNorNoneThenNone(ReadedDataRowsAsDataFrame['P12Bytes'].iloc[0])	!=	None:
						returnStringValue	=	self.CoalesceEmptyNorNoneThenNone(ReadedDataRowsAsDataFrame['P12Bytes'].iloc[0])
			return	returnStringValue
		else:
			return None
		#

	# end class Base
	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •


# In[ ]:


class AzSQL_DAL(Base):
	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •
	##
	# @brief	Protected Member Variables
	_soarGlobalSettings = {}

	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •
	##
	# @brief	Public Member Variables
	T							=	TypeVar('T')

	##
	# @brief	AzSQL_DAL Constructor
	def __init__(self, soarGlobalSettings : dict):
		self._soarGlobalSettings = soarGlobalSettings
		super(AzSQL_DAL, self).__init__(soarGlobalSettings = self._soarGlobalSettings)
		#

	def __HandleDateTimeOffsetHierarchy(self, _value: T) -> datetime:
		##
		#	@brief Handle DateTimeOffset as Hierarchy (-155)
		#
		#	Keyword arguments:
		#	@param _value -- DateTimeOffset value to parse
		""" Handle DateTimeOffset as Hierarchy (-155) """
		# # # ref:	https://learn.microsoft.com/en-us/sql/relational-databases/native-client-odbc-date-time/data-type-support-for-odbc-date-and-time-improvements?view=sql-server-ver16
		# # # ref:	https://github.com/mkleehammer/pyodbc/wiki/Using-an-Output-Converter-function
		tupVal	=	struct.unpack('<6hI2h', _value)		# e.g., (2017, 3, 16, 10, 35, 18, 500000000, -6, 0)
		return	datetime(tupVal[0], tupVal[1], tupVal[2], tupVal[3], tupVal[4], tupVal[5], tupVal[6] // 1000, timezone(timedelta(hours = tupVal[7], minutes = tupVal[8])))
		#

	def __HandleBitHierarchy(self, _value: T) -> bool:
		##
		#	@brief Handle bit as Hierarchy (pyodbc.SQL_BIT)
		#
		#	Keyword arguments:
		#	@param _value -- byte value to parse
		"""
		Handle bit as Hierarchy (pyodbc.SQL_BIT) :
		--	--	-------
			id	bit_col
		--	--	-------
		0	-1	None
		1	0	b'\x00'
		2	1	b'\x01'
		--	--	-------
		"""
		r	=	bool(False)
		if	_value	==	b'\x01':
			r	=	bool(True)
		return r
		#

	def _DoExecuteGetCataloguesInfo_AsPandas(										\
													self							\
											) -> list:
		##
		#	@brief Execute USP usp_GetCataloguesInfo Return Result as Pandas DataFrame.
		#
		#	Keyword arguments:
		#	@param N/A
		""" Execute USP usp_GetCataloguesInfo Return Result as Pandas DataFrame """
		#
		azSQLtoken			=	None
		_runMSImodeInsteadCertificateBasedAuth	=	True
		if	'RunMSImodeInsteadCertificateBasedAuth'	in	self._soarGlobalSettings:
			_runMSImodeInsteadCertificateBasedAuth	=	bool(self._soarGlobalSettings['RunMSImodeInsteadCertificateBasedAuth'])
		#
		if		_runMSImodeInsteadCertificateBasedAuth	==	True	\
			and	'AutoAcctAzSQLLinkedServiceName'	in	self._soarGlobalSettings:
			_AutoAcctAzSQLLinkedServiceName_AsString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctAzSQLLinkedServiceName'])
			if	_AutoAcctAzSQLLinkedServiceName_AsString	!=	None:
				azSQLtoken		=	super().GetAccessTokenThroughMSI(_linkedServiceNameAsString=_AutoAcctAzSQLLinkedServiceName_AsString)					
		else:
			azSQLtoken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																										_SPN_ApplicationId		=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppId']			\
																									,	_TenantId				=	self._soarGlobalSettings['AutoAcctSOARtorusTenantId']				\
																									,	_P12certBytes			=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12']			\
																									,	_P12certKy				=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12K']			\
																									,	_ScopeAudienceDomain	=	str('https://database.windows.net/')								\
																								)
		#
		AzSQLRcataloguesResultAsDataFrameList	=	[]
		if			azSQLtoken					!=	None	\
			and		self._soarGlobalSettings	!=	None:
			if	len(azSQLtoken)	>	0:
					if			'access_token'							in	azSQLtoken					\
						and		'AutoAcctSOARtorusAzSQLServerConn'		in	self._soarGlobalSettings:
						if		super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token'])									!=	None	\
							and	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])	!=	None:
							azSQLtokenAsBytes		=	b''
							for i in bytes(super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token']), 'UTF-8'):
								azSQLtokenAsBytes	+=	bytes({i})
								azSQLtokenAsBytes	+=	bytes(1)
							azSQLtokenAsStruct	=	struct.pack('=i', len(azSQLtokenAsBytes)) + azSQLtokenAsBytes
							#
							for currentTry in range(super()._maxRetries):
								#
								currentTry_ProcessResult	=	False
								#
								try:
									connectionString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])
									AzSQLconn_			=	pyodbc.connect(connectionString, attrs_before = { super().SQL_COPT_SS_ACCESS_TOKEN:azSQLtokenAsStruct })
									AzSQLconn_.add_output_converter(-155, self.__HandleDateTimeOffsetHierarchy)
									AzSQLconn_.add_output_converter(pyodbc.SQL_BIT, self.__HandleBitHierarchy)
									uspQueryCommandExec		=			'DECLARE @ProcedureResult [bit];'										\
																	+	'SELECT @ProcedureResult = CONVERT([bit], 0);'							\
																	+	'EXECUTE [soar].[usp_GetCataloguesInfo] @ProcedureResult OUTPUT;'
									AzSQLcolumns		=	None
									AzSQLrows			=	None
									AzSQLcursor_		=	AzSQLconn_.cursor()
									### exex usp
									procedureResult		=	AzSQLcursor_.execute(uspQueryCommandExec)
									### fetch all rowset from execute for tfirst table result
									AzSQLrows			=	[tuple(r) for r in AzSQLcursor_.fetchall()]
									AzSQLcolumns		=	[x[0] for x in AzSQLcursor_.description]
									### convert to data frame
									if		AzSQLcolumns	!=	None	\
										and	AzSQLrows		!=	None:
										if		len(AzSQLcolumns)	>	0	\
											and	len(AzSQLrows)		>	0:
											if		len(AzSQLcolumns)	==	len(AzSQLrows[0]):
												#
												AzSQLRcataloguesResultAsDataFrameList.append(pandas.DataFrame(data = AzSQLrows, columns = AzSQLcolumns))
												AzSQLcolumns		=	None
												AzSQLrows			=	None
												#
									### go next result on a while
									while	AzSQLcursor_.nextset()	==	True:
										AzSQLrows		=	[tuple(r) for r in AzSQLcursor_.fetchall()]
										AzSQLcolumns	=	[x[0] for x in AzSQLcursor_.description]
										### convert to data frame
										if		AzSQLcolumns	!=	None	\
											and	AzSQLrows		!=	None:
											if		len(AzSQLcolumns)	>	0	\
												and	len(AzSQLrows)		>	0:
												if		len(AzSQLcolumns)	==	len(AzSQLrows[0]):
													#
													AzSQLRcataloguesResultAsDataFrameList.append(pandas.DataFrame(data = AzSQLrows, columns = AzSQLcolumns))
													AzSQLcolumns		=	None
													AzSQLrows			=	None
													#
										elif	len(AzSQLcolumns)	>	0	\
											and	len(AzSQLrows)		<=	0:
												#
												currentTry_ProcessResult	=	True
												break
												#
									### close and delete cursor
									AzSQLcursor_.close()
									del AzSQLcursor_
									### close connection
									AzSQLconn_.close()
									del AzSQLconn_
									#
									currentTry_ProcessResult	=	True
									break
									#
								except pyodbc.Error as _pEx:
									super().HandleGLobalException(_pEx)
								except Exception as _exInst:
									super().HandleGLobalException(_exInst)
								#
								if	currentTry_ProcessResult	==	True:
									break
								else:
									time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
									continue
								#
							#
		#
		return AzSQLRcataloguesResultAsDataFrameList
		# end _DoExecuteGetCataloguesInfo_AsPandas

	def _ExecuteInsertNewAlertSynchronizeBatchRecord_AsPandas(										\
																	self							\
																,	_AlertId:				int		\
															) -> pandas.DataFrame:
		##
		#	@brief Execute USP usp_InsertNewAlertSynchronizeBatchRecord Return Result as Pandas DataFrame.
		#
		#	Keyword arguments:
		#	@param _AlertId -- AlertId
		""" Execute USP usp_InsertNewAlertSynchronizeBatchRecord Return Result as Pandas DataFrame """
		#
		azSQLtoken			=	None
		_runMSImodeInsteadCertificateBasedAuth	=	True
		if	'RunMSImodeInsteadCertificateBasedAuth'	in	self._soarGlobalSettings:
			_runMSImodeInsteadCertificateBasedAuth	=	bool(self._soarGlobalSettings['RunMSImodeInsteadCertificateBasedAuth'])
		#
		if		_runMSImodeInsteadCertificateBasedAuth	==	True	\
			and	'AutoAcctAzSQLLinkedServiceName'	in	self._soarGlobalSettings:
			_AutoAcctAzSQLLinkedServiceName_AsString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctAzSQLLinkedServiceName'])
			if	_AutoAcctAzSQLLinkedServiceName_AsString	!=	None:
				azSQLtoken		=	super().GetAccessTokenThroughMSI(_linkedServiceNameAsString=_AutoAcctAzSQLLinkedServiceName_AsString)
		else:
			azSQLtoken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																										_SPN_ApplicationId		=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppId']			\
																									,	_TenantId				=	self._soarGlobalSettings['AutoAcctSOARtorusTenantId']				\
																									,	_P12certBytes			=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12']			\
																									,	_P12certKy				=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12K']			\
																									,	_ScopeAudienceDomain	=	str('https://database.windows.net/')								\
																								)
		#
		AzSQLResultRowsAsDataFrame	=	pandas.DataFrame(None).dropna()
		if			azSQLtoken					!=	None	\
			and		self._soarGlobalSettings	!=	None	\
			and		_AlertId					>	0:
			if	len(azSQLtoken)	>	0:
					if			'access_token'							in	azSQLtoken					\
						and		'AutoAcctSOARtorusAzSQLServerConn'		in	self._soarGlobalSettings:
						if		super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token'])									!=	None	\
							and	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])	!=	None:
							azSQLtokenAsBytes		=	b''
							for i in bytes(super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token']), 'UTF-8'):
								azSQLtokenAsBytes	+=	bytes({i})
								azSQLtokenAsBytes	+=	bytes(1)
							azSQLtokenAsStruct	=	struct.pack('=i', len(azSQLtokenAsBytes)) + azSQLtokenAsBytes
							#
							for currentTry in range(super()._maxRetries):
								#
								currentTry_ProcessResult	=	False
								#
								try:
									connectionString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])
									AzSQLconn_			=	pyodbc.connect(connectionString, attrs_before = { super().SQL_COPT_SS_ACCESS_TOKEN:azSQLtokenAsStruct })
									AzSQLconn_.add_output_converter(-155, self.__HandleDateTimeOffsetHierarchy)
									AzSQLconn_.add_output_converter(pyodbc.SQL_BIT, self.__HandleBitHierarchy)
									uspQueryCommandExec		=			'DECLARE @AlertId [bigint];'																	\
																	+	'DECLARE @OUT_ProcedureResult [bit];'															\
																	+	'DECLARE @OUT_ScopeRow_AlertSyncBatchId [bigint];'												\
																	+	'SELECT @AlertId = CONVERT([bigint], {num});'.format(num = _AlertId)							\
																	+	'EXECUTE [soar].[usp_InsertNewAlertSynchronizeBatchRecord]'										\
																	+	'	@AlertId'																					\
																	+	',	@ProcedureResult = @OUT_ProcedureResult OUTPUT'												\
																	+	',	@ScopeRow_AlertSyncBatchId = @OUT_ScopeRow_AlertSyncBatchId OUTPUT;'
									with	AzSQLconn_.cursor()	as	AzSQLcursor_:
										AzSQLcursor_.execute(uspQueryCommandExec)
										AzSQLcolumns	=	[x[0] for x in AzSQLcursor_.description]
										AzSQLrows		=	[tuple(r) for r in AzSQLcursor_.fetchall()]
									if		AzSQLcolumns	!=	None	\
										and	AzSQLrows		!=	None:
										if		len(AzSQLcolumns)	>	0	\
											and	len(AzSQLrows)		>	0:
											if		len(AzSQLcolumns)	==	len(AzSQLrows[0]):
												#
												AzSQLResultRowsAsDataFrame	=	pandas.DataFrame(data = AzSQLrows, columns = AzSQLcolumns)
												#
												currentTry_ProcessResult	=	True
												break
												#
										elif	len(AzSQLcolumns)	>	0	\
											and	len(AzSQLrows)		<=	0:
												#
												currentTry_ProcessResult	=	True
												break
												#
								except pyodbc.Error as _pEx:
									super().HandleGLobalException(_pEx)
								except Exception as _exInst:
									super().HandleGLobalException(_exInst)
								#
								if	currentTry_ProcessResult	==	True:
									break
								else:
									time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
									continue
								#
							#
		#
		return AzSQLResultRowsAsDataFrame
		# end _ExecuteInsertNewAlertSynchronizeBatchRecord_AsPandas

	def _ExecuteUpdateExistentAlertSynchronizeBatchRecord_AsPandas(												\
																		self									\
																	,	_AlertId:						int		\
																	,	_AlertSyncBatchId:				int		\
																	,	_AlertSyncBatchExecutionResult:	bool	\
																	,	_ErrorMessage:					str		\
																) -> pandas.DataFrame:
		##
		#	@brief Execute USP usp_UpdateExistentAlertSynchronizeBatchRecord Return Result as Pandas DataFrame.
		#
		#	Keyword arguments:
		#	@param _AlertId							--	AlertId
		#	@param _AlertSyncBatchId				--	AlertSyncBatchId
		#	@param _AlertSyncBatchExecutionResult	--	AlertSyncBatchExecutionResult
		#	@param _ErrorMessage					--	ErrorMessage
		""" Execute USP usp_UpdateExistentAlertSynchronizeBatchRecord Return Result as Pandas DataFrame """
		#
		azSQLtoken			=	None
		_runMSImodeInsteadCertificateBasedAuth	=	True
		if	'RunMSImodeInsteadCertificateBasedAuth'	in	self._soarGlobalSettings:
			_runMSImodeInsteadCertificateBasedAuth	=	bool(self._soarGlobalSettings['RunMSImodeInsteadCertificateBasedAuth'])
		#
		if		_runMSImodeInsteadCertificateBasedAuth	==	True	\
			and	'AutoAcctAzSQLLinkedServiceName'	in	self._soarGlobalSettings:
			_AutoAcctAzSQLLinkedServiceName_AsString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctAzSQLLinkedServiceName'])
			if	_AutoAcctAzSQLLinkedServiceName_AsString	!=	None:
				azSQLtoken		=	super().GetAccessTokenThroughMSI(_linkedServiceNameAsString=_AutoAcctAzSQLLinkedServiceName_AsString)
		else:
			azSQLtoken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																										_SPN_ApplicationId		=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppId']			\
																									,	_TenantId				=	self._soarGlobalSettings['AutoAcctSOARtorusTenantId']				\
																									,	_P12certBytes			=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12']			\
																									,	_P12certKy				=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12K']			\
																									,	_ScopeAudienceDomain	=	str('https://database.windows.net/')								\
																								)
		#
		AzSQLResultRowsAsDataFrame	=	pandas.DataFrame(None).dropna()
		if			azSQLtoken					!=	None	\
			and		self._soarGlobalSettings	!=	None	\
			and		_AlertId					>	0		\
			and		_AlertSyncBatchId			>	0:
			if	len(azSQLtoken)	>	0:
					if			'access_token'							in	azSQLtoken					\
						and		'AutoAcctSOARtorusAzSQLServerConn'		in	self._soarGlobalSettings:
						if		super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token'])									!=	None	\
							and	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])	!=	None:
							azSQLtokenAsBytes		=	b''
							for i in bytes(super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token']), 'UTF-8'):
								azSQLtokenAsBytes	+=	bytes({i})
								azSQLtokenAsBytes	+=	bytes(1)
							azSQLtokenAsStruct	=	struct.pack('=i', len(azSQLtokenAsBytes)) + azSQLtokenAsBytes
							#
							for currentTry in range(super()._maxRetries):
								#
								currentTry_ProcessResult	=	False
								#
								try:
									connectionString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])
									AzSQLconn_			=	pyodbc.connect(connectionString, attrs_before = { super().SQL_COPT_SS_ACCESS_TOKEN:azSQLtokenAsStruct })
									AzSQLconn_.add_output_converter(-155, self.__HandleDateTimeOffsetHierarchy)
									AzSQLconn_.add_output_converter(pyodbc.SQL_BIT, self.__HandleBitHierarchy)
									uspQueryCommandExec		=			'DECLARE @AlertId [bigint];'																	\
																	+	'DECLARE @AlertSyncBatchId [bigint];'															\
																	+	'DECLARE @AlertSyncBatchExecutionResult [bit];'													\
																	+	'DECLARE @ErrorMessage [nvarchar](max);'														\
																	+	'DECLARE @OUT_ProcedureResult [bit];'															\
																	+	'DECLARE @OUT_ScopeRow_AlertSyncBatchId [bigint];'												\
																	+	'SELECT @AlertId = CONVERT([bigint], {num});'.format(num = _AlertId)							\
																	+	'SELECT @AlertSyncBatchId = CONVERT([bigint], {num});'.format(num = _AlertSyncBatchId)			\
																	+	'SELECT @AlertSyncBatchExecutionResult = CONVERT([bit], {boolean_value});'.format(boolean_value = '1'	if	_AlertSyncBatchExecutionResult	==	True	else	'0')	\
																	+	'SELECT	@ErrorMessage	=	'	+	str('\'{string_value}\';'.format(string_value = (super().CoalesceEmptyNorNoneThenNone(_ErrorMessage)).replace('\'', '').replace('"', '')	if	super().CoalesceEmptyNorNoneThenNone(_ErrorMessage)	!=	None	else	'NULL;'))	\
																	+	'EXECUTE [soar].[usp_UpdateExistentAlertSynchronizeBatchRecord]'								\
																	+	'	@AlertId'																					\
																	+	',	@AlertSyncBatchId'																			\
																	+	',	@AlertSyncBatchExecutionResult'																\
																	+	',	@ErrorMessage'																				\
																	+	',	@ProcedureResult = @OUT_ProcedureResult OUTPUT'												\
																	+	',	@ScopeRow_AlertSyncBatchId = @OUT_ScopeRow_AlertSyncBatchId OUTPUT;'
									with	AzSQLconn_.cursor()	as	AzSQLcursor_:
										AzSQLcursor_.execute(uspQueryCommandExec)
										AzSQLcolumns	=	[x[0] for x in AzSQLcursor_.description]
										AzSQLrows		=	[tuple(r) for r in AzSQLcursor_.fetchall()]
									if		AzSQLcolumns	!=	None	\
										and	AzSQLrows		!=	None:
										if		len(AzSQLcolumns)	>	0	\
											and	len(AzSQLrows)		>	0:
											if		len(AzSQLcolumns)	==	len(AzSQLrows[0]):
												#
												AzSQLResultRowsAsDataFrame	=	pandas.DataFrame(data = AzSQLrows, columns = AzSQLcolumns)
												#
												currentTry_ProcessResult	=	True
												break
												#
										elif	len(AzSQLcolumns)	>	0	\
											and	len(AzSQLrows)		<=	0:
												#
												currentTry_ProcessResult	=	True
												break
												#
								except pyodbc.Error as _pEx:
									super().HandleGLobalException(_pEx)
								except Exception as _exInst:
									super().HandleGLobalException(_exInst)
								#
								if	currentTry_ProcessResult	==	True:
									break
								else:
									time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
									continue
								#
							#
		#
		return AzSQLResultRowsAsDataFrame
		# end _ExecuteUpdateExistentAlertSynchronizeBatchRecord_AsPandas

	def _ExecuteGenericRetrievalUSP_AsPandas(											\
													self								\
												,	_uspName:				str			\
												,	_inputParameters:		tuple = {}	\
											) -> T:
		##
		#	@brief Execute Generic Retrieval Stored Procedure, return result as Pandas DataFrame.
		#
		#	Keyword arguments:
		#	@param _uspName -- Stored Procedure Name (schema should be specified)
		#	@param _inputParameters -- Stored Procedure Input Parameters
		""" Execute Generic Retrieval Stored Procedure, return result as Pandas DataFrame """
		#
		azSQLtoken			=	None
		_runMSImodeInsteadCertificateBasedAuth	=	True
		if	'RunMSImodeInsteadCertificateBasedAuth'	in	self._soarGlobalSettings:
			_runMSImodeInsteadCertificateBasedAuth	=	bool(self._soarGlobalSettings['RunMSImodeInsteadCertificateBasedAuth'])
		#
		if		_runMSImodeInsteadCertificateBasedAuth	==	True	\
			and	'AutoAcctAzSQLLinkedServiceName'	in	self._soarGlobalSettings:
			_AutoAcctAzSQLLinkedServiceName_AsString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctAzSQLLinkedServiceName'])
			if	_AutoAcctAzSQLLinkedServiceName_AsString	!=	None:
				azSQLtoken		=	super().GetAccessTokenThroughMSI(_linkedServiceNameAsString=_AutoAcctAzSQLLinkedServiceName_AsString)
		else:
			azSQLtoken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																										_SPN_ApplicationId		=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppId']			\
																									,	_TenantId				=	self._soarGlobalSettings['AutoAcctSOARtorusTenantId']				\
																									,	_P12certBytes			=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12']			\
																									,	_P12certKy				=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12K']			\
																									,	_ScopeAudienceDomain	=	str('https://database.windows.net/')								\
																								)
		#
		AzSQLrowsAsDataFrame	=	pandas.DataFrame(None).dropna()
		if			azSQLtoken					!=	None	\
			and		self._soarGlobalSettings	!=	None:
			if	len(azSQLtoken)	>	0:
					if			'access_token'							in	azSQLtoken					\
						and		'AutoAcctSOARtorusAzSQLServerConn'		in	self._soarGlobalSettings:
						if		super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token'])									!=	None	\
							and	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])	!=	None	\
							and	super().CoalesceEmptyNorNoneThenNone(_uspName)														!=	None:
							azSQLtokenAsBytes		=	b''
							for i in bytes(super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token']), 'UTF-8'):
								azSQLtokenAsBytes	+=	bytes({i})
								azSQLtokenAsBytes	+=	bytes(1)
							azSQLtokenAsStruct	=	struct.pack('=i', len(azSQLtokenAsBytes)) + azSQLtokenAsBytes
							#
							for currentTry in range(super()._maxRetries):
								#
								currentTry_ProcessResult	=	False
								#
								try:
									connectionString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])
									AzSQLconn_			=	pyodbc.connect(connectionString, attrs_before = { super().SQL_COPT_SS_ACCESS_TOKEN:azSQLtokenAsStruct })
									AzSQLconn_.add_output_converter(-155, self.__HandleDateTimeOffsetHierarchy)
									AzSQLconn_.add_output_converter(pyodbc.SQL_BIT, self.__HandleBitHierarchy)
									with	AzSQLconn_.cursor()	as	AzSQLcursor_:
										AzSQLcursor_.execute(_uspName)
										AzSQLcolumns	=	[x[0] for x in AzSQLcursor_.description]
										AzSQLrows		=	[tuple(r) for r in AzSQLcursor_.fetchall()]
									if		AzSQLcolumns	!=	None	\
										and	AzSQLrows		!=	None:
										if		len(AzSQLcolumns)	>	0	\
											and	len(AzSQLrows)		>	0:
											if		len(AzSQLcolumns)	==	len(AzSQLrows[0]):
												AzSQLrowsAsDataFrame	=	pandas.DataFrame(data = AzSQLrows, columns = AzSQLcolumns)
												#
												currentTry_ProcessResult	=	True
												break
												#
										elif	len(AzSQLcolumns)	>	0	\
											and	len(AzSQLrows)		<=	0:
												#
												currentTry_ProcessResult	=	True
												break
												#
								except pyodbc.Error as _pEx:
									super().HandleGLobalException(_pEx)
								except Exception as _exInst:
									super().HandleGLobalException(_exInst)
								#
								if	currentTry_ProcessResult	==	True:
									break
								else:
									time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
									continue
								#
							#
		#
		return AzSQLrowsAsDataFrame
		# end _ExecuteGenericRetrieveUSP_AsPandas

	def _ExecuteGetOpenOrUnexpiredTicketByResourceIdAsGUID_AsPandas(													\
																			self										\
																		,	_ResourceIdAsGUID:					str		\
																		,	_TenantId:							str		\
																		,	_ExternalReferenceTypeName:			str		\
																		,	_ExternalReferenceCaseComments:		str		\
																		,	_TimeForTicketExpirationInHours:	int		\
																	) -> pandas.DataFrame:
		##
		#	@brief Execute USP usp_GetOpenOrUnexpiredTicketAndExternalReferenceByResourceIdAsGUID Return Result as Pandas DataFrame.
		#
		#	Keyword arguments
		#	@param _ResourceIdAsGUID				--	ResourceIdAsGUID
		#	@param _TenantId						--	TenantId
		#	@param _ExternalReferenceTypeName		--	ExternalReferenceTypeName
		#	@param _ExternalReferenceCaseComments	--	ExternalReferenceCaseComments
		#	@param _TimeForTicketExpirationInHours	--	TimeForTicketExpirationInHours
		""" Execute USP usp_GetOpenOrUnexpiredTicketAndExternalReferenceByResourceIdAsGUID Return Result as Pandas DataFrame """
		#
		azSQLtoken			=	None
		_runMSImodeInsteadCertificateBasedAuth	=	True
		if	'RunMSImodeInsteadCertificateBasedAuth'	in	self._soarGlobalSettings:
			_runMSImodeInsteadCertificateBasedAuth	=	bool(self._soarGlobalSettings['RunMSImodeInsteadCertificateBasedAuth'])
		#
		if		_runMSImodeInsteadCertificateBasedAuth	==	True	\
			and	'AutoAcctAzSQLLinkedServiceName'	in	self._soarGlobalSettings:
			_AutoAcctAzSQLLinkedServiceName_AsString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctAzSQLLinkedServiceName'])
			if	_AutoAcctAzSQLLinkedServiceName_AsString	!=	None:
				azSQLtoken		=	super().GetAccessTokenThroughMSI(_linkedServiceNameAsString=_AutoAcctAzSQLLinkedServiceName_AsString)
		else:
			azSQLtoken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																										_SPN_ApplicationId		=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppId']			\
																									,	_TenantId				=	self._soarGlobalSettings['AutoAcctSOARtorusTenantId']				\
																									,	_P12certBytes			=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12']			\
																									,	_P12certKy				=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12K']			\
																									,	_ScopeAudienceDomain	=	str('https://database.windows.net/')								\
																								)
		#
		AzSQLResultRowsAsDataFrame	=	pandas.DataFrame(None).dropna()
		if			azSQLtoken					!=	None	\
			and		self._soarGlobalSettings	!=	None	\
			and		_TimeForTicketExpirationInHours					>	0:
			if	len(azSQLtoken)	>	0:
					if			'access_token'							in	azSQLtoken					\
						and		'AutoAcctSOARtorusAzSQLServerConn'		in	self._soarGlobalSettings:
						if		super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token'])									!=	None	\
							and	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])	!=	None:
							azSQLtokenAsBytes		=	b''
							for i in bytes(super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token']), 'UTF-8'):
								azSQLtokenAsBytes	+=	bytes({i})
								azSQLtokenAsBytes	+=	bytes(1)
							azSQLtokenAsStruct	=	struct.pack('=i', len(azSQLtokenAsBytes)) + azSQLtokenAsBytes
							#
							for currentTry in range(super()._maxRetries):
								#
								currentTry_ProcessResult	=	False
								#
								try:
									connectionString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])
									AzSQLconn_			=	pyodbc.connect(connectionString, attrs_before = { super().SQL_COPT_SS_ACCESS_TOKEN:azSQLtokenAsStruct })
									AzSQLconn_.add_output_converter(-155, self.__HandleDateTimeOffsetHierarchy)
									AzSQLconn_.add_output_converter(pyodbc.SQL_BIT, self.__HandleBitHierarchy)
									uspQueryCommandExec		=			'DECLARE @Input_ResourceIdAsGUID [uniqueidentifier]; DECLARE @Input_TenantId [uniqueidentifier]; DECLARE @Input_ExternalReferenceTypeName [nvarchar](128); DECLARE @Input_ExternalReferenceCaseComments [nvarchar](4000); DECLARE @Input_TimeForTicketExpirationInHours [int];'		\
																	+	'SELECT @Input_ResourceIdAsGUID =				\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_ResourceIdAsGUID))					\
																	+	'SELECT @Input_TenantId =						\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_TenantId))							\
																	+	'SELECT @Input_ExternalReferenceTypeName =		\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_ExternalReferenceTypeName))		\
																	+	'SELECT @Input_ExternalReferenceCaseComments =	\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_ExternalReferenceCaseComments))	\
																	+	'SELECT @Input_TimeForTicketExpirationInHours =	CONVERT([int], {num});'.format(num = _TimeForTicketExpirationInHours)													\
																	+	'EXECUTE [soar].[usp_GetOpenOrUnexpiredTicketAndExternalReferenceByResourceIdAsGUID] @ResourceIdAsGUID = @Input_ResourceIdAsGUID, @TenantId = @Input_TenantId, @ExternalReferenceTypeName = @Input_ExternalReferenceTypeName, @ExternalReferenceCaseComments = @Input_ExternalReferenceCaseComments, @TimeForTicketExpirationInHours = @Input_TimeForTicketExpirationInHours;'
									with	AzSQLconn_.cursor()	as	AzSQLcursor_:
										AzSQLcursor_.execute(uspQueryCommandExec)
										AzSQLcolumns	=	[x[0] for x in AzSQLcursor_.description]
										AzSQLrows		=	[tuple(r) for r in AzSQLcursor_.fetchall()]
									if		AzSQLcolumns	!=	None	\
										and	AzSQLrows		!=	None:
										if		len(AzSQLcolumns)	>	0	\
											and	len(AzSQLrows)		>	0:
											if		len(AzSQLcolumns)	==	len(AzSQLrows[0]):
												#
												AzSQLResultRowsAsDataFrame	=	pandas.DataFrame(data = AzSQLrows, columns = AzSQLcolumns)
												#
												currentTry_ProcessResult	=	True
												break
												#
										elif	len(AzSQLcolumns)	>	0	\
											and	len(AzSQLrows)		<=	0:
												#
												currentTry_ProcessResult	=	True
												break
												#
								except pyodbc.Error as _pEx:
									super().HandleGLobalException(_pEx)
								except Exception as _exInst:
									super().HandleGLobalException(_exInst)
								#
								if	currentTry_ProcessResult	==	True:
									break
								else:
									time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
									continue
								#
							#
		#
		return AzSQLResultRowsAsDataFrame
		# end _ExecuteInsertNewAlertSynchronizeBatchRecord_AsPandas

	def _ExecuteGetOpenOrUnexpiredTicketByResourceIdAsString_AsPandas(													\
																			self										\
																		,	_ResourceIdAsString:				str		\
																		,	_TenantId:							str		\
																		,	_ExternalReferenceTypeName:			str		\
																		,	_ExternalReferenceCaseComments:		str		\
																		,	_TimeForTicketExpirationInHours:	int		\
																	) -> pandas.DataFrame:
		##
		#	@brief Execute USP usp_GetOpenOrUnexpiredTicketAndExternalReferenceByResourceIdAsString Return Result as Pandas DataFrame.
		#
		#	Keyword arguments
		#	@param _ResourceIdAsString				--	ResourceIdAsString
		#	@param _TenantId						--	TenantId
		#	@param _ExternalReferenceTypeName		--	ExternalReferenceTypeName
		#	@param _ExternalReferenceCaseComments	--	ExternalReferenceCaseComments
		#	@param _TimeForTicketExpirationInHours	--	TimeForTicketExpirationInHours
		""" Execute USP usp_GetOpenOrUnexpiredTicketAndExternalReferenceByResourceIdAsString Return Result as Pandas DataFrame """
		#
		azSQLtoken			=	None
		_runMSImodeInsteadCertificateBasedAuth	=	True
		if	'RunMSImodeInsteadCertificateBasedAuth'	in	self._soarGlobalSettings:
			_runMSImodeInsteadCertificateBasedAuth	=	bool(self._soarGlobalSettings['RunMSImodeInsteadCertificateBasedAuth'])
		#
		if		_runMSImodeInsteadCertificateBasedAuth	==	True	\
			and	'AutoAcctAzSQLLinkedServiceName'	in	self._soarGlobalSettings:
			_AutoAcctAzSQLLinkedServiceName_AsString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctAzSQLLinkedServiceName'])
			if	_AutoAcctAzSQLLinkedServiceName_AsString	!=	None:
				azSQLtoken		=	super().GetAccessTokenThroughMSI(_linkedServiceNameAsString=_AutoAcctAzSQLLinkedServiceName_AsString)
		else:
			azSQLtoken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																										_SPN_ApplicationId		=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppId']			\
																									,	_TenantId				=	self._soarGlobalSettings['AutoAcctSOARtorusTenantId']				\
																									,	_P12certBytes			=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12']			\
																									,	_P12certKy				=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12K']			\
																									,	_ScopeAudienceDomain	=	str('https://database.windows.net/')								\
																								)
		#
		AzSQLResultRowsAsDataFrame	=	pandas.DataFrame(None).dropna()
		if			azSQLtoken					!=	None	\
			and		self._soarGlobalSettings	!=	None	\
			and		_TimeForTicketExpirationInHours					>	0:
			if	len(azSQLtoken)	>	0:
					if			'access_token'							in	azSQLtoken					\
						and		'AutoAcctSOARtorusAzSQLServerConn'		in	self._soarGlobalSettings:
						if		super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token'])									!=	None	\
							and	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])	!=	None:
							azSQLtokenAsBytes		=	b''
							for i in bytes(super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token']), 'UTF-8'):
								azSQLtokenAsBytes	+=	bytes({i})
								azSQLtokenAsBytes	+=	bytes(1)
							azSQLtokenAsStruct	=	struct.pack('=i', len(azSQLtokenAsBytes)) + azSQLtokenAsBytes
							#
							for currentTry in range(super()._maxRetries):
								#
								currentTry_ProcessResult	=	False
								#
								try:
									connectionString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])
									AzSQLconn_			=	pyodbc.connect(connectionString, attrs_before = { super().SQL_COPT_SS_ACCESS_TOKEN:azSQLtokenAsStruct })
									AzSQLconn_.add_output_converter(-155, self.__HandleDateTimeOffsetHierarchy)
									AzSQLconn_.add_output_converter(pyodbc.SQL_BIT, self.__HandleBitHierarchy)
									uspQueryCommandExec		=			'DECLARE @Input_ResourceIdAsString [varchar](768); DECLARE @Input_TenantId [uniqueidentifier]; DECLARE @Input_ExternalReferenceTypeName [nvarchar](128); DECLARE @Input_ExternalReferenceCaseComments [nvarchar](4000); DECLARE @Input_TimeForTicketExpirationInHours [int];'		\
																	+	'SELECT @Input_ResourceIdAsString =				\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_ResourceIdAsString))					\
																	+	'SELECT @Input_TenantId =						\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_TenantId))							\
																	+	'SELECT @Input_ExternalReferenceTypeName =		\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_ExternalReferenceTypeName))		\
																	+	'SELECT @Input_ExternalReferenceCaseComments =	\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_ExternalReferenceCaseComments))	\
																	+	'SELECT @Input_TimeForTicketExpirationInHours =	CONVERT([int], {num});'.format(num = _TimeForTicketExpirationInHours)													\
																	+	'EXECUTE [soar].[usp_GetOpenOrUnexpiredTicketAndExternalReferenceByResourceIdAsString] @ResourceIdAsString = @Input_ResourceIdAsString, @TenantId = @Input_TenantId, @ExternalReferenceTypeName = @Input_ExternalReferenceTypeName, @ExternalReferenceCaseComments = @Input_ExternalReferenceCaseComments, @TimeForTicketExpirationInHours = @Input_TimeForTicketExpirationInHours;'
									with	AzSQLconn_.cursor()	as	AzSQLcursor_:
										AzSQLcursor_.execute(uspQueryCommandExec)
										AzSQLcolumns	=	[x[0] for x in AzSQLcursor_.description]
										AzSQLrows		=	[tuple(r) for r in AzSQLcursor_.fetchall()]
									if		AzSQLcolumns	!=	None	\
										and	AzSQLrows		!=	None:
										if		len(AzSQLcolumns)	>	0	\
											and	len(AzSQLrows)		>	0:
											if		len(AzSQLcolumns)	==	len(AzSQLrows[0]):
												#
												AzSQLResultRowsAsDataFrame	=	pandas.DataFrame(data = AzSQLrows, columns = AzSQLcolumns)
												#
												currentTry_ProcessResult	=	True
												break
												#
										elif	len(AzSQLcolumns)	>	0	\
											and	len(AzSQLrows)		<=	0:
												#
												currentTry_ProcessResult	=	True
												break
												#
								except pyodbc.Error as _pEx:
									super().HandleGLobalException(_pEx)
								except Exception as _exInst:
									super().HandleGLobalException(_exInst)
								#
								if	currentTry_ProcessResult	==	True:
									break
								else:
									time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
									continue
								#
							#
		#
		return AzSQLResultRowsAsDataFrame
		# end _ExecuteInsertNewAlertSynchronizeBatchRecord_AsPandas

	def _ExecuteInsertNewTicketWithExternalReferenceThroughResourceIdAsGUID_AsPandas(					\
																							self		\
																						,	**kwargs	\
																					) -> list:
		##
		#	@brief Execute USP usp_InsertNewTicketWithExternalReferenceThroughResourceIdAsGUID Return Result as Pandas DataFrame.
		#
		#	Keyword arguments
		#	@param alertSettings_AsJSON							--	alertSettings_AsJSON
		#	@param soarCurrentAlertToProcess_PandasDataFrame	--	soarCurrentAlertToProcess_PandasDataFrame
		#	@param soarAlertConfigs_AsPandasDataFrame			--	soarAlertConfigs_AsPandasDataFrame
		#	@param UserId										--	UserId
		#	@param TicketTypeId									--	TicketTypeId
		#	@param TicketStatusId								--	TicketStatusId
		#	@param TicketSeverityId								--	TicketSeverityId
		#	@param ExternalReferenceTypeId						--	ExternalReferenceTypeId
		#	@param ResourceTypeId								--	ResourceTypeId
		#	@param ExternalReferenceCaseNumber					--	ExternalReferenceCaseNumber
		#	@param ExternalReferenceCaseURL						--	ExternalReferenceCaseURL
		#	@param ExternalReferenceCaseComments				--	ExternalReferenceCaseComments
		#	@param TicketTitle									--	TicketTitle
		#	@param ResourceName									--	ResourceName
		#	@param ResourceIdAsGUID								--	ResourceIdAsGUID
		#	@param ResourceIdAsString							--	ResourceIdAsString
		#	@param ResourceObjectIdAsGUID						--	ResourceObjectIdAsGUID
		#	@param ResourceURL									--	ResourceURL
		#	@param ResourcePATH									--	ResourcePATH
		#	@param ResourceDescription							--	ResourceDescription
		""" Execute USP usp_InsertNewTicketWithExternalReferenceThroughResourceIdAsGUID Return Result as Pandas DataFrame """
		self._arg		=	kwargs
		AzSQLResultRowsAsDataFrame	=	pandas.DataFrame(None).dropna()
		#
		if		'alertSettings_AsJSON'							in	self._arg	\
			and	'soarCurrentAlertToProcess_PandasDataFrame'		in	self._arg	\
			and	'soarAlertConfigs_AsPandasDataFrame'			in	self._arg	\
			and	'UserId'										in	self._arg	\
			and	'TicketTypeId'									in	self._arg	\
			and	'TicketStatusId'								in	self._arg	\
			and	'TicketSeverityId'								in	self._arg	\
			and	'ExternalReferenceTypeId'						in	self._arg	\
			and	'ResourceTypeId'								in	self._arg	\
			and	'ExternalReferenceCaseNumber'					in	self._arg	\
			and	'ExternalReferenceCaseURL'						in	self._arg	\
			and	'ExternalReferenceCaseComments'					in	self._arg	\
			and	'TicketTitle'									in	self._arg:
			#
			_alertSettings_AsJSON							=	self._arg['alertSettings_AsJSON']
			_soarCurrentAlertToProcess_PandasDataFrame		=	self._arg['soarCurrentAlertToProcess_PandasDataFrame']
			_soarAlertConfigs_AsPandasDataFrame				=	self._arg['soarAlertConfigs_AsPandasDataFrame']
			_UserId											=	self._arg['UserId']
			_TicketTypeId									=	self._arg['TicketTypeId']
			_TicketStatusId									=	self._arg['TicketStatusId']
			_TicketSeverityId								=	self._arg['TicketSeverityId']
			_ExternalReferenceTypeId						=	self._arg['ExternalReferenceTypeId']
			_ResourceTypeId									=	self._arg['ResourceTypeId']
			_ExternalReferenceCaseNumber					=	self._arg['ExternalReferenceCaseNumber']
			_ExternalReferenceCaseURL						=	self._arg['ExternalReferenceCaseURL']
			_ExternalReferenceCaseComments					=	self._arg['ExternalReferenceCaseComments']
			_TicketTitle									=	self._arg['TicketTitle']
			#
			_ResourceName				=	None
			_ResourceIdAsGUID			=	None
			_ResourceIdAsString			=	None
			_ResourceObjectIdAsGUID		=	None
			_ResourceURL				=	None
			_ResourcePATH				=	None
			_ResourceDescription		=	None
			#
			## TODO : review here if more parameters on resources are required, consider to make the proper changes on all optional values
			if	'ResourceName'			in	self._arg:
				if	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceName']))	!=	None:
					_ResourceName			=	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceName']))
			if	'ResourceIdAsGUID'		in	self._arg:
				if	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceIdAsGUID']))	!=	None:
					if	re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceIdAsGUID'])))	!=	None:
						guidMatch	=	re.search(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceIdAsGUID'])))
						if	len(guidMatch.group(0))	==	36:
							_ResourceIdAsGUID		=	guidMatch.group(0)
			if	'ResourceIdAsString'			in	self._arg:
				if	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceIdAsString']))	!=	None:
					_ResourceIdAsString			=	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceIdAsString']))
			if	'ResourceObjectIdAsGUID'		in	self._arg:
				if	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceObjectIdAsGUID']))	!=	None:
					if	re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceObjectIdAsGUID'])))	!=	None:
						guidMatch	=	re.search(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceObjectIdAsGUID'])))
						if	len(guidMatch.group(0))	==	36:
							_ResourceObjectIdAsGUID		=	guidMatch.group(0)
			if	'ResourceURL'			in	self._arg:
				if	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceURL']))	!=	None:
					_ResourceURL			=	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceURL']))
			if	'ResourcePATH'			in	self._arg:
				if	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourcePATH']))	!=	None:
					_ResourcePATH			=	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourcePATH']))
			if	'ResourceDescription'			in	self._arg:
				if	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceDescription']))	!=	None:
					_ResourceDescription			=	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceDescription']))
			#
			if	_soarCurrentAlertToProcess_PandasDataFrame.empty	!=	True:
				if		len(_alertSettings_AsJSON)								>	int(0)	\
					and	'AlertId'			in _soarAlertConfigs_AsPandasDataFrame.columns	\
					and	len(_soarCurrentAlertToProcess_PandasDataFrame)			>	int(0)	\
					and	_soarCurrentAlertToProcess_PandasDataFrame.shape[0]		>	int(0)	\
					and	len(_soarAlertConfigs_AsPandasDataFrame)				>	int(0)	\
					and	_soarAlertConfigs_AsPandasDataFrame.shape[0]			>	int(0)	\
					and	_UserId													>	int(0)	\
					and	_TicketTypeId											>	int(0)	\
					and	_TicketStatusId											>	int(0)	\
					and	_TicketSeverityId										>	int(0)	\
					and	_ExternalReferenceTypeId								>	int(0)	\
					and	_ResourceTypeId											>	int(0)	\
					and super().CoalesceEmptyNorNoneThenNone(str(_ExternalReferenceCaseNumber))		!=	None	\
					and	super().CoalesceEmptyNorNoneThenNone(str(_ExternalReferenceCaseURL))		!=	None:
					#
					azSQLtoken			=	None
					_runMSImodeInsteadCertificateBasedAuth	=	True
					if	'RunMSImodeInsteadCertificateBasedAuth'	in	self._soarGlobalSettings:
						_runMSImodeInsteadCertificateBasedAuth	=	bool(self._soarGlobalSettings['RunMSImodeInsteadCertificateBasedAuth'])
					#
					if		_runMSImodeInsteadCertificateBasedAuth	==	True	\
						and	'AutoAcctAzSQLLinkedServiceName'	in	self._soarGlobalSettings:
						_AutoAcctAzSQLLinkedServiceName_AsString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctAzSQLLinkedServiceName'])
						if	_AutoAcctAzSQLLinkedServiceName_AsString	!=	None:
							azSQLtoken		=	super().GetAccessTokenThroughMSI(_linkedServiceNameAsString=_AutoAcctAzSQLLinkedServiceName_AsString)
					else:
						azSQLtoken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																													_SPN_ApplicationId		=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppId']			\
																												,	_TenantId				=	self._soarGlobalSettings['AutoAcctSOARtorusTenantId']				\
																												,	_P12certBytes			=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12']			\
																												,	_P12certKy				=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12K']			\
																												,	_ScopeAudienceDomain	=	str('https://database.windows.net/')								\
																											)
					#
					if			azSQLtoken					!=	None	\
						and		self._soarGlobalSettings	!=	None:
						if	len(azSQLtoken)	>	0:
							if			'access_token'							in	azSQLtoken					\
								and		'AutoAcctSOARtorusAzSQLServerConn'		in	self._soarGlobalSettings:
								if		super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token'])									!=	None	\
									and	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])	!=	None:
									azSQLtokenAsBytes		=	b''
									for i in bytes(super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token']), 'UTF-8'):
										azSQLtokenAsBytes	+=	bytes({i})
										azSQLtokenAsBytes	+=	bytes(1)
									azSQLtokenAsStruct	=	struct.pack('=i', len(azSQLtokenAsBytes)) + azSQLtokenAsBytes
									#
									for currentTry in range(super()._maxRetries):
										#
										currentTry_ProcessResult	=	False
										#
										try:
											_TicketId_AsUnixTimestamp	=	int(datetime.timestamp(datetime.now(timezone.utc)))
											time.sleep(int(int(super()._sleepTimeAsMiliseconds/1000)/5))
											connectionString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])
											AzSQLconn_			=	pyodbc.connect(connectionString, attrs_before = { super().SQL_COPT_SS_ACCESS_TOKEN:azSQLtokenAsStruct })
											AzSQLconn_.add_output_converter(-155, self.__HandleDateTimeOffsetHierarchy)
											AzSQLconn_.add_output_converter(pyodbc.SQL_BIT, self.__HandleBitHierarchy)
											uspQueryCommandExec		=			'DECLARE @Input_TicketId [bigint];'	+	'\n'		\
																			+	'DECLARE @Input_AlertId [bigint];'	+	'\n'		\
																			+	'DECLARE @Input_TenantId [uniqueidentifier];'	+	'\n'		\
																			+	'DECLARE @Input_UserId [int];'	+	'\n'		\
																			+	'DECLARE @Input_TicketTypeId [int];'	+	'\n'		\
																			+	'DECLARE @Input_TicketStatusId [int];'	+	'\n'		\
																			+	'DECLARE @Input_TicketSeverityId [int];'	+	'\n'		\
																			+	'DECLARE @Input_ExternalReferenceTypeId [int];'	+	'\n'		\
																			+	'DECLARE @Input_ExternalReferenceCaseNumber [varchar](128);'	+	'\n'		\
																			+	'DECLARE @Input_ExternalReferenceCaseURL [nvarchar](2048);'	+	'\n'		\
																			+	'DECLARE @Input_ExternalReferenceCaseComments [nvarchar](4000);'	+	'\n'		\
																			+	'DECLARE @Input_ExternalReferenceEnabled [bit];'	+	'\n'		\
																			+	'DECLARE @Input_TicketResultId [int];'	+	'\n'		\
																			+	'DECLARE @Input_TicketTitle [nvarchar](512);'	+	'\n'		\
																			+	'DECLARE @Input_TicketRequestor [nvarchar](1024);'	+	'\n'		\
																			+	'DECLARE @Input_TicketTeam [nvarchar](512);'	+	'\n'		\
																			+	'DECLARE @Input_TicketDescription [nvarchar](2048);'	+	'\n'		\
																			+	'DECLARE @Input_TicketEnabled [bit];'	+	'\n'		\
																			+	'DECLARE @Input_TicketDeleted [bit];'	+	'\n'		\
																			+	'DECLARE @Input_ResourceTypeId [int];'	+	'\n'		\
																			+	'DECLARE @Input_ResourceName [nvarchar](840);'	+	'\n'		\
																			+	'DECLARE @Input_ResourceIdAsGUID [uniqueidentifier];'	+	'\n'		\
																			+	'DECLARE @Input_ResourceIdAsString [nvarchar](768);'	+	'\n'		\
																			+	'DECLARE @Input_ResourceObjectIdAsGUID [uniqueidentifier];'	+	'\n'		\
																			+	'DECLARE @Input_ResourceURL [nvarchar](4000);'	+	'\n'		\
																			+	'DECLARE @Input_ResourcePATH [nvarchar](4000);'	+	'\n'		\
																			+	'DECLARE @Input_ResourceDescription [nvarchar](2048);'	+	'\n'		\
																			+	'DECLARE @Input_ResourceEnabled [bit];'	+	'\n'		\
																			+	'DECLARE @Output_ProcedureResult [bit];'	+	'\n'		\
																			+	'DECLARE @Output_ScopeRow_TicketId [bigint];'	+	'\n'		\
																			+	'\n'		\
																			+	'SELECT	@Input_TicketId	=	CONVERT([bigint], {num});'.format(num = _TicketId_AsUnixTimestamp)	+	'\n'		\
																			+	'SELECT	@Input_AlertId	=	CONVERT([bigint], {num});'.format(num = _soarAlertConfigs_AsPandasDataFrame.iloc[0]['AlertId'])	+	'\n'		\
																			+	'SELECT	@Input_TenantId	=	\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(str(_soarAlertConfigs_AsPandasDataFrame.iloc[0]['TenantId'])))	+	'\n'		\
																			+	'SELECT	@Input_UserId	=	CONVERT([int], {num});'.format(num = _UserId)	+	'\n'		\
																			+	'SELECT	@Input_TicketTypeId	=	CONVERT([int], {num});'.format(num = _TicketTypeId)	+	'\n'		\
																			+	'SELECT	@Input_TicketStatusId	=	CONVERT([int], {num});'.format(num = _TicketStatusId)	+	'\n'		\
																			+	'SELECT	@Input_TicketSeverityId	=	CONVERT([int], {num});'.format(num = _TicketSeverityId)	+	'\n'		\
																			+	'SELECT	@Input_ExternalReferenceTypeId	=	CONVERT([int], {num});'.format(num = _ExternalReferenceTypeId)	+	'\n'		\
																			+	'SELECT	@Input_ExternalReferenceCaseNumber	=	\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(str(_ExternalReferenceCaseNumber)))	+	'\n'		\
																			+	'SELECT	@Input_ExternalReferenceCaseURL	=	\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(str(_ExternalReferenceCaseURL)))	+	'\n'		\
																			+	'SELECT	@Input_ExternalReferenceCaseComments	=	\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(str(_ExternalReferenceCaseComments)))	+	'\n'		\
																			+	'SELECT	@Input_ExternalReferenceEnabled	=	NULL;'	+	'\n'		\
																			+	'SELECT	@Input_TicketResultId	=	NULL;'	+	'\n'		\
																			+	'SELECT	@Input_TicketTitle	=	\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(str(_TicketTitle)))	+	'\n'		\
																			+	'SELECT	@Input_TicketRequestor	=	NULL;'	+	'\n'		\
																			+	'SELECT	@Input_TicketTeam	=	NULL;'	+	'\n'		\
																			+	'SELECT	@Input_TicketDescription	=	NULL;'	+	'\n'		\
																			+	'SELECT	@Input_TicketEnabled	=	NULL;'	+	'\n'		\
																			+	'SELECT	@Input_TicketDeleted	=	NULL;'	+	'\n'		\
																			+	'SELECT	@Input_ResourceTypeId	=	CONVERT([int], {num});'.format(num = _ResourceTypeId)	+	'\n'		\
																			+	'SELECT	@Input_ResourceName	=	'	\
																										+	str('\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_ResourceName))								if	super().CoalesceEmptyNorNoneThenNone(_ResourceName)	!=	None	else	'NULL;')	\
																										+	'\n'	\
																			+	'SELECT	@Input_ResourceIdAsGUID	=	'	\
																										+	str('CONVERT([uniqueidentifier], \'{string_value}\');'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_ResourceIdAsGUID))	if	super().CoalesceEmptyNorNoneThenNone(_ResourceIdAsGUID)		!=	None	else	'NULL;')	\
																										+	'\n'	\
																			+	'SELECT	@Input_ResourceIdAsString	=	'	\
																										+	str('\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_ResourceIdAsString))								if	super().CoalesceEmptyNorNoneThenNone(_ResourceIdAsString)	!=	None	else	'NULL;')	\
																										+	'\n'	\
																			+	'SELECT	@Input_ResourceObjectIdAsGUID	=	'	\
																										+	str('CONVERT([uniqueidentifier], \'{string_value}\');'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_ResourceObjectIdAsGUID))	if	super().CoalesceEmptyNorNoneThenNone(_ResourceObjectIdAsGUID)		!=	None	else	'NULL;')	\
																										+	'\n'	\
																			+	'SELECT	@Input_ResourceURL	=	'	\
																										+	str('\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_ResourceURL))								if	super().CoalesceEmptyNorNoneThenNone(_ResourceURL)	!=	None	else	'NULL;')	\
																										+	'\n'	\
																			+	'SELECT	@Input_ResourcePATH	=	'	\
																										+	str('\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_ResourcePATH))								if	super().CoalesceEmptyNorNoneThenNone(_ResourcePATH)	!=	None	else	'NULL;')	\
																										+	'\n'	\
																			+	'SELECT	@Input_ResourceDescription	=	'	\
																										+	str('\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_ResourceDescription))								if	super().CoalesceEmptyNorNoneThenNone(_ResourceDescription)	!=	None	else	'NULL;')	\
																										+	'\n'	\
																			+	'SELECT	@Input_ResourceEnabled	=	NULL;'	+	'\n'		\
																			+	'\n'		\
																			+	'EXECUTE [soar].[usp_InsertNewTicketWithExternalReferenceThroughResourceIdAsGUID] '	+	'\n'		\
																			+	'		@TicketId	=	@Input_TicketId'	+	'\n'		\
																			+	'	,	@AlertId	=	@Input_AlertId'	+	'\n'		\
																			+	'	,	@TenantId	=	@Input_TenantId'	+	'\n'		\
																			+	'	,	@UserId	=	@Input_UserId'	+	'\n'		\
																			+	'	,	@TicketTypeId	=	@Input_TicketTypeId'	+	'\n'		\
																			+	'	,	@TicketStatusId	=	@Input_TicketStatusId'	+	'\n'		\
																			+	'	,	@TicketSeverityId	=	@Input_TicketSeverityId'	+	'\n'		\
																			+	'	,	@ExternalReferenceTypeId	=	@Input_ExternalReferenceTypeId'	+	'\n'		\
																			+	'	,	@ExternalReferenceCaseNumber	=	@Input_ExternalReferenceCaseNumber'	+	'\n'		\
																			+	'	,	@ExternalReferenceCaseURL	=	@Input_ExternalReferenceCaseURL'	+	'\n'		\
																			+	'	,	@ExternalReferenceCaseComments	=	@Input_ExternalReferenceCaseComments'	+	'\n'		\
																			+	'	,	@ExternalReferenceEnabled	=	@Input_ExternalReferenceEnabled'	+	'\n'		\
																			+	'	,	@TicketResultId	=	@Input_TicketResultId'	+	'\n'		\
																			+	'	,	@TicketTitle	=	@Input_TicketTitle'	+	'\n'		\
																			+	'	,	@TicketRequestor	=	@Input_TicketRequestor'	+	'\n'		\
																			+	'	,	@TicketTeam	=	@Input_TicketTeam'	+	'\n'		\
																			+	'	,	@TicketDescription	=	@Input_TicketDescription'	+	'\n'		\
																			+	'	,	@TicketEnabled	=	@Input_TicketEnabled'	+	'\n'		\
																			+	'	,	@TicketDeleted	=	@Input_TicketDeleted'	+	'\n'		\
																			+	'	,	@ResourceTypeId	=	@Input_ResourceTypeId'	+	'\n'		\
																			+	'	,	@ResourceName	=	@Input_ResourceName'	+	'\n'		\
																			+	'	,	@ResourceIdAsGUID	=	@Input_ResourceIdAsGUID'	+	'\n'		\
																			+	'	,	@ResourceIdAsString	=	@Input_ResourceIdAsString'	+	'\n'		\
																			+	'	,	@ResourceObjectIdAsGUID	=	@Input_ResourceObjectIdAsGUID'	+	'\n'		\
																			+	'	,	@ResourceURL	=	@Input_ResourceURL'	+	'\n'		\
																			+	'	,	@ResourcePATH	=	@Input_ResourcePATH'	+	'\n'		\
																			+	'	,	@ResourceDescription	=	@Input_ResourceDescription'	+	'\n'		\
																			+	'	,	@ResourceEnabled	=	@Input_ResourceEnabled'	+	'\n'		\
																			+	'	,	@ProcedureResult	=	@Output_ProcedureResult	OUTPUT'	+	'\n'		\
																			+	'	,	@ScopeRow_TicketId	=	@Output_ScopeRow_TicketId	OUTPUT;'
											#
											## let's remove new lines
											uspQueryCommandExec		=	uspQueryCommandExec.replace('\n','')
											with	AzSQLconn_.cursor()	as	AzSQLcursor_:
												AzSQLcursor_.execute(uspQueryCommandExec)
												AzSQLcolumns	=	[x[0] for x in AzSQLcursor_.description]
												AzSQLrows		=	[tuple(r) for r in AzSQLcursor_.fetchall()]
											if		AzSQLcolumns	!=	None	\
												and	AzSQLrows		!=	None:
												if		len(AzSQLcolumns)	>	0	\
													and	len(AzSQLrows)		>	0:
													if		len(AzSQLcolumns)	==	len(AzSQLrows[0]):
														#
														AzSQLResultRowsAsDataFrame	=	pandas.DataFrame(data = AzSQLrows, columns = AzSQLcolumns)
														#
														currentTry_ProcessResult	=	True
														break
														#
												elif	len(AzSQLcolumns)	>	0	\
													and	len(AzSQLrows)		<=	0:
														#
														currentTry_ProcessResult	=	True
														break
														#
										except pyodbc.Error as _pEx:
											super().HandleGLobalException(_pEx)
										except Exception as _exInst:
											super().HandleGLobalException(_exInst)
										#
										if	currentTry_ProcessResult	==	True:
											break
										else:
											time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
											continue
										#
									#
					#
		#
		return AzSQLResultRowsAsDataFrame
		# end _ExecuteInsertNewTicketWithExternalReferenceThroughResourceIdAsGUID_AsPandas

	def _Execute_usp_GetP12sBytes_AsPandas(												\
													self								\
												,	SettingName:				str		\
											) -> T:
		##
		#	@brief Execute usp_GetP12sBytes Stored Procedure, return result as Pandas DataFrame.
		#
		#	Keyword arguments:
		#	@param SettingName -- SettingName
		""" Execute usp_GetP12sBytes Stored Procedure, return result as Pandas DataFrame. """
		#
		azSQLtoken			=	None
		_runMSImodeInsteadCertificateBasedAuth	=	True
		if	'RunMSImodeInsteadCertificateBasedAuth'	in	self._soarGlobalSettings:
			_runMSImodeInsteadCertificateBasedAuth	=	bool(self._soarGlobalSettings['RunMSImodeInsteadCertificateBasedAuth'])
		#
		if		_runMSImodeInsteadCertificateBasedAuth	==	True	\
			and	'AutoAcctAzSQLLinkedServiceName'	in	self._soarGlobalSettings:
			_AutoAcctAzSQLLinkedServiceName_AsString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctAzSQLLinkedServiceName'])
			if	_AutoAcctAzSQLLinkedServiceName_AsString	!=	None:
				azSQLtoken		=	super().GetAccessTokenThroughMSI(_linkedServiceNameAsString=_AutoAcctAzSQLLinkedServiceName_AsString)
		else:
			azSQLtoken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																										_SPN_ApplicationId		=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppId']			\
																									,	_TenantId				=	self._soarGlobalSettings['AutoAcctSOARtorusTenantId']				\
																									,	_P12certBytes			=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12']			\
																									,	_P12certKy				=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12K']			\
																									,	_ScopeAudienceDomain	=	str('https://database.windows.net/')								\
																								)
		#
		AzSQLrowsAsDataFrame	=	pandas.DataFrame(None).dropna()
		if			azSQLtoken					!=	None	\
			and		self._soarGlobalSettings	!=	None:
			if	len(azSQLtoken)	>	0:
					if			'access_token'							in	azSQLtoken					\
						and		'AutoAcctSOARtorusAzSQLServerConn'		in	self._soarGlobalSettings:
						if		super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token'])									!=	None	\
							and	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])	!=	None	\
							and	super().CoalesceEmptyNorNoneThenNone(SettingName)													!=	None:
							azSQLtokenAsBytes		=	b''
							for i in bytes(super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token']), 'UTF-8'):
								azSQLtokenAsBytes	+=	bytes({i})
								azSQLtokenAsBytes	+=	bytes(1)
							azSQLtokenAsStruct	=	struct.pack('=i', len(azSQLtokenAsBytes)) + azSQLtokenAsBytes
							#
							for currentTry in range(super()._maxRetries):
								#
								currentTry_ProcessResult	=	False
								#
								try:
									connectionString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])
									AzSQLconn_			=	pyodbc.connect(connectionString, attrs_before = { super().SQL_COPT_SS_ACCESS_TOKEN:azSQLtokenAsStruct })
									AzSQLconn_.add_output_converter(-155, self.__HandleDateTimeOffsetHierarchy)
									AzSQLconn_.add_output_converter(pyodbc.SQL_BIT, self.__HandleBitHierarchy)
									uspQueryCommandExec		=			'DECLARE @Input_SettingName [nvarchar](448);'																	\
																	+	'SELECT	@Input_SettingName	=	'	+	str('\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(SettingName))	if	super().CoalesceEmptyNorNoneThenNone(SettingName)	!=	None	else	'NULL;')	\
																	+	'EXECUTE [soar].[usp_GetP12sBytes]'								\
																	+	'	@SettingName = @Input_SettingName;'
									with	AzSQLconn_.cursor()	as	AzSQLcursor_:
										AzSQLcursor_.execute(uspQueryCommandExec)
										AzSQLcolumns	=	[x[0] for x in AzSQLcursor_.description]
										AzSQLrows		=	[tuple(r) for r in AzSQLcursor_.fetchall()]
									if		AzSQLcolumns	!=	None	\
										and	AzSQLrows		!=	None:
										if		len(AzSQLcolumns)	>	0	\
											and	len(AzSQLrows)		>	0:
											if		len(AzSQLcolumns)	==	len(AzSQLrows[0]):
												AzSQLrowsAsDataFrame	=	pandas.DataFrame(data = AzSQLrows, columns = AzSQLcolumns)
												#
												currentTry_ProcessResult	=	True
												break
												#
										elif	len(AzSQLcolumns)	>	0	\
											and	len(AzSQLrows)		<=	0:
												#
												currentTry_ProcessResult	=	True
												break
												#
								except pyodbc.Error as _pEx:
									super().HandleGLobalException(_pEx)
								except Exception as _exInst:
									super().HandleGLobalException(_exInst)
								#
								if	currentTry_ProcessResult	==	True:
									break
								else:
									time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
									continue
								#
							#
		#
		return AzSQLrowsAsDataFrame
		# end _Execute_usp_GetP12sBytes_AsPandas

	def _ExecuteInsertNewRemediationByRemediationTypeName_AsPandas(						\
																			self		\
																		,	**kwargs	\
																	) -> list:
		##
		#	@brief Execute USP usp_InsertNewRemediationByRemediationTypeName Return Result as Pandas DataFrame.
		#
		#	Keyword arguments
		#	@param alertSettings_AsJSON							--	alertSettings_AsJSON
		#	@param soarCurrentAlertToProcess_PandasDataFrame	--	soarCurrentAlertToProcess_PandasDataFrame
		#	@param soarAlertConfigs_AsPandasDataFrame			--	soarAlertConfigs_AsPandasDataFrame
		#	@param UserId										--	UserId
		#	@param RemediationTypeName							--	RemediationTypeName
		#	@param RemediationResultId							--	RemediationResultId
		#	@param TicketId										--	TicketId
		#	@param ResourceId									--	ResourceId
		#	@param RemediationCode								--	RemediationCode
		#	@param RemediationResponse							--	RemediationResponse
		#	@param RemediationDescription						--	RemediationDescription
		""" Execute USP usp_InsertNewRemediationByRemediationTypeName Return Result as Pandas DataFrame """
		self._arg		=	kwargs
		AzSQLResultRowsAsDataFrame	=	pandas.DataFrame(None).dropna()
		#
		if		'alertSettings_AsJSON'							in	self._arg	\
			and	'soarCurrentAlertToProcess_PandasDataFrame'		in	self._arg	\
			and	'soarAlertConfigs_AsPandasDataFrame'			in	self._arg	\
			and	'UserId'										in	self._arg	\
			and	'RemediationTypeName'							in	self._arg	\
			and	'RemediationResultId'							in	self._arg	\
			and	'TicketId'										in	self._arg	\
			and	'ResourceId'									in	self._arg:
			#
			_alertSettings_AsJSON							=	self._arg['alertSettings_AsJSON']
			_soarCurrentAlertToProcess_PandasDataFrame		=	self._arg['soarCurrentAlertToProcess_PandasDataFrame']
			_soarAlertConfigs_AsPandasDataFrame				=	self._arg['soarAlertConfigs_AsPandasDataFrame']
			_UserId											=	self._arg['UserId']
			_RemediationTypeName							=	self._arg['RemediationTypeName']
			_RemediationResultId							=	self._arg['RemediationResultId']
			_TicketId										=	self._arg['TicketId']
			_ResourceId										=	self._arg['ResourceId']
			#
			_RemediationCode			=	int(-1)
			_RemediationResponse		=	None
			_RemediationDescription		=	None
			#
			## TODO : review here if more parameters on resources are required, consider to make the proper changes on all optional values
			if	'RemediationCode'			in	self._arg:
				if	self._arg['RemediationCode']	>	int(0):
					_RemediationCode		=	self._arg['RemediationCode']
			if	'RemediationResponse'			in	self._arg:
				if	super().CoalesceEmptyNorNoneThenNone(self._arg['RemediationResponse'])	!=	None:
					_RemediationResponse			=	super().CoalesceEmptyNorNoneThenNone(str(self._arg['RemediationResponse']))
			if	'RemediationDescription'		in	self._arg:
				if	super().CoalesceEmptyNorNoneThenNone(self._arg['RemediationDescription'])	!=	None:
					_RemediationDescription		=	super().CoalesceEmptyNorNoneThenNone(str(self._arg['RemediationDescription']))
			#
			if	_soarCurrentAlertToProcess_PandasDataFrame.empty	!=	True:
				if		len(_alertSettings_AsJSON)											>	int(0)	\
					and	'AlertId'			in _soarAlertConfigs_AsPandasDataFrame.columns				\
					and	len(_soarCurrentAlertToProcess_PandasDataFrame)						>	int(0)	\
					and	_soarCurrentAlertToProcess_PandasDataFrame.shape[0]					>	int(0)	\
					and	len(_soarAlertConfigs_AsPandasDataFrame)							>	int(0)	\
					and	_soarAlertConfigs_AsPandasDataFrame.shape[0]						>	int(0)	\
					and	_UserId																>	int(0)	\
					and super().CoalesceEmptyNorNoneThenNone(str(_RemediationTypeName))		!=	None	\
					and	_RemediationResultId												>	int(0)	\
					and	_TicketId															>	int(0)	\
					and	_ResourceId															>	int(0):
					#
					azSQLtoken			=	None
					_runMSImodeInsteadCertificateBasedAuth	=	True
					if	'RunMSImodeInsteadCertificateBasedAuth'	in	self._soarGlobalSettings:
						_runMSImodeInsteadCertificateBasedAuth	=	bool(self._soarGlobalSettings['RunMSImodeInsteadCertificateBasedAuth'])
					#
					if		_runMSImodeInsteadCertificateBasedAuth	==	True	\
						and	'AutoAcctAzSQLLinkedServiceName'	in	self._soarGlobalSettings:
						_AutoAcctAzSQLLinkedServiceName_AsString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctAzSQLLinkedServiceName'])
						if	_AutoAcctAzSQLLinkedServiceName_AsString	!=	None:
							azSQLtoken		=	super().GetAccessTokenThroughMSI(_linkedServiceNameAsString=_AutoAcctAzSQLLinkedServiceName_AsString)
					else:
						azSQLtoken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																													_SPN_ApplicationId		=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppId']			\
																												,	_TenantId				=	self._soarGlobalSettings['AutoAcctSOARtorusTenantId']				\
																												,	_P12certBytes			=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12']			\
																												,	_P12certKy				=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12K']			\
																												,	_ScopeAudienceDomain	=	str('https://database.windows.net/')								\
																											)
					#
					if			azSQLtoken					!=	None	\
						and		self._soarGlobalSettings	!=	None:
						if	len(azSQLtoken)	>	0:
								if			'access_token'							in	azSQLtoken					\
									and		'AutoAcctSOARtorusAzSQLServerConn'		in	self._soarGlobalSettings:
									if		super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token'])									!=	None	\
										and	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])	!=	None:
										azSQLtokenAsBytes		=	b''
										for i in bytes(super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token']), 'UTF-8'):
											azSQLtokenAsBytes	+=	bytes({i})
											azSQLtokenAsBytes	+=	bytes(1)
										azSQLtokenAsStruct	=	struct.pack('=i', len(azSQLtokenAsBytes)) + azSQLtokenAsBytes
										#
										for currentTry in range(super()._maxRetries):
											#
											currentTry_ProcessResult	=	False
											#
											try:
												_TicketId_AsUnixTimestamp	=	int(datetime.timestamp(datetime.now(timezone.utc)))
												time.sleep(int(int(super()._sleepTimeAsMiliseconds/1000)/5))
												connectionString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])
												AzSQLconn_			=	pyodbc.connect(connectionString, attrs_before = { super().SQL_COPT_SS_ACCESS_TOKEN:azSQLtokenAsStruct })
												AzSQLconn_.add_output_converter(-155, self.__HandleDateTimeOffsetHierarchy)
												AzSQLconn_.add_output_converter(pyodbc.SQL_BIT, self.__HandleBitHierarchy)
												uspQueryCommandExec		=			'DECLARE @Input_RemediationTypeName [nvarchar](256);'	+	'\n'		\
																				+	'DECLARE @Input_RemediationResultId [int];'	+	'\n'		\
																				+	'DECLARE @Input_TicketId [bigint];'	+	'\n'		\
																				+	'DECLARE @Input_ResourceId [bigint];'	+	'\n'		\
																				+	'DECLARE @Input_UserId [int];'	+	'\n'		\
																				+	'DECLARE @Input_RemediationCode [int];'	+	'\n'		\
																				+	'DECLARE @Input_RemediationResponse [nvarchar](1024);'	+	'\n'		\
																				+	'DECLARE @Input_RemediationDescription [nvarchar](2048);'	+	'\n'		\
																				+	'DECLARE @Output_ProcedureResult [bit];'	+	'\n'		\
																				+	'DECLARE @Output_ScopeRow_RemediationId [bigint];'	+	'\n'		\
																				+	'\n'		\
																				+	'SELECT	@Input_RemediationTypeName	=	\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(str(_RemediationTypeName)))	+	'\n'		\
																				+	'SELECT	@Input_RemediationResultId	=	CONVERT([int], {num});'.format(num = _RemediationResultId)	+	'\n'		\
																				+	'SELECT	@Input_TicketId	=	CONVERT([bigint], {num});'.format(num = math.trunc(int(_TicketId)))	+	'\n'		\
																				+	'SELECT	@Input_ResourceId	=	CONVERT([bigint], {num});'.format(num = math.trunc(int(_ResourceId)))	+	'\n'		\
																				+	'SELECT	@Input_UserId	=	CONVERT([int], {num});'.format(num = _UserId)	+	'\n'		\
																				+	'SELECT	@Input_RemediationCode	=	'	\
																											+	str('\'{int_value}\';'.format(int_value = str(math.trunc(int(_RemediationCode))))	if	_RemediationCode	>	int(0)	else	'NULL;')	\
																											+	'\n'	\
																				+	'SELECT	@Input_RemediationResponse	=	'	\
																											+	str('\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_RemediationResponse))		if	super().CoalesceEmptyNorNoneThenNone(_RemediationResponse)			!=	None	else	'NULL;')	\
																											+	'\n'	\
																				+	'SELECT	@Input_RemediationDescription	=	'	\
																											+	str('\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_RemediationDescription))	if	super().CoalesceEmptyNorNoneThenNone(_RemediationDescription)		!=	None	else	'NULL;')	\
																											+	'\n'	\
																				+	'\n'		\
																				+	'EXECUTE [soar].[usp_InsertNewRemediationByRemediationTypeName] '	+	'\n'		\
																				+	'		@RemediationTypeName		=	@Input_RemediationTypeName'	+	'\n'		\
																				+	',		@RemediationResultId		=	@Input_RemediationResultId'	+	'\n'		\
																				+	',		@TicketId					=	@Input_TicketId'	+	'\n'		\
																				+	',		@ResourceId					=	@Input_ResourceId'	+	'\n'		\
																				+	',		@UserId						=	@Input_UserId'	+	'\n'		\
																				+	',		@RemediationCode			=	@Input_RemediationCode'	+	'\n'		\
																				+	',		@RemediationResponse		=	@Input_RemediationResponse'	+	'\n'		\
																				+	',		@RemediationDescription		=	@Input_RemediationDescription'	+	'\n'		\
																				+	',		@ProcedureResult			=	@Output_ProcedureResult OUTPUT'	+	'\n'		\
																				+	',		@ScopeRow_RemediationId		=	@Output_ScopeRow_RemediationId OUTPUT;'
												#
												## let's remove new lines
												uspQueryCommandExec		=	uspQueryCommandExec.replace('\n','')
												with	AzSQLconn_.cursor()	as	AzSQLcursor_:
													AzSQLcursor_.execute(uspQueryCommandExec)
													AzSQLcolumns	=	[x[0] for x in AzSQLcursor_.description]
													AzSQLrows		=	[tuple(r) for r in AzSQLcursor_.fetchall()]
												if		AzSQLcolumns	!=	None	\
													and	AzSQLrows		!=	None:
													if		len(AzSQLcolumns)	>	0	\
														and	len(AzSQLrows)		>	0:
														if		len(AzSQLcolumns)	==	len(AzSQLrows[0]):
															#
															AzSQLResultRowsAsDataFrame	=	pandas.DataFrame(data = AzSQLrows, columns = AzSQLcolumns)
															#
															currentTry_ProcessResult	=	True
															break
															#
													elif	len(AzSQLcolumns)	>	0	\
														and	len(AzSQLrows)		<=	0:
															#
															currentTry_ProcessResult	=	True
															break
															#
											except pyodbc.Error as _pEx:
												super().HandleGLobalException(_pEx)
											except Exception as _exInst:
												super().HandleGLobalException(_exInst)
											#
											if	currentTry_ProcessResult	==	True:
												break
											else:
												time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
												continue
											#
										#
					#
		#
		return AzSQLResultRowsAsDataFrame
		# end _ExecuteInsertNewRemediationByRemediationTypeName_AsPandas

	def _Execute_usp_GetSettingBySettingName_AsPandas(											\
															self								\
														,	SettingName:				str		\
													) -> T:
		##
		#	@brief Execute usp_GetSettingBySettingName Stored Procedure, return result as Pandas DataFrame.
		#
		#	Keyword arguments:
		#	@param SettingName -- SettingName
		""" Execute usp_GetSettingBySettingName Stored Procedure, return result as Pandas DataFrame. """
		#
		azSQLtoken			=	None
		_runMSImodeInsteadCertificateBasedAuth	=	True
		if	'RunMSImodeInsteadCertificateBasedAuth'	in	self._soarGlobalSettings:
			_runMSImodeInsteadCertificateBasedAuth	=	bool(self._soarGlobalSettings['RunMSImodeInsteadCertificateBasedAuth'])
		#
		if		_runMSImodeInsteadCertificateBasedAuth	==	True	\
			and	'AutoAcctAzSQLLinkedServiceName'	in	self._soarGlobalSettings:
			_AutoAcctAzSQLLinkedServiceName_AsString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctAzSQLLinkedServiceName'])
			if	_AutoAcctAzSQLLinkedServiceName_AsString	!=	None:
				azSQLtoken		=	super().GetAccessTokenThroughMSI(_linkedServiceNameAsString=_AutoAcctAzSQLLinkedServiceName_AsString)
		else:
			azSQLtoken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																										_SPN_ApplicationId		=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppId']			\
																									,	_TenantId				=	self._soarGlobalSettings['AutoAcctSOARtorusTenantId']				\
																									,	_P12certBytes			=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12']			\
																									,	_P12certKy				=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12K']			\
																									,	_ScopeAudienceDomain	=	str('https://database.windows.net/')								\
																								)
		#
		AzSQLrowsAsDataFrame	=	pandas.DataFrame(None).dropna()
		if			azSQLtoken					!=	None	\
			and		self._soarGlobalSettings	!=	None:
			if	len(azSQLtoken)	>	0:
					if			'access_token'							in	azSQLtoken					\
						and		'AutoAcctSOARtorusAzSQLServerConn'		in	self._soarGlobalSettings:
						if		super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token'])									!=	None	\
							and	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])	!=	None	\
							and	super().CoalesceEmptyNorNoneThenNone(SettingName)													!=	None:
							azSQLtokenAsBytes		=	b''
							for i in bytes(super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token']), 'UTF-8'):
								azSQLtokenAsBytes	+=	bytes({i})
								azSQLtokenAsBytes	+=	bytes(1)
							azSQLtokenAsStruct	=	struct.pack('=i', len(azSQLtokenAsBytes)) + azSQLtokenAsBytes
							#
							for currentTry in range(super()._maxRetries):
								#
								currentTry_ProcessResult	=	False
								#
								try:
									connectionString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])
									AzSQLconn_			=	pyodbc.connect(connectionString, attrs_before = { super().SQL_COPT_SS_ACCESS_TOKEN:azSQLtokenAsStruct })
									AzSQLconn_.add_output_converter(-155, self.__HandleDateTimeOffsetHierarchy)
									AzSQLconn_.add_output_converter(pyodbc.SQL_BIT, self.__HandleBitHierarchy)
									uspQueryCommandExec		=			'DECLARE @Input_SettingName [nvarchar](448);'																	\
																	+	'SELECT	@Input_SettingName	=	'	+	str('\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(SettingName))	if	super().CoalesceEmptyNorNoneThenNone(SettingName)	!=	None	else	'NULL;')	\
																	+	'EXECUTE [soar].[usp_GetSettingBySettingName]'								\
																	+	'	@SettingName = @Input_SettingName;'
									with	AzSQLconn_.cursor()	as	AzSQLcursor_:
										AzSQLcursor_.execute(uspQueryCommandExec)
										AzSQLcolumns	=	[x[0] for x in AzSQLcursor_.description]
										AzSQLrows		=	[tuple(r) for r in AzSQLcursor_.fetchall()]
									if		AzSQLcolumns	!=	None	\
										and	AzSQLrows		!=	None:
										if		len(AzSQLcolumns)	>	0	\
											and	len(AzSQLrows)		>	0:
											if		len(AzSQLcolumns)	==	len(AzSQLrows[0]):
												AzSQLrowsAsDataFrame	=	pandas.DataFrame(data = AzSQLrows, columns = AzSQLcolumns)
												#
												currentTry_ProcessResult	=	True
												break
												#
										elif	len(AzSQLcolumns)	>	0	\
											and	len(AzSQLrows)		<=	0:
												#
												currentTry_ProcessResult	=	True
												break
												#
								except pyodbc.Error as _pEx:
									super().HandleGLobalException(_pEx)
								except Exception as _exInst:
									super().HandleGLobalException(_exInst)
								#
								if	currentTry_ProcessResult	==	True:
									break
								else:
									time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
									continue
								#
							#
		#
		return AzSQLrowsAsDataFrame
		# end _Execute_usp_GetSettingBySettingName_AsPandas

	def _ExecuteUpdateTicketStatusAndResultByTicketId_AsPandas(					\
																	self		\
																,	**kwargs	\
															) -> pandas.DataFrame:
		##
		#	@brief Execute USP usp_UpdateTicketStatusAndResultByTicketId Return Result as Pandas DataFrame.
		#
		#	Keyword arguments
		#	@param TicketId										--	TicketId
		#	@param UserId										--	UserId	
		#	@param TicketTypeId									--	TicketTypeId
		#	@param TicketStatusId								--	TicketStatusId		
		#	@param TicketResultId								--	TicketResultId			
		#	@param TruePositive									--	TruePositive
		#	@param FalsePositive								--	FalsePositive
		""" Execute USP usp_UpdateTicketStatusAndResultByTicketId Return Result as Pandas DataFrame """
		self._arg		=	kwargs
		AzSQLResultRowsAsDataFrame	=	pandas.DataFrame(None).dropna()		
		#
		if		'TicketId'			in	self._arg	\
			and	'UserId'			in	self._arg	\
			and	'TicketTypeId'		in	self._arg	\
			and	'TicketStatusId'	in	self._arg	\
			and	'TicketResultId'	in	self._arg:
			#
			_TicketId			=	self._arg['TicketId']
			_UserId				=	self._arg['UserId']
			_TicketTypeId		=	self._arg['TicketTypeId']
			_TicketStatusId		=	self._arg['TicketStatusId']
			_TicketResultId		=	self._arg['TicketResultId']
			_TruePositive		=	None
			_FalsePositive		=	None
			#
			if	'TruePositive'	in	self._arg:
				_TruePositive		=	self._arg['TruePositive']
			if	'TruePositive'	in	self._arg:
				_FalsePositive		=	self._arg['FalsePositive']
			#
			azSQLtoken			=	None
			_runMSImodeInsteadCertificateBasedAuth	=	True
			if	'RunMSImodeInsteadCertificateBasedAuth'	in	self._soarGlobalSettings:
				_runMSImodeInsteadCertificateBasedAuth	=	bool(self._soarGlobalSettings['RunMSImodeInsteadCertificateBasedAuth'])
			#
			if		_runMSImodeInsteadCertificateBasedAuth	==	True	\
				and	'AutoAcctAzSQLLinkedServiceName'	in	self._soarGlobalSettings:
				_AutoAcctAzSQLLinkedServiceName_AsString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctAzSQLLinkedServiceName'])
				if	_AutoAcctAzSQLLinkedServiceName_AsString	!=	None:
					azSQLtoken		=	super().GetAccessTokenThroughMSI(_linkedServiceNameAsString=_AutoAcctAzSQLLinkedServiceName_AsString)
			else:
				azSQLtoken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																											_SPN_ApplicationId		=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppId']			\
																										,	_TenantId				=	self._soarGlobalSettings['AutoAcctSOARtorusTenantId']				\
																										,	_P12certBytes			=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12']			\
																										,	_P12certKy				=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12K']			\
																										,	_ScopeAudienceDomain	=	str('https://database.windows.net/')								\
																									)
			#
			AzSQLResultRowsAsDataFrame	=	pandas.DataFrame(None).dropna()
			if			azSQLtoken					!=	None	\
				and		self._soarGlobalSettings	!=	None	\
				and		_TicketId					>	0:
				if	len(azSQLtoken)	>	0:
						if			'access_token'							in	azSQLtoken					\
							and		'AutoAcctSOARtorusAzSQLServerConn'		in	self._soarGlobalSettings:
							if		super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token'])									!=	None	\
								and	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])	!=	None:
								azSQLtokenAsBytes		=	b''
								for i in bytes(super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token']), 'UTF-8'):
									azSQLtokenAsBytes	+=	bytes({i})
									azSQLtokenAsBytes	+=	bytes(1)
								azSQLtokenAsStruct	=	struct.pack('=i', len(azSQLtokenAsBytes)) + azSQLtokenAsBytes
								#
								for currentTry in range(super()._maxRetries):
									#
									currentTry_ProcessResult	=	False
									#
									try:
										connectionString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])
										AzSQLconn_			=	pyodbc.connect(connectionString, attrs_before = { super().SQL_COPT_SS_ACCESS_TOKEN:azSQLtokenAsStruct })
										AzSQLconn_.add_output_converter(-155, self.__HandleDateTimeOffsetHierarchy)
										AzSQLconn_.add_output_converter(pyodbc.SQL_BIT, self.__HandleBitHierarchy)
										#
										uspQueryCommandExec		=																			\
													'DECLARE @Input_TicketId [bigint];'	+	'\n'											\
												+	'DECLARE @Input_UserId [int];'	+	'\n'												\
												+	'DECLARE @Input_TicketTypeId [int];'	+	'\n'										\
												+	'DECLARE @Input_TicketStatusId [int];'	+	'\n'										\
												+	'DECLARE @Input_TicketResultId [int];'	+	'\n'										\
												+	'DECLARE @Input_TruePositive [bit];'	+	'\n'										\
												+	'DECLARE @Input_FalsePositive [bit];'	+	'\n'										\
												+	'DECLARE @Output_ProcedureResult [bit];'	+	'\n'									\
												+	'DECLARE @Output_ScopeRow_TicketId [bigint];'	+	'\n'								\
												+	'\n'																					\
												+	'SELECT @Input_TicketId = CONVERT([bigint], {num});'.format(num = _TicketId)			\
												+	'\n'																					\
												+	'SELECT @Input_UserId = CONVERT([int], {num});'.format(num = _UserId)					\
												+	'\n'																					\
												+	'SELECT @Input_TicketTypeId = CONVERT([int], {num});'.format(num = _TicketTypeId)		\
												+	'\n'																					\
												+	'SELECT @Input_TicketStatusId = CONVERT([int], {num});'.format(num = _TicketStatusId)	\
												+	'\n'																					\
												+	'SELECT @Input_TicketResultId = CONVERT([int], {num});'.format(num = _TicketResultId)	\
												+	'\n'																					\
												+	'SELECT @Input_TruePositive = CONVERT([bit], {bit});'.format(bit = ({True: 'NULL', False: ({True: '1', False: '0'} [_TruePositive == True])} [_TruePositive == None]))		\
												+	'\n'																					\
												+	'SELECT @Input_FalsePositive = CONVERT([bit], {bit});'.format(bit = ({True: 'NULL', False: ({True: '1', False: '0'} [_FalsePositive == True])} [_FalsePositive == None]))	\
												+	'\n'																					\
												+	'EXECUTE [soar].[usp_UpdateTicketStatusAndResultByTicketId] '							\
												+	'		@TicketId = @Input_TicketId'	+	'\n'										\
												+	'	,	@UserId = @Input_UserId'	+	'\n'											\
												+	'	,	@TicketTypeId = @Input_TicketTypeId'	+	'\n'								\
												+	'	,	@TicketStatusId = @Input_TicketStatusId'	+	'\n'							\
												+	'	,	@TicketResultId = @Input_TicketResultId'	+	'\n'							\
												+	'	,	@TruePositive = @Input_TruePositive'	+	'\n'								\
												+	'	,	@FalsePositive = @Input_FalsePositive'	+	'\n'								\
												+	'	,	@ProcedureResult = @Output_ProcedureResult OUTPUT'	+	'\n'					\
												+	'	,	@ScopeRow_TicketId = @Output_ScopeRow_TicketId OUTPUT;'	+	'\n'				\
										#
										## let's remove new lines
										uspQueryCommandExec		=	uspQueryCommandExec.replace('\n','')												
										with	AzSQLconn_.cursor()	as	AzSQLcursor_:
											AzSQLcursor_.execute(uspQueryCommandExec)
											AzSQLcolumns	=	[x[0] for x in AzSQLcursor_.description]
											AzSQLrows		=	[tuple(r) for r in AzSQLcursor_.fetchall()]
										if		AzSQLcolumns	!=	None	\
											and	AzSQLrows		!=	None:
											if		len(AzSQLcolumns)	>	0	\
												and	len(AzSQLrows)		>	0:
												if		len(AzSQLcolumns)	==	len(AzSQLrows[0]):
													#
													AzSQLResultRowsAsDataFrame	=	pandas.DataFrame(data = AzSQLrows, columns = AzSQLcolumns)
													#
													currentTry_ProcessResult	=	True
													break
													#
											elif	len(AzSQLcolumns)	>	0	\
												and	len(AzSQLrows)		<=	0:
													#
													currentTry_ProcessResult	=	True
													break
													#
									except pyodbc.Error as _pEx:
										super().HandleGLobalException(_pEx)
									except Exception as _exInst:
										super().HandleGLobalException(_exInst)
									#
									if	currentTry_ProcessResult	==	True:
										break
									else:
										time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
										continue
									#
								#
			#
			return AzSQLResultRowsAsDataFrame
			# end _ExecuteUpdateTicketStatusAndResultByTicketId_AsPandas

	def _ExecuteInsertNewExternalReferenceForExistentTicket_AsPandas(					\
																			self		\
																		,	**kwargs	\
																	) -> list:
		##
		#	@brief Execute USP usp_InsertNewExternalReferenceForExistentTicket Return Result as Pandas DataFrame.
		#
		#	Keyword arguments
		#	@param TicketId										--	TicketId
		#	@param UserId										--	UserId
		#	@param ExternalReferenceTypeId						--	ExternalReferenceTypeId
		#	@param ExternalReferenceCaseNumber					--	ExternalReferenceCaseNumber
		#	@param ExternalReferenceCaseURL						--	ExternalReferenceCaseURL
		#	@param ExternalReferenceCaseComments				--	ExternalReferenceCaseComments
		""" Execute USP usp_InsertNewExternalReferenceForExistentTicket Return Result as Pandas DataFrame """
		self._arg		=	kwargs
		AzSQLResultRowsAsDataFrame	=	pandas.DataFrame(None).dropna()
		#
		if		'TicketId'										in	self._arg	\
			and	'UserId'										in	self._arg	\
			and	'ExternalReferenceTypeId'						in	self._arg	\
			and	'ExternalReferenceCaseNumber'					in	self._arg	\
			and	'ExternalReferenceCaseURL'						in	self._arg	\
			and	'ExternalReferenceCaseComments'					in	self._arg:
			#
			_TicketId										=	self._arg['TicketId']
			_UserId											=	self._arg['UserId']
			_ExternalReferenceTypeId						=	self._arg['ExternalReferenceTypeId']
			_ExternalReferenceCaseNumber					=	self._arg['ExternalReferenceCaseNumber']
			_ExternalReferenceCaseURL						=	self._arg['ExternalReferenceCaseURL']
			_ExternalReferenceCaseComments					=	self._arg['ExternalReferenceCaseComments']
			#
			if		_TicketId												>	int(0)	\
				and	_UserId													>	int(0)	\
				and	_ExternalReferenceTypeId								>	int(0)	\
				and super().CoalesceEmptyNorNoneThenNone(str(_ExternalReferenceCaseNumber))		!=	None	\
				and	super().CoalesceEmptyNorNoneThenNone(str(_ExternalReferenceCaseURL))		!=	None	\
				and	super().CoalesceEmptyNorNoneThenNone(str(_ExternalReferenceCaseComments))	!=	None:
				#
				azSQLtoken			=	None
				_runMSImodeInsteadCertificateBasedAuth	=	True
				if	'RunMSImodeInsteadCertificateBasedAuth'	in	self._soarGlobalSettings:
					_runMSImodeInsteadCertificateBasedAuth	=	bool(self._soarGlobalSettings['RunMSImodeInsteadCertificateBasedAuth'])
				#
				if		_runMSImodeInsteadCertificateBasedAuth	==	True	\
					and	'AutoAcctAzSQLLinkedServiceName'	in	self._soarGlobalSettings:
					_AutoAcctAzSQLLinkedServiceName_AsString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctAzSQLLinkedServiceName'])
					if	_AutoAcctAzSQLLinkedServiceName_AsString	!=	None:
						azSQLtoken		=	super().GetAccessTokenThroughMSI(_linkedServiceNameAsString=_AutoAcctAzSQLLinkedServiceName_AsString)
				else:
					azSQLtoken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																												_SPN_ApplicationId		=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppId']			\
																											,	_TenantId				=	self._soarGlobalSettings['AutoAcctSOARtorusTenantId']				\
																											,	_P12certBytes			=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12']			\
																											,	_P12certKy				=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12K']			\
																											,	_ScopeAudienceDomain	=	str('https://database.windows.net/')								\
																										)
				#
				if			azSQLtoken					!=	None	\
					and		self._soarGlobalSettings	!=	None:
					if	len(azSQLtoken)	>	0:
						if			'access_token'							in	azSQLtoken					\
							and		'AutoAcctSOARtorusAzSQLServerConn'		in	self._soarGlobalSettings:
							if		super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token'])									!=	None	\
								and	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])	!=	None:
								azSQLtokenAsBytes		=	b''
								for i in bytes(super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token']), 'UTF-8'):
									azSQLtokenAsBytes	+=	bytes({i})
									azSQLtokenAsBytes	+=	bytes(1)
								azSQLtokenAsStruct	=	struct.pack('=i', len(azSQLtokenAsBytes)) + azSQLtokenAsBytes
								#
								for currentTry in range(super()._maxRetries):
									#
									currentTry_ProcessResult	=	False
									#
									try:
										#
										connectionString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])
										AzSQLconn_			=	pyodbc.connect(connectionString, attrs_before = { super().SQL_COPT_SS_ACCESS_TOKEN:azSQLtokenAsStruct })
										AzSQLconn_.add_output_converter(-155, self.__HandleDateTimeOffsetHierarchy)
										AzSQLconn_.add_output_converter(pyodbc.SQL_BIT, self.__HandleBitHierarchy)
										uspQueryCommandExec		=			'DECLARE @Input_TicketId [bigint];'	+	'\n'		\
																		+	'DECLARE @Input_UserId [int];'	+	'\n'		\
																		+	'DECLARE @Input_ExternalReferenceTypeId [int];'	+	'\n'		\
																		+	'DECLARE @Input_ExternalReferenceCaseNumber [varchar](128);'	+	'\n'		\
																		+	'DECLARE @Input_ExternalReferenceCaseURL [nvarchar](2048);'	+	'\n'		\
																		+	'DECLARE @Input_ExternalReferenceCaseComments [nvarchar](4000);'	+	'\n'		\
																		+	'DECLARE @Input_ExternalReferenceEnabled [bit];'	+	'\n'		\
																		+	'DECLARE @Output_ProcedureResult [bit];'	+	'\n'		\
																		+	'DECLARE @Output_ScopeRow_ExternalReferenceId [bigint];'	+	'\n'		\
																		+	'\n'		\
																		+	'SELECT	@Input_TicketId	=	CONVERT([bigint], {num});'.format(num = _TicketId)	+	'\n'		\
																		+	'SELECT	@Input_UserId	=	CONVERT([int], {num});'.format(num = _UserId)	+	'\n'		\
																		+	'SELECT	@Input_ExternalReferenceTypeId	=	CONVERT([int], {num});'.format(num = _ExternalReferenceTypeId)	+	'\n'		\
																		+	'SELECT	@Input_ExternalReferenceCaseNumber	=	\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(str(_ExternalReferenceCaseNumber)))	+	'\n'		\
																		+	'SELECT	@Input_ExternalReferenceCaseURL	=	\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(str(_ExternalReferenceCaseURL)))	+	'\n'		\
																		+	'SELECT	@Input_ExternalReferenceCaseComments	=	\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(str(_ExternalReferenceCaseComments)))	+	'\n'		\
																		+	'SELECT	@Input_ExternalReferenceEnabled	=	NULL;'	+	'\n'		\
																		+	'\n'		\
																		+	'EXECUTE [soar].[usp_InsertNewExternalReferenceForExistentTicket] '	+	'\n'		\
																		+	'		@TicketId	=	@Input_TicketId'	+	'\n'		\
																		+	'	,	@UserId	=	@Input_UserId'	+	'\n'		\
																		+	'	,	@ExternalReferenceTypeId	=	@Input_ExternalReferenceTypeId'	+	'\n'		\
																		+	'	,	@ExternalReferenceCaseNumber	=	@Input_ExternalReferenceCaseNumber'	+	'\n'		\
																		+	'	,	@ExternalReferenceCaseURL	=	@Input_ExternalReferenceCaseURL'	+	'\n'		\
																		+	'	,	@ExternalReferenceCaseComments	=	@Input_ExternalReferenceCaseComments'	+	'\n'		\
																		+	'	,	@ExternalReferenceEnabled	=	@Input_ExternalReferenceEnabled'	+	'\n'		\
																		+	'	,	@ProcedureResult	=	@Output_ProcedureResult	OUTPUT'	+	'\n'		\
																		+	'	,	@ScopeRow_ExternalReferenceId	=	@Output_ScopeRow_ExternalReferenceId	OUTPUT;'
										#
										## let's remove new lines
										uspQueryCommandExec		=	uspQueryCommandExec.replace('\n','')
										with	AzSQLconn_.cursor()	as	AzSQLcursor_:
											AzSQLcursor_.execute(uspQueryCommandExec)
											AzSQLcolumns	=	[x[0] for x in AzSQLcursor_.description]
											AzSQLrows		=	[tuple(r) for r in AzSQLcursor_.fetchall()]
										if		AzSQLcolumns	!=	None	\
											and	AzSQLrows		!=	None:
											if		len(AzSQLcolumns)	>	0	\
												and	len(AzSQLrows)		>	0:
												if		len(AzSQLcolumns)	==	len(AzSQLrows[0]):
													#
													AzSQLResultRowsAsDataFrame	=	pandas.DataFrame(data = AzSQLrows, columns = AzSQLcolumns)
													#
													currentTry_ProcessResult	=	True
													break
													#
											elif	len(AzSQLcolumns)	>	0	\
												and	len(AzSQLrows)		<=	0:
													#
													currentTry_ProcessResult	=	True
													break
													#
										#
									except pyodbc.Error as _pEx:
										super().HandleGLobalException(_pEx)
									except Exception as _exInst:
										super().HandleGLobalException(_exInst)
									#
									if	currentTry_ProcessResult	==	True:
										break
									else:
										time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
										continue
									#
								#
				#
		#
		return AzSQLResultRowsAsDataFrame
		# end _ExecuteInsertNewExternalReferenceForExistentTicket_AsPandas

	def _ExecuteInsertNewResourceForExistentTicket_AsPandas(					\
																	self		\
																,	**kwargs	\
															) -> list:
		##
		#	@brief Execute USP usp_InsertNewResourceForExistentTicket Return Result as Pandas DataFrame.
		#
		#	Keyword arguments
		#	@param TicketId										--	TicketId
		#	@param soarAlertConfigs_AsPandasDataFrame			--	soarAlertConfigs_AsPandasDataFrame
		#	@param UserId										--	UserId
		#	@param ResourceTypeId								--	ResourceTypeId
		#	@param ResourceName									--	ResourceName
		#	@param ResourceIdAsGUID								--	ResourceIdAsGUID
		#	@param ResourceIdAsString							--	ResourceIdAsString
		#	@param ResourceObjectIdAsGUID						--	ResourceObjectIdAsGUID
		#	@param ResourceURL									--	ResourceURL
		#	@param ResourcePATH									--	ResourcePATH
		#	@param ResourceDescription							--	ResourceDescription
		""" Execute USP usp_InsertNewResourceForExistentTicket Return Result as Pandas DataFrame """
		self._arg		=	kwargs
		AzSQLResultRowsAsDataFrame	=	pandas.DataFrame(None).dropna()
		#
		if		'TicketId'										in	self._arg	\
			and	'soarAlertConfigs_AsPandasDataFrame'			in	self._arg	\
			and	'UserId'										in	self._arg	\
			and	'ResourceTypeId'								in	self._arg:
			#
			_TicketId										=	self._arg['TicketId']
			_soarAlertConfigs_AsPandasDataFrame				=	self._arg['soarAlertConfigs_AsPandasDataFrame']
			_UserId											=	self._arg['UserId']
			_ResourceTypeId									=	self._arg['ResourceTypeId']
			#
			_ResourceName				=	None
			_ResourceIdAsGUID			=	None
			_ResourceIdAsString			=	None
			_ResourceObjectIdAsGUID		=	None
			_ResourceURL				=	None
			_ResourcePATH				=	None
			_ResourceDescription		=	None
			#
			## TODO : review here if more parameters on resources are required, consider to make the proper changes on all optional values
			if	'ResourceName'			in	self._arg:
				if	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceName']))	!=	None:
					_ResourceName			=	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceName']))
			if	'ResourceIdAsGUID'		in	self._arg:
				if	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceIdAsGUID']))	!=	None:
					if	re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceIdAsGUID'])))	!=	None:
						guidMatch	=	re.search(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceIdAsGUID'])))
						if	len(guidMatch.group(0))	==	36:
							_ResourceIdAsGUID		=	guidMatch.group(0)
			if	'ResourceIdAsString'			in	self._arg:
				if	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceIdAsString']))	!=	None:
					_ResourceIdAsString			=	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceIdAsString']))
			if	'ResourceObjectIdAsGUID'		in	self._arg:
				if	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceObjectIdAsGUID']))	!=	None:
					if	re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceObjectIdAsGUID'])))	!=	None:
						guidMatch	=	re.search(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceObjectIdAsGUID'])))
						if	len(guidMatch.group(0))	==	36:
							_ResourceObjectIdAsGUID		=	guidMatch.group(0)
			if	'ResourceURL'			in	self._arg:
				if	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceURL']))	!=	None:
					_ResourceURL			=	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceURL']))
			if	'ResourcePATH'			in	self._arg:
				if	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourcePATH']))	!=	None:
					_ResourcePATH			=	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourcePATH']))
			if	'ResourceDescription'			in	self._arg:
				if	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceDescription']))	!=	None:
					_ResourceDescription			=	super().CoalesceEmptyNorNoneThenNone(str(self._arg['ResourceDescription']))
			#
			if		_TicketId												>	int(0)	\
				and	'TenantId'			in _soarAlertConfigs_AsPandasDataFrame.columns	\
				and	len(_soarAlertConfigs_AsPandasDataFrame)				>	int(0)	\
				and	_soarAlertConfigs_AsPandasDataFrame.shape[0]			>	int(0)	\
				and	_UserId													>	int(0)	\
				and	_ResourceTypeId											>	int(0):
				#
				azSQLtoken			=	None
				_runMSImodeInsteadCertificateBasedAuth	=	True
				if	'RunMSImodeInsteadCertificateBasedAuth'	in	self._soarGlobalSettings:
					_runMSImodeInsteadCertificateBasedAuth	=	bool(self._soarGlobalSettings['RunMSImodeInsteadCertificateBasedAuth'])
				#
				if		_runMSImodeInsteadCertificateBasedAuth	==	True	\
					and	'AutoAcctAzSQLLinkedServiceName'	in	self._soarGlobalSettings:
					_AutoAcctAzSQLLinkedServiceName_AsString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctAzSQLLinkedServiceName'])
					if	_AutoAcctAzSQLLinkedServiceName_AsString	!=	None:
						azSQLtoken		=	super().GetAccessTokenThroughMSI(_linkedServiceNameAsString=_AutoAcctAzSQLLinkedServiceName_AsString)
				else:
					azSQLtoken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																												_SPN_ApplicationId		=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppId']			\
																											,	_TenantId				=	self._soarGlobalSettings['AutoAcctSOARtorusTenantId']				\
																											,	_P12certBytes			=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12']			\
																											,	_P12certKy				=	self._soarGlobalSettings['AutoAcctSOARtorusServiceAppP12K']			\
																											,	_ScopeAudienceDomain	=	str('https://database.windows.net/')								\
																										)
				#
				if			azSQLtoken					!=	None	\
					and		self._soarGlobalSettings	!=	None:
					if	len(azSQLtoken)	>	0:
						if			'access_token'							in	azSQLtoken					\
							and		'AutoAcctSOARtorusAzSQLServerConn'		in	self._soarGlobalSettings:
							if		super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token'])									!=	None	\
								and	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])	!=	None:
								azSQLtokenAsBytes		=	b''
								for i in bytes(super().CoalesceEmptyNorNoneThenNone(azSQLtoken['access_token']), 'UTF-8'):
									azSQLtokenAsBytes	+=	bytes({i})
									azSQLtokenAsBytes	+=	bytes(1)
								azSQLtokenAsStruct	=	struct.pack('=i', len(azSQLtokenAsBytes)) + azSQLtokenAsBytes
								#
								for currentTry in range(super()._maxRetries):
									#
									currentTry_ProcessResult	=	False
									#
									try:
										#
										connectionString	=	super().CoalesceEmptyNorNoneThenNone(self._soarGlobalSettings['AutoAcctSOARtorusAzSQLServerConn'])
										AzSQLconn_			=	pyodbc.connect(connectionString, attrs_before = { super().SQL_COPT_SS_ACCESS_TOKEN:azSQLtokenAsStruct })
										AzSQLconn_.add_output_converter(-155, self.__HandleDateTimeOffsetHierarchy)
										AzSQLconn_.add_output_converter(pyodbc.SQL_BIT, self.__HandleBitHierarchy)
										#
										uspQueryCommandExec		=			'DECLARE @Input_TicketId [bigint];'	+	'\n'		\
																		+	'DECLARE @Input_TenantId [uniqueidentifier];'	+	'\n'		\
																		+	'DECLARE @Input_UserId [int];'	+	'\n'		\
																		+	'DECLARE @Input_ResourceTypeId [int];'	+	'\n'		\
																		+	'DECLARE @Input_ResourceName [nvarchar](840);'	+	'\n'		\
																		+	'DECLARE @Input_ResourceIdAsGUID [uniqueidentifier];'	+	'\n'		\
																		+	'DECLARE @Input_ResourceIdAsString [nvarchar](768);'	+	'\n'		\
																		+	'DECLARE @Input_ResourceObjectIdAsGUID [uniqueidentifier];'	+	'\n'		\
																		+	'DECLARE @Input_ResourceURL [nvarchar](4000);'	+	'\n'		\
																		+	'DECLARE @Input_ResourcePATH [nvarchar](4000);'	+	'\n'		\
																		+	'DECLARE @Input_ResourceDescription [nvarchar](2048);'	+	'\n'		\
																		+	'DECLARE @Input_ResourceEnabled [bit];'	+	'\n'		\
																		+	'DECLARE @Output_ProcedureResult [bit];'	+	'\n'		\
																		+	'DECLARE @Output_ScopeRow_ResourceId [bigint];'	+	'\n'		\
																		+	'\n'		\
																		+	'SELECT	@Input_TicketId	=	CONVERT([bigint], {num});'.format(num = _TicketId)	+	'\n'		\
																		+	'SELECT	@Input_TenantId	=	\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(str(_soarAlertConfigs_AsPandasDataFrame.iloc[0]['TenantId'])))	+	'\n'		\
																		+	'SELECT	@Input_UserId	=	CONVERT([int], {num});'.format(num = _UserId)	+	'\n'		\
																		+	'SELECT	@Input_ResourceTypeId	=	CONVERT([int], {num});'.format(num = _ResourceTypeId)	+	'\n'		\
																		+	'SELECT	@Input_ResourceName	=	'	\
																									+	str('\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_ResourceName))								if	super().CoalesceEmptyNorNoneThenNone(_ResourceName)	!=	None	else	'NULL;')	\
																									+	'\n'	\
																		+	'SELECT	@Input_ResourceIdAsGUID	=	'	\
																									+	str('CONVERT([uniqueidentifier], \'{string_value}\');'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_ResourceIdAsGUID))	if	super().CoalesceEmptyNorNoneThenNone(_ResourceIdAsGUID)		!=	None	else	'NULL;')	\
																									+	'\n'	\
																		+	'SELECT	@Input_ResourceIdAsString	=	'	\
																									+	str('\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_ResourceIdAsString))								if	super().CoalesceEmptyNorNoneThenNone(_ResourceIdAsString)	!=	None	else	'NULL;')	\
																									+	'\n'	\
																		+	'SELECT	@Input_ResourceObjectIdAsGUID	=	'	\
																									+	str('CONVERT([uniqueidentifier], \'{string_value}\');'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_ResourceObjectIdAsGUID))	if	super().CoalesceEmptyNorNoneThenNone(_ResourceObjectIdAsGUID)		!=	None	else	'NULL;')	\
																									+	'\n'	\
																		+	'SELECT	@Input_ResourceURL	=	'	\
																									+	str('\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_ResourceURL))								if	super().CoalesceEmptyNorNoneThenNone(_ResourceURL)	!=	None	else	'NULL;')	\
																									+	'\n'	\
																		+	'SELECT	@Input_ResourcePATH	=	'	\
																									+	str('\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_ResourcePATH))								if	super().CoalesceEmptyNorNoneThenNone(_ResourcePATH)	!=	None	else	'NULL;')	\
																									+	'\n'	\
																		+	'SELECT	@Input_ResourceDescription	=	'	\
																									+	str('\'{string_value}\';'.format(string_value = super().CoalesceEmptyNorNoneThenNone(_ResourceDescription))								if	super().CoalesceEmptyNorNoneThenNone(_ResourceDescription)	!=	None	else	'NULL;')	\
																									+	'\n'	\
																		+	'SELECT	@Input_ResourceEnabled	=	NULL;'	+	'\n'		\
																		+	'\n'		\
																		+	'EXECUTE [soar].[usp_InsertNewResourceForExistentTicket] '	+	'\n'		\
																		+	'		@TicketId	=	@Input_TicketId'	+	'\n'		\
																		+	'	,	@TenantId	=	@Input_TenantId'	+	'\n'		\
																		+	'	,	@UserId	=	@Input_UserId'	+	'\n'		\
																		+	'	,	@ResourceTypeId	=	@Input_ResourceTypeId'	+	'\n'		\
																		+	'	,	@ResourceName	=	@Input_ResourceName'	+	'\n'		\
																		+	'	,	@ResourceIdAsGUID	=	@Input_ResourceIdAsGUID'	+	'\n'		\
																		+	'	,	@ResourceIdAsString	=	@Input_ResourceIdAsString'	+	'\n'		\
																		+	'	,	@ResourceObjectIdAsGUID	=	@Input_ResourceObjectIdAsGUID'	+	'\n'		\
																		+	'	,	@ResourceURL	=	@Input_ResourceURL'	+	'\n'		\
																		+	'	,	@ResourcePATH	=	@Input_ResourcePATH'	+	'\n'		\
																		+	'	,	@ResourceDescription	=	@Input_ResourceDescription'	+	'\n'		\
																		+	'	,	@ResourceEnabled	=	@Input_ResourceEnabled'	+	'\n'		\
																		+	'	,	@ProcedureResult	=	@Output_ProcedureResult	OUTPUT'	+	'\n'		\
																		+	'	,	@ScopeRow_ResourceId	=	@Output_ScopeRow_ResourceId	OUTPUT;'
										#
										## let's remove new lines
										uspQueryCommandExec		=	uspQueryCommandExec.replace('\n','')
										with	AzSQLconn_.cursor()	as	AzSQLcursor_:
											AzSQLcursor_.execute(uspQueryCommandExec)
											AzSQLcolumns	=	[x[0] for x in AzSQLcursor_.description]
											AzSQLrows		=	[tuple(r) for r in AzSQLcursor_.fetchall()]
										if		AzSQLcolumns	!=	None	\
											and	AzSQLrows		!=	None:
											if		len(AzSQLcolumns)	>	0	\
												and	len(AzSQLrows)		>	0:
												if		len(AzSQLcolumns)	==	len(AzSQLrows[0]):
													#
													AzSQLResultRowsAsDataFrame	=	pandas.DataFrame(data = AzSQLrows, columns = AzSQLcolumns)
													#
													currentTry_ProcessResult	=	True
													break
													#
											elif	len(AzSQLcolumns)	>	0	\
												and	len(AzSQLrows)		<=	0:
													#
													currentTry_ProcessResult	=	True
													break
													#
									except pyodbc.Error as _pEx:
										super().HandleGLobalException(_pEx)
									except Exception as _exInst:
										super().HandleGLobalException(_exInst)
									#
									if	currentTry_ProcessResult	==	True:
										break
									else:
										time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
										continue
									#
								#
				#
		#
		return AzSQLResultRowsAsDataFrame
		# end _ExecuteInsertNewResourceForExistentTicket_AsPandas

	# end class AzSQL_DAL
	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •


# In[ ]:


class AzGraphHandler(Base):
	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •
	##
	# @brief	Protected Member Variables
	#
	_soarGlobalSettings		=	{}
	_randomChars			=	string.ascii_letters + string.digits + '!@#$%^&*()[]'

	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •
	##
	# @brief	Public Member Variables
	#
	T							=	TypeVar('T')

	##
	# @brief	AzGraphHandler Constructor
	def __init__(self, soarGlobalSettings : dict):
		self._soarGlobalSettings = soarGlobalSettings
		super(AzGraphHandler, self).__init__(soarGlobalSettings = self._soarGlobalSettings)
		#

	def DoJoinDataFrameWithAzGraphEnabledStatus(
														self														\
													,	TenantId:							str						\
													,	ServiceApplicationId:				str						\
													,	ServiceApplicationP12bytes:			bytes					\
													,	ServiceAppP12Kbytes:				bytes					\
													,	inputPandasDataFrame:				pandas.DataFrame	=	pandas.DataFrame(None).dropna()		\
													,	_TimeOutInSeconds:					int					=	int(15)								\
												) -> pandas.DataFrame:
		##
		#	@brief Do Join Input-DataFrame with Az-Graph Enabled Status
		#
		#	Keyword arguments:
		#	@param TenantId										--
		#	@param ServiceApplicationId				--
		#	@param ServiceApplicationP12bytes		--
		#	@param ServiceAppP12Kbytes				--
		#	@param inputPandasDataFrame							--
		"""
		Do Join Input-DataFrame with Az-Graph Enabled Status
		"""
		returnPandasDataFrame	=	pandas.DataFrame(None).dropna()
		#
		if			super().CoalesceEmptyNorNoneThenNone(TenantId)														!=	None		\
			and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(TenantId))				!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)											!=	None		\
			and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId))	!=	None		\
			and		len(ServiceApplicationP12bytes)																		>	0			\
			and		len(ServiceAppP12Kbytes)																			>	0			\
			and		inputPandasDataFrame.empty	!=	True:
			if		inputPandasDataFrame.shape[0]	>	0	\
				and	inputPandasDataFrame.shape[1]	>	0:
				if	'UPN'	in	inputPandasDataFrame.columns:
					if	len(list(set(inputPandasDataFrame['UPN'].where((inputPandasDataFrame['UPN'] != None) & (inputPandasDataFrame['UPN'].str.strip().str.len() > int(0)) & (inputPandasDataFrame['UPN'].astype(str).str.lower().str.casefold().ne('none') == True)).dropna(how = 'all').tolist())))	>	0:
						listUPNs_AsList				=	list(set(inputPandasDataFrame['UPN'].where((inputPandasDataFrame['UPN'] != None) & (inputPandasDataFrame['UPN'].str.strip().str.len() > int(0)) & (inputPandasDataFrame['UPN'].astype(str).str.lower().str.casefold().ne('none') == True)).dropna(how = 'all').tolist()))
						listUPNs_AsListToConvert	=	[]
						#
						for	x in range(len(listUPNs_AsList)):
							verifiedUPN		=	None
							#
							if	super().CoalesceEmptyNorNoneThenNone(listUPNs_AsList[x])	!=	None:
								#
								for currentTry in range(super()._maxRetries):
								#
									#
									currentTry_ProcessResult	=	False
									#
									try:
										if	re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(listUPNs_AsList[x]))	!=	None:
											guidMatch	=	re.search(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(listUPNs_AsList[x]))
											if	len(guidMatch.group(0))	==	36:
												UPNasGUID	=	guidMatch.group(0)
												Graph_AAD_RestApiTokenRequest_SPNfullTokenToGatherUPN = super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																																											_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																																										,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																																										,	_P12certBytes			=	ServiceApplicationP12bytes											\
																																										,	_P12certKy				=	ServiceAppP12Kbytes													\
																																										,	_ScopeAudienceDomain	=	str('https://graph.microsoft.com')									\
																																									)
												if		Graph_AAD_RestApiTokenRequest_SPNfullTokenToGatherUPN			!=	None	\
													and	len(Graph_AAD_RestApiTokenRequest_SPNfullTokenToGatherUPN)	>	0:
													# url
													GetUPN_InfoUrl			=		'https://graph.microsoft.com/v1.0/users/'							\
																				+	super().CoalesceEmptyNorNoneThenNone(UPNasGUID)						\
																				+	'?$select=userPrincipalName,mail,id,accountEnabled,displayName'		\
													#
													HeadersV1				=	{
																						'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = Graph_AAD_RestApiTokenRequest_SPNfullTokenToGatherUPN['access_token'])
																					,	'Content-Type'					:		'application/json; charset=utf-8'
																					,	'accept'						:		'application/json, text/plain, */*'
																				}
													#
													UPN_InfoFromHttpPost	=	requests.get(													\
																									url				=	GetUPN_InfoUrl			\
																								,	headers			=	HeadersV1				\
																								,	timeout			=	_TimeOutInSeconds		\
																							)
													#
													if	not	UPN_InfoFromHttpPost is None:
														if		UPN_InfoFromHttpPost.status_code >= int(200)	\
															and	UPN_InfoFromHttpPost.status_code <= int(299):
															if	super().CoalesceEmptyNorNoneThenNone(UPN_InfoFromHttpPost.text)	!=	None:
																UPN_InfoFromHttpPostResponseText_AsJSON		=	json.loads(super().CoalesceEmptyNorNoneThenNone(UPN_InfoFromHttpPost.text))
																if		'userPrincipalName'		in	UPN_InfoFromHttpPostResponseText_AsJSON		\
																	and	'id'					in	UPN_InfoFromHttpPostResponseText_AsJSON:
																	verifiedUPN	=	super().CoalesceEmptyNorNoneThenNone(UPN_InfoFromHttpPostResponseText_AsJSON['userPrincipalName'])
														else:
															super().HandleGLobalPostRequestError(																		\
																										_reason			=	UPN_InfoFromHttpPost.reason					\
																									,	_status_code	=	int(UPN_InfoFromHttpPost.status_code)		\
																									,	_text			=	UPN_InfoFromHttpPost.text					\
																									,	_content		=	UPN_InfoFromHttpPost.content				\
																								)
													#
										#
										else:
											verifiedUPN		=	super().CoalesceEmptyNorNoneThenNone(listUPNs_AsList[x])
										#
										if	super().CoalesceEmptyNorNoneThenNone(verifiedUPN)	!=	None:
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											## let's gather current status for the account
											CurrentUPN		=	super().CoalesceEmptyNorNoneThenNone(verifiedUPN)
											Graph_AAD_RestApiTokenRequest_SPNfullToken	=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																																								_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																																							,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																																							,	_P12certBytes			=	ServiceApplicationP12bytes											\
																																							,	_P12certKy				=	ServiceAppP12Kbytes													\
																																							,	_ScopeAudienceDomain	=	str('https://graph.microsoft.com')									\
																																						)
											if		Graph_AAD_RestApiTokenRequest_SPNfullToken			!=	None	\
													and	len(Graph_AAD_RestApiTokenRequest_SPNfullToken)	>	0:
												# url
												GetUPN_InfoUrl			=		'https://graph.microsoft.com/v1.0/users/'							\
																			+	super().CoalesceEmptyNorNoneThenNone(CurrentUPN)					\
																			+	'?$select=userPrincipalName,mail,id,accountEnabled,displayName'		\
												#
												HeadersV2				=	{
																					'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = Graph_AAD_RestApiTokenRequest_SPNfullToken['access_token'])
																				,	'Content-Type'					:		'application/json; charset=utf-8'
																				,	'accept'						:		'application/json, text/plain, */*'
																			}
												#
												emailInfo	=	requests.get(													\
																					url				=	GetUPN_InfoUrl			\
																				,	headers			=	HeadersV2				\
																				,	timeout			=	_TimeOutInSeconds		\
																			)
												#
												currentUPN_IsEnabledStatusAsBool	=	bool(False)
												#
												if	not	emailInfo is None:
													if		emailInfo.status_code >= int(200)	\
														and	emailInfo.status_code <= int(299):
														if	super().CoalesceEmptyNorNoneThenNone(emailInfo.text)	!=	None:
															emailInfo_AsJSON		=	json.loads(super().CoalesceEmptyNorNoneThenNone(emailInfo.text))
															if		'userPrincipalName'		in	emailInfo_AsJSON		\
																and	'id'					in	emailInfo_AsJSON		\
																and	'accountEnabled'		in	emailInfo_AsJSON:
																if	super().fold_text(super().CoalesceEmptyNorNoneThenNone(CurrentUPN))	== 	super().fold_text(super().CoalesceEmptyNorNoneThenNone(emailInfo_AsJSON['userPrincipalName'])):
																	if	bool(emailInfo_AsJSON['accountEnabled'])	==	bool(True):
																		currentUPN_IsEnabledStatusAsBool	=	bool(True)
																	else:
																		currentUPN_IsEnabledStatusAsBool	=	bool(False)
																	#
																	#
																	listUPNs_AsListToConvert.append({			\
																												'UPN'											:	super().CoalesceEmptyNorNoneThenNone(CurrentUPN)						\
																											,	'AzADUser_WasEnabled_PriorRemediation_AsBool'	:	currentUPN_IsEnabledStatusAsBool										\
																											,	'AzADUser_Id_AsGUID'							:	super().CoalesceEmptyNorNoneThenNone(str(emailInfo_AsJSON['id']))		\
																									})
																	#
																	#
																	currentTry_ProcessResult	=	True
																	break
																	#
																	#
													elif	emailInfo.status_code == int(404):
														if	super().CoalesceEmptyNorNoneThenNone(emailInfo.text)	!=	None:
															_verify_Request_ResourceNotFound_asJSON		=	(json.loads(emailInfo.text))
															if	 'error' in _verify_Request_ResourceNotFound_asJSON:
																if	'code' in _verify_Request_ResourceNotFound_asJSON['error']:
																	if	super().CoalesceEmptyNorNoneThenNone(_verify_Request_ResourceNotFound_asJSON['error']['code'])	!=	None:
																		if	super().fold_text(super().CoalesceEmptyNorNoneThenNone(_verify_Request_ResourceNotFound_asJSON['error']['code']))	== 	super().fold_text(super().CoalesceEmptyNorNoneThenNone('Request_ResourceNotFound')):
																			#
																			#
																			## ## ## in this case, the email DO NOT exists on the AzAD, let's continue with next email without append on listUPNs_AsListToConvert
																			#
																			currentTry_ProcessResult	=	True
																			break
																			#
																			#
													else:
														#
														### deprecated 2024/07/09
														# # # # # if	currentTry	>=	int(super()._maxRetries - 1):
														# # # # # 	listUPNs_AsListToConvert.append({			\
														# # # # # 												'UPN'											:	super().CoalesceEmptyNorNoneThenNone(CurrentUPN)	\
														# # # # # 											,	'AzADUser_WasEnabled_PriorRemediation_AsBool'	:	bool(False)											\
														# # # # # 											,	'AzADUser_Id_AsGUID'							:	None												\
														# # # # # 									})
														#
														super().HandleGLobalPostRequestError(															\
																									_reason			=	emailInfo.reason				\
																								,	_status_code	=	int(emailInfo.status_code)		\
																								,	_text			=	emailInfo.text					\
																								,	_content		=	emailInfo.content				\
																							)
														#
												#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
									except requests.exceptions.HTTPError as httpEerr_:
										super().HandleGLobalException(httpEerr_)
									except requests.exceptions.ConnectionError as cnEerr_:
										super().HandleGLobalException(cnEerr_)
									except requests.exceptions.Timeout as toEerr_:
										super().HandleGLobalException(toEerr_)
									except requests.exceptions.RequestException as reqEx_:
										super().HandleGLobalException(reqEx_)
									except Exception as _exInst:
										super().HandleGLobalException(_exInst)
									#
									if	currentTry_ProcessResult	==	True:
										break
									else:
										time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
										continue
									#
								# end for currentTry
								#
						# end for range(len(listUPNs_AsList))
						#
						if	len(listUPNs_AsListToConvert)	==	len(listUPNs_AsList):
							returnPandasDataFrame	=	pandas.DataFrame(																								\
																				data	= listUPNs_AsListToConvert														\
																			,	columns	= ['UPN','AzADUser_WasEnabled_PriorRemediation_AsBool','AzADUser_Id_AsGUID']	\
																		)
						#
		#
		return returnPandasDataFrame
		#

	def DoProcessAzADUserRemediation(
											self																							\
										,	TenantId:							str															\
										,	ServiceApplicationId:				str															\
										,	ServiceApplicationP12bytes:			bytes														\
										,	ServiceAppP12Kbytes:				bytes														\
										,	AzADUserRemediationActionsAsDict:	dict														\
										,	AzADUserDetailsAsPandasDataFrame:	pandas.DataFrame	=	pandas.DataFrame(None).dropna()		\
										,	TimeOutInSeconds:					int					=	int(20)								\
										,	randomPasswordLength:				int					=	int(30)
									) -> pandas.DataFrame:
		##
		#	@brief Do Process AzADUser Remediation
		#
		#	Keyword arguments:
		#	@param TenantId								--
		#	@param ServiceApplicationId					--
		#	@param ServiceApplicationP12bytes			--
		#	@param ServiceAppP12Kbytes					--
		#	@param AzADUserDetailsAsPandasDataFrame		--
		"""
		Do Process AzADUser Remediation
		"""
		returnActionsResultsAsPDF	=	pandas.DataFrame(None).dropna()
		returnActionsResultsAsPDF	=	pandas.DataFrame({	\
																c	:	pandas.Series(dtype=t)	for	c
															,	t	in	{	\
																				'RemediationTypeName'		:	numpy.dtype('U')		\
																			,	'ExecutionSuccessfulResult'	:	numpy.dtype('?')		\
																			,	'RemediationCode'			:	numpy.dtype('i')		\
																			,	'AzADUser_Id_AsGUID'		:	numpy.dtype('U')		\
																			,	'UPN'						:	numpy.dtype('U')		\
																		}.items()	\
														})
		#
		if		AzADUserDetailsAsPandasDataFrame.empty	!=	True	\
			and	len(AzADUserRemediationActionsAsDict)	>	int(0):
			if		AzADUserDetailsAsPandasDataFrame.shape[0]	>	0	\
				and	AzADUserDetailsAsPandasDataFrame.shape[1]	>	0:
				if		'UPN'					in	AzADUserDetailsAsPandasDataFrame.columns	\
					and	'AzADUser_Id_AsGUID'	in	AzADUserDetailsAsPandasDataFrame.columns:
					if		super().CoalesceEmptyNorNoneThenNone(AzADUserDetailsAsPandasDataFrame['UPN'].iloc[0])	!=	None	\
						and	super().fold_text(super().CoalesceEmptyNorNoneThenNone(AzADUserDetailsAsPandasDataFrame['UPN'].iloc[0]))	!=	super().fold_text(super().CoalesceEmptyNorNoneThenNone('None')):
						if		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(AzADUserDetailsAsPandasDataFrame['AzADUser_Id_AsGUID'].iloc[0]))	!=	None	\
							and	super().CoalesceEmptyNorNoneThenNone(TenantId)															!=	None		\
							and	re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(TenantId))					!=	None		\
							and		super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)											!=	None		\
							and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId))	!=	None		\
							and		len(ServiceApplicationP12bytes)																		>	0			\
							and		len(ServiceAppP12Kbytes)																			>	0:
							guidSGidMatch	=	re.search(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(AzADUserDetailsAsPandasDataFrame['AzADUser_Id_AsGUID'].iloc[0]))
							if	len(guidSGidMatch.group(0))	==	36:
								#
								UPNasGUID		=	guidSGidMatch.group(0)
								UPN				=	super().CoalesceEmptyNorNoneThenNone(AzADUserDetailsAsPandasDataFrame['UPN'].iloc[0])
								randomizer		=	random.SystemRandom()
								#
								# @xxxxxxxx][==============================================================>
								#
								if	'DisableAccountAsNewState'	in	AzADUserRemediationActionsAsDict:
									if	bool(AzADUserRemediationActionsAsDict['DisableAccountAsNewState'])	==	True:
										#
										for currentTry in range(super()._maxRetries):
										#
											#
											currentTry_ProcessResult	=	False
											#
											try:
												Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD = super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																											\
																																											_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																																										,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																																										,	_P12certBytes			=	ServiceApplicationP12bytes											\
																																										,	_P12certKy				=	ServiceAppP12Kbytes													\
																																										,	_ScopeAudienceDomain	=	str('https://graph.microsoft.com')									\
																																									)
												if		Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD			!=	None	\
													and	len(Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD)	>	0:
													#
													# ref : https://learn.microsoft.com/en-us/graph/api/user-update
													# url
													Patch_accountEnabled_Url	=		'https://graph.microsoft.com/v1.0/users/'				\
																					+	super().CoalesceEmptyNorNoneThenNone(UPNasGUID)
													#
													Patch_accountEnabled_Body	=	{
																						'accountEnabled'	:	False
																					}
													#
													HeadersV1					=	{
																							'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD['access_token'])
																						,	'Content-Type'					:		'application/json; charset=utf-8'
																					}
													#
													Response_accountEnabled_HttpPatch	=	requests.patch(																		\
																													url				=	Patch_accountEnabled_Url				\
																												,	json			=	Patch_accountEnabled_Body				\
																												,	data			=	json.dumps(Patch_accountEnabled_Body)	\
																												,	headers			=	HeadersV1								\
																												,	timeout			=	TimeOutInSeconds						\
																											)
													#
													if	not	Response_accountEnabled_HttpPatch is None:
														### ref : https://developer.mozilla.org/en-US/docs/Web/HTTP/Status#successful_responses
														if		Response_accountEnabled_HttpPatch.status_code >= int(200)	\
															and Response_accountEnabled_HttpPatch.status_code <= int(299):
															#
															newRowAsDict	=	{}
															newRowAsDict	=	{
																						'RemediationTypeName'			:	'DisableAccountAsNewState'
																					,	'ExecutionSuccessfulResult'		:	True
																					,	'RemediationCode'				:	Response_accountEnabled_HttpPatch.status_code
																					,	'AzADUser_Id_AsGUID'			:	UPNasGUID
																					,	'UPN'							:	UPN
																				}
															returnActionsResultsAsPDF	=	pandas.concat([returnActionsResultsAsPDF, pandas.DataFrame([newRowAsDict])], ignore_index = True, verify_integrity = False, sort = False)
															#
															currentTry_ProcessResult	=	True
															break
															#
														else:
															super().HandleGLobalPostRequestError(																					\
																										_reason			=	Response_accountEnabled_HttpPatch.reason				\
																									,	_status_code	=	int(Response_accountEnabled_HttpPatch.status_code)		\
																									,	_text			=	Response_accountEnabled_HttpPatch.text					\
																									,	_content		=	Response_accountEnabled_HttpPatch.content				\
																								)
													#
											except requests.exceptions.HTTPError as httpEerr_:
												super().HandleGLobalException(httpEerr_)
											except requests.exceptions.ConnectionError as cnEerr_:
												super().HandleGLobalException(cnEerr_)
											except requests.exceptions.Timeout as toEerr_:
												super().HandleGLobalException(toEerr_)
											except requests.exceptions.RequestException as reqEx_:
												super().HandleGLobalException(reqEx_)
											except Exception as _exInst:
												super().HandleGLobalException(_exInst)
											#
											if	currentTry_ProcessResult	==	True:
												break
											else:
												time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
												continue
											#
										# end for currentTry
										#
									# end DisableAccountAsNewState == True
								#
								# @xxxxxxxx][==============================================================>
								#
								if	'ReEnableAccountAsNewState'	in	AzADUserRemediationActionsAsDict:
									if	bool(AzADUserRemediationActionsAsDict['ReEnableAccountAsNewState'])	==	True:
										#
										for currentTry in range(super()._maxRetries):
										#
											#
											currentTry_ProcessResult	=	False
											#
											try:
												Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD = super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																											\
																																											_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																																										,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																																										,	_P12certBytes			=	ServiceApplicationP12bytes											\
																																										,	_P12certKy				=	ServiceAppP12Kbytes													\
																																										,	_ScopeAudienceDomain	=	str('https://graph.microsoft.com')									\
																																									)
												if		Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD			!=	None	\
													and	len(Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD)	>	0:
													#
													# ref : https://learn.microsoft.com/en-us/graph/api/user-update
													# url
													Patch_accountEnabled_Url	=		'https://graph.microsoft.com/v1.0/users/'				\
																					+	super().CoalesceEmptyNorNoneThenNone(UPNasGUID)
													#
													Patch_accountEnabled_Body	=	{
																						'accountEnabled'	:	True
																					}
													#
													HeadersV1					=	{
																							'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD['access_token'])
																						,	'Content-Type'					:		'application/json; charset=utf-8'
																					}
													#
													Response_accountEnabled_HttpPatch	=	requests.patch(																		\
																													url				=	Patch_accountEnabled_Url				\
																												,	json			=	Patch_accountEnabled_Body				\
																												,	data			=	json.dumps(Patch_accountEnabled_Body)	\
																												,	headers			=	HeadersV1								\
																												,	timeout			=	TimeOutInSeconds						\
																											)
													#
													if	not	Response_accountEnabled_HttpPatch is None:
														if		Response_accountEnabled_HttpPatch.status_code >= int(200)	\
															and Response_accountEnabled_HttpPatch.status_code <= int(299):
															#
															newRowAsDict	=	{}
															newRowAsDict	=	{
																						'RemediationTypeName'			:	'ReEnableAccountAsNewState'
																					,	'ExecutionSuccessfulResult'		:	True
																					,	'RemediationCode'				:	Response_accountEnabled_HttpPatch.status_code
																					,	'AzADUser_Id_AsGUID'			:	UPNasGUID
																					,	'UPN'							:	UPN
																				}
															returnActionsResultsAsPDF	=	pandas.concat([returnActionsResultsAsPDF, pandas.DataFrame([newRowAsDict])], ignore_index = True, verify_integrity = False, sort = False)
															#
															currentTry_ProcessResult	=	True
															break
															#
														else:
															super().HandleGLobalPostRequestError(																					\
																										_reason			=	Response_accountEnabled_HttpPatch.reason				\
																									,	_status_code	=	int(Response_accountEnabled_HttpPatch.status_code)		\
																									,	_text			=	Response_accountEnabled_HttpPatch.text					\
																									,	_content		=	Response_accountEnabled_HttpPatch.content				\
																								)
													#
											except requests.exceptions.HTTPError as httpEerr_:
												super().HandleGLobalException(httpEerr_)
											except requests.exceptions.ConnectionError as cnEerr_:
												super().HandleGLobalException(cnEerr_)
											except requests.exceptions.Timeout as toEerr_:
												super().HandleGLobalException(toEerr_)
											except requests.exceptions.RequestException as reqEx_:
												super().HandleGLobalException(reqEx_)
											except Exception as _exInst:
												super().HandleGLobalException(_exInst)
											#
											if	currentTry_ProcessResult	==	True:
												break
											else:
												time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
												continue
											#
										# end for currentTry
										#
									# end ReEnableAccountAsNewState == True
								#
								# @xxxxxxxx][==============================================================>
								#
								if	'ResetAccountPassword'	in	AzADUserRemediationActionsAsDict:
									if	bool(AzADUserRemediationActionsAsDict['ResetAccountPassword'])	==	True:
										#
										for currentTry in range(super()._maxRetries):
										#
											#
											currentTry_ProcessResult	=	False
											#
											try:
												Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD = super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																											\
																																											_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																																										,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																																										,	_P12certBytes			=	ServiceApplicationP12bytes											\
																																										,	_P12certKy				=	ServiceAppP12Kbytes													\
																																										,	_ScopeAudienceDomain	=	str('https://graph.microsoft.com')									\
																																									)
												if		Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD			!=	None	\
													and	len(Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD)	>	0:
													#
													# ref : https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0&tabs=http#example-3-update-the-passwordprofile-of-a-user-to-reset-their-password
													# ref : https://learn.microsoft.com/en-us/graph/api/resources/passwordprofile?view=graph-rest-1.0
													# url
													Patch_passwordProfile_Url	=		'https://graph.microsoft.com/v1.0/users/'				\
																					+	super().CoalesceEmptyNorNoneThenNone(UPNasGUID)
													#
													randomPsw					=	''.join(randomizer.choice(self._randomChars) for i in range(randomPasswordLength))
													#
													Patch_passwordProfile_Body	=	{
																						'passwordProfile'	:	{
																													'password'	:	str(randomPsw)
																												}
																					}
													#
													HeadersV1					=	{
																							'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD['access_token'])
																						,	'Content-Type'					:		'application/json; charset=utf-8'
																					}
													#
													Response_passwordProfile_HttpPatch	=	requests.patch(																		\
																													url				=	Patch_passwordProfile_Url				\
																												,	json			=	Patch_passwordProfile_Body				\
																												,	data			=	json.dumps(Patch_passwordProfile_Body)	\
																												,	headers			=	HeadersV1								\
																												,	timeout			=	TimeOutInSeconds						\
																											)
													#
													if	not	Response_passwordProfile_HttpPatch is None:
														if		Response_passwordProfile_HttpPatch.status_code >= int(200)	\
															and Response_passwordProfile_HttpPatch.status_code <= int(299):
															#
															newRowAsDict	=	{}
															newRowAsDict	=	{
																						'RemediationTypeName'			:	'ResetAccountPassword'
																					,	'ExecutionSuccessfulResult'		:	True
																					,	'RemediationCode'				:	Response_passwordProfile_HttpPatch.status_code
																					,	'AzADUser_Id_AsGUID'			:	UPNasGUID
																					,	'UPN'							:	UPN
																				}
															returnActionsResultsAsPDF	=	pandas.concat([returnActionsResultsAsPDF, pandas.DataFrame([newRowAsDict])], ignore_index = True, verify_integrity = False, sort = False)
															#
															currentTry_ProcessResult	=	True
															break
															#
														else:
															super().HandleGLobalPostRequestError(																					\
																										_reason			=	Response_passwordProfile_HttpPatch.reason				\
																									,	_status_code	=	int(Response_passwordProfile_HttpPatch.status_code)		\
																									,	_text			=	Response_passwordProfile_HttpPatch.text					\
																									,	_content		=	Response_passwordProfile_HttpPatch.content				\
																								)
													#
											except requests.exceptions.HTTPError as httpEerr_:
												super().HandleGLobalException(httpEerr_)
											except requests.exceptions.ConnectionError as cnEerr_:
												super().HandleGLobalException(cnEerr_)
											except requests.exceptions.Timeout as toEerr_:
												super().HandleGLobalException(toEerr_)
											except requests.exceptions.RequestException as reqEx_:
												super().HandleGLobalException(reqEx_)
											except Exception as _exInst:
												super().HandleGLobalException(_exInst)
											#
											if	currentTry_ProcessResult	==	True:
												break
											else:
												time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
												continue
											#
										# end for currentTry
										#
									# end ResetAccountPassword == True
								#
								# @xxxxxxxx][==============================================================>
								#
								if	'ForceChangePasswordAtLogon'	in	AzADUserRemediationActionsAsDict:
									if	bool(AzADUserRemediationActionsAsDict['ForceChangePasswordAtLogon'])	==	True:
										#
										for currentTry in range(super()._maxRetries):
										#
											#
											currentTry_ProcessResult	=	False
											#
											try:
												Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD = super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																											\
																																											_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																																										,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																																										,	_P12certBytes			=	ServiceApplicationP12bytes											\
																																										,	_P12certKy				=	ServiceAppP12Kbytes													\
																																										,	_ScopeAudienceDomain	=	str('https://graph.microsoft.com')									\
																																									)
												if		Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD			!=	None	\
													and	len(Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD)	>	0:
													#
													# ref : https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0&tabs=http#example-3-update-the-passwordprofile-of-a-user-to-reset-their-password
													# ref : https://learn.microsoft.com/en-us/graph/api/resources/passwordprofile?view=graph-rest-1.0
													# url
													Patch_passwordProfile_Url	=		'https://graph.microsoft.com/v1.0/users/'				\
																					+	super().CoalesceEmptyNorNoneThenNone(UPNasGUID)
													#
													Patch_passwordProfile_Body	=	{
																						'passwordProfile'	:	{
																														'forceChangePasswordNextSignIn'	:	True
																												}
																					}
													#
													HeadersV1					=	{
																							'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD['access_token'])
																						,	'Content-Type'					:		'application/json; charset=utf-8'
																					}
													#
													Response_passwordProfile_HttpPatch	=	requests.patch(																		\
																													url				=	Patch_passwordProfile_Url				\
																												,	json			=	Patch_passwordProfile_Body				\
																												,	data			=	json.dumps(Patch_passwordProfile_Body)	\
																												,	headers			=	HeadersV1								\
																												,	timeout			=	TimeOutInSeconds						\
																											)
													#
													if	not	Response_passwordProfile_HttpPatch is None:
														if		Response_passwordProfile_HttpPatch.status_code >= int(200)	\
															and Response_passwordProfile_HttpPatch.status_code <= int(299):
															#
															newRowAsDict	=	{}
															newRowAsDict	=	{
																						'RemediationTypeName'			:	'ForceChangePasswordAtLogon'
																					,	'ExecutionSuccessfulResult'		:	True
																					,	'RemediationCode'				:	Response_passwordProfile_HttpPatch.status_code
																					,	'AzADUser_Id_AsGUID'			:	UPNasGUID
																					,	'UPN'							:	UPN
																				}
															returnActionsResultsAsPDF	=	pandas.concat([returnActionsResultsAsPDF, pandas.DataFrame([newRowAsDict])], ignore_index = True, verify_integrity = False, sort = False)
															#
															currentTry_ProcessResult	=	True
															break
															#
														else:
															super().HandleGLobalPostRequestError(																					\
																										_reason			=	Response_passwordProfile_HttpPatch.reason				\
																									,	_status_code	=	int(Response_passwordProfile_HttpPatch.status_code)		\
																									,	_text			=	Response_passwordProfile_HttpPatch.text					\
																									,	_content		=	Response_passwordProfile_HttpPatch.content				\
																								)
													#
											except requests.exceptions.HTTPError as httpEerr_:
												super().HandleGLobalException(httpEerr_)
											except requests.exceptions.ConnectionError as cnEerr_:
												super().HandleGLobalException(cnEerr_)
											except requests.exceptions.Timeout as toEerr_:
												super().HandleGLobalException(toEerr_)
											except requests.exceptions.RequestException as reqEx_:
												super().HandleGLobalException(reqEx_)
											except Exception as _exInst:
												super().HandleGLobalException(_exInst)
											#
											if	currentTry_ProcessResult	==	True:
												break
											else:
												time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
												continue
											#
										# end for currentTry
										#
									# end ForceChangePasswordAtLogon == True
								#
								# @xxxxxxxx][==============================================================>
								#
								if		'ForceAddToRevokedSecurityGroup'	in	AzADUserRemediationActionsAsDict	\
									and	'RevokedSecurityGroupName'				in	AzADUserRemediationActionsAsDict:
									if		bool(AzADUserRemediationActionsAsDict['ForceAddToRevokedSecurityGroup'])	==	True	\
										and	super().CoalesceEmptyNorNoneThenNone(str(AzADUserRemediationActionsAsDict['RevokedSecurityGroupName']))	!=	None:
										#
										for currentTry in range(super()._maxRetries):
										#
											#
											currentTry_ProcessResult	=	False
											memberOf_Details_AsJSON		=	{}
											#
											try:
												#
												bCurrentUserExistsOnRevokedSG	=	False
												strRevokedSecurityGroupName		=	super().CoalesceEmptyNorNoneThenNone(str(AzADUserRemediationActionsAsDict['RevokedSecurityGroupName']))
												RevokedSecurityGroupId_AsGUID	=	None
												#
												# ••---------------------------------------------------------------------------------->
												#
												Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD = super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																											\
																																											_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																																										,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																																										,	_P12certBytes			=	ServiceApplicationP12bytes											\
																																										,	_P12certKy				=	ServiceAppP12Kbytes													\
																																										,	_ScopeAudienceDomain	=	str('https://graph.microsoft.com')									\
																																									)
												if		Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD			!=	None	\
													and	len(Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD)	>	0:


													# ### ref : https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http#example-5-use-search-to-get-groups-with-display-names-that-contain-the-letters-video-or-a-description-that-contains-the-letters-prod-including-a-count-of-returned-objects
													# url
													Get_listSGGroup_Url	=				'https://graph.microsoft.com/v1.0/groups?$filter=displayName+eq+\''		\
																					+	super().CoalesceEmptyNorNoneThenNone(strRevokedSecurityGroupName)		\
																					+	'\'&$search="displayName:'												\
																					+	super().CoalesceEmptyNorNoneThenNone(strRevokedSecurityGroupName)		\
																					+	'"'
													#
													HeadersV1					=	{
																							'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD['access_token'])
																						,	'Content-Type'					:		'application/json; charset=utf-8'
																						,	'ConsistencyLevel'				:		'eventual'
																					}
													#
													Response_listSGdetails_HttpGet	=	requests.get(														\
																											url				=	Get_listSGGroup_Url			\
																										,	headers			=	HeadersV1					\
																										,	timeout			=	TimeOutInSeconds			\
																									)
													#
													if	not	Response_listSGdetails_HttpGet is None:
														if		Response_listSGdetails_HttpGet.status_code >= int(200)	\
															and Response_listSGdetails_HttpGet.status_code <= int(299):
															if	super().CoalesceEmptyNorNoneThenNone(Response_listSGdetails_HttpGet.text)	!=	None:
																#
																sgFullDetails_AsJSONjson	=	json.loads(Response_listSGdetails_HttpGet.text)
																if		'@odata.context'	in	sgFullDetails_AsJSONjson	\
																	and	'value'				in	sgFullDetails_AsJSONjson:
																	if		len(list(filter(lambda x:'displayName'	in	x and 'id'	in	x, sgFullDetails_AsJSONjson['value'])))	==	1:
																		if	super().CoalesceEmptyNorNoneThenNone(str((sgFullDetails_AsJSONjson['value'][0])['displayName']))	!=	None:
																			if	re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(str((sgFullDetails_AsJSONjson['value'][0])['id'])))	!=	None:
																				guidSGidMatch	=	re.search(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(str((sgFullDetails_AsJSONjson['value'][0])['id'])))
																				if	len(guidSGidMatch.group(0))	==	36:
																					RevokedSecurityGroupId_AsGUID	=	guidSGidMatch.group(0)
																#
														else:
															super().HandleGLobalPostRequestError(																					\
																										_reason			=	Response_listSGdetails_HttpGet.reason				\
																									,	_status_code	=	int(Response_listSGdetails_HttpGet.status_code)		\
																									,	_text			=	Response_listSGdetails_HttpGet.text					\
																									,	_content		=	Response_listSGdetails_HttpGet.content				\
																								)
													#
												#
												# ••---------------------------------------------------------------------------------->
												#
												Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD = super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																											\
																																											_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																																										,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																																										,	_P12certBytes			=	ServiceApplicationP12bytes											\
																																										,	_P12certKy				=	ServiceAppP12Kbytes													\
																																										,	_ScopeAudienceDomain	=	str('https://graph.microsoft.com')									\
																																									)
												if		Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD					!=	None	\
													and	len(Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD)				>	0		\
													and	super().CoalesceEmptyNorNoneThenNone(RevokedSecurityGroupId_AsGUID)		!=	None:
													### ref : https://learn.microsoft.com/en-us/graph/api/user-list-memberof?view=graph-rest-1.0&tabs=http
													# url
													Get_memberOfVerification_Url	=		'https://graph.microsoft.com/v1.0/users/'			\
																						+	super().CoalesceEmptyNorNoneThenNone(UPNasGUID)		\
																						+	'/memberOf/'
													#
													HeadersV1					=	{
																							'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD['access_token'])
																						,	'Content-Type'					:		'application/json; charset=utf-8'
																					}
													#
													Response_memberOfVerification_HttpGet	=	requests.get(																	\
																													url				=	Get_memberOfVerification_Url			\
																												,	headers			=	HeadersV1								\
																												,	timeout			=	TimeOutInSeconds						\
																											)
													#
													if	not	Response_memberOfVerification_HttpGet is None:
														if		Response_memberOfVerification_HttpGet.status_code >= int(200)	\
															and Response_memberOfVerification_HttpGet.status_code <= int(299):
															if	super().CoalesceEmptyNorNoneThenNone(Response_memberOfVerification_HttpGet.text)	!=	None:
																#
																memberOf_Details_AsJSON		=	json.loads(super().CoalesceEmptyNorNoneThenNone(Response_memberOfVerification_HttpGet.text))
																#
																if		'value'				in	memberOf_Details_AsJSON		\
																	and	'@odata.context'	in	memberOf_Details_AsJSON:
																	if		len(list(filter(lambda x:'@odata.type'	in	x, memberOf_Details_AsJSON['value'])))	>	0:
																		for	currentOdataType	in	list(filter(lambda x:'@odata.type' in x, memberOf_Details_AsJSON['value'])):
																			if	super().fold_text(super().CoalesceEmptyNorNoneThenNone(str(currentOdataType['@odata.type'])))	==	super().fold_text('#microsoft.graph.group'):
																				if		'id'		in	currentOdataType:
																					if	re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(str(currentOdataType['id'])))	!=	None:
																						guidSGidMatch	=	re.search(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(str(currentOdataType['id'])))
																						if	len(guidSGidMatch.group(0))	==	36:
																							if	super().fold_text(super().CoalesceEmptyNorNoneThenNone(guidSGidMatch.group(0)))	==	super().CoalesceEmptyNorNoneThenNone(RevokedSecurityGroupId_AsGUID):
																								bCurrentUserExistsOnRevokedSG	=	True
																								break
																#
														else:
															super().HandleGLobalPostRequestError(																					\
																										_reason			=	Response_memberOfVerification_HttpGet.reason				\
																									,	_status_code	=	int(Response_memberOfVerification_HttpGet.status_code)		\
																									,	_text			=	Response_memberOfVerification_HttpGet.text					\
																									,	_content		=	Response_memberOfVerification_HttpGet.content				\
																								)
													#
												#
												# ••---------------------------------------------------------------------------------->
												#
												Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD = super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																											\
																																											_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																																										,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																																										,	_P12certBytes			=	ServiceApplicationP12bytes											\
																																										,	_P12certKy				=	ServiceAppP12Kbytes													\
																																										,	_ScopeAudienceDomain	=	str('https://graph.microsoft.com')									\
																																									)
												if		Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD					!=	None	\
													and	len(Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD)				>	0		\
													and	super().CoalesceEmptyNorNoneThenNone(RevokedSecurityGroupId_AsGUID)		!=	None	\
													and	bCurrentUserExistsOnRevokedSG	==	False:
													### ref : https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0&tabs=http
													# url
													Patch_updateGroupMemberOf_Url	=			'https://graph.microsoft.com/v1.0/groups/{groupId}/members/$ref'				\
																								.format(groupId = super().CoalesceEmptyNorNoneThenNone(RevokedSecurityGroupId_AsGUID))
													#
													Patch_updateGroupMemberOf_Body	=	{
																							'@odata.id'	:	'https://graph.microsoft.com/v1.0/users/{userId}'		\
																											.format(userId = super().CoalesceEmptyNorNoneThenNone(UPNasGUID))
																						}
													#
													HeadersV1					=	{
																							'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD['access_token'])
																						,	'Content-Type'					:		'application/json; charset=utf-8'
																					}
													#
													Response_updateGroupMemberOf_HttpPost	=	requests.post(																		\
																													url				=	Patch_updateGroupMemberOf_Url				\
																												,	json			=	Patch_updateGroupMemberOf_Body				\
																												,	data			=	json.dumps(Patch_updateGroupMemberOf_Body)	\
																												,	headers			=	HeadersV1									\
																												,	timeout			=	TimeOutInSeconds							\
																											)
													#
													if	not	Response_updateGroupMemberOf_HttpPost is None:
														if		Response_updateGroupMemberOf_HttpPost.status_code >= int(200)	\
															and Response_updateGroupMemberOf_HttpPost.status_code <= int(299):
															#
															newRowAsDict	=	{}
															newRowAsDict	=	{
																						'RemediationTypeName'			:	'ForceAddToRevokedSecurityGroup'
																					,	'ExecutionSuccessfulResult'		:	True
																					,	'RemediationCode'				:	Response_updateGroupMemberOf_HttpPost.status_code
																					,	'AzADUser_Id_AsGUID'			:	UPNasGUID
																					,	'UPN'							:	UPN
																				}
															returnActionsResultsAsPDF	=	pandas.concat([returnActionsResultsAsPDF, pandas.DataFrame([newRowAsDict])], ignore_index = True, verify_integrity = False, sort = False)
															#
															currentTry_ProcessResult	=	True
															break
															#
														else:
															super().HandleGLobalPostRequestError(																					\
																										_reason			=	Response_updateGroupMemberOf_HttpPost.reason				\
																									,	_status_code	=	int(Response_updateGroupMemberOf_HttpPost.status_code)		\
																									,	_text			=	Response_updateGroupMemberOf_HttpPost.text					\
																									,	_content		=	Response_updateGroupMemberOf_HttpPost.content				\
																								)
													#
												elif	super().CoalesceEmptyNorNoneThenNone(RevokedSecurityGroupId_AsGUID)		!=	None	\
													and	bCurrentUserExistsOnRevokedSG	==	True:
													### NO action needed, the user already member of the SG
													#
													currentTry_ProcessResult	=	True
													break
													#
												#
												# ••---------------------------------------------------------------------------------->
												#
											except requests.exceptions.HTTPError as httpEerr_:
												super().HandleGLobalException(httpEerr_)
											except requests.exceptions.ConnectionError as cnEerr_:
												super().HandleGLobalException(cnEerr_)
											except requests.exceptions.Timeout as toEerr_:
												super().HandleGLobalException(toEerr_)
											except requests.exceptions.RequestException as reqEx_:
												super().HandleGLobalException(reqEx_)
											except Exception as _exInst:
												super().HandleGLobalException(_exInst)
											#
											if	currentTry_ProcessResult	==	True:
												break
											else:
												time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
												continue
											#
										# end for currentTry
										#
									# end ForceAddToRevokedSecurityGroup == True
								#
								#
								# @xxxxxxxx][==============================================================>
								#
								if	'ForceRevokeAzADUserAllRefreshToken'	in	AzADUserRemediationActionsAsDict:
									if	bool(AzADUserRemediationActionsAsDict['ForceRevokeAzADUserAllRefreshToken'])	==	True:
										#
										for currentTry in range(super()._maxRetries):
										#
											#
											currentTry_ProcessResult	=	False
											#
											try:
												#
												bForceRevokeAzADUserAllRefreshToken_Result	=	False
												#
												# ••---------------------------------------------------------------------------------->
												#
												Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD = super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																											\
																																											_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																																										,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																																										,	_P12certBytes			=	ServiceApplicationP12bytes											\
																																										,	_P12certKy				=	ServiceAppP12Kbytes													\
																																										,	_ScopeAudienceDomain	=	str('https://graph.microsoft.com')									\
																																									)
												if		Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD			!=	None	\
													and	len(Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD)	>	0:
													## ref : https://learn.microsoft.com/en-us/graph/api/user-invalidateallrefreshtokens?view=graph-rest-beta&tabs=http&viewFallbackFrom=graph-rest-1.0
													# url
													Post_revokeResetSignInSessionsTokens_Url	=		'https://graph.microsoft.com/{apiVersion}/users/{userId}/invalidateAllRefreshTokens'	\
																										.format(apiVersion = 'beta', userId = super().CoalesceEmptyNorNoneThenNone(UPNasGUID))	### v1.0 | beta
													#
													HeadersV1					=	{
																							'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD['access_token'])
																						,	'Content-Type'					:		'application/json; charset=utf-8'
																					}
													#
													Response_revokeResetSignInSessionsTokens_HttpPost	=	requests.post(																		\
																																url				=	Post_revokeResetSignInSessionsTokens_Url				\
																															,	headers			=	HeadersV1								\
																															,	timeout			=	TimeOutInSeconds						\
																														)
													#
													if	not	Response_revokeResetSignInSessionsTokens_HttpPost is None:
														if		Response_revokeResetSignInSessionsTokens_HttpPost.status_code >= int(200)	\
															and Response_revokeResetSignInSessionsTokens_HttpPost.status_code <= int(299):
															#
															bForceRevokeAzADUserAllRefreshToken_Result	=	True
															#
															newRowAsDict	=	{}
															newRowAsDict	=	{
																						'RemediationTypeName'			:	'ForceRevokeAzADUserAllRefreshToken'
																					,	'ExecutionSuccessfulResult'		:	True
																					,	'RemediationCode'				:	Response_revokeResetSignInSessionsTokens_HttpPost.status_code
																					,	'AzADUser_Id_AsGUID'			:	UPNasGUID
																					,	'UPN'							:	UPN
																				}
															returnActionsResultsAsPDF	=	pandas.concat([returnActionsResultsAsPDF, pandas.DataFrame([newRowAsDict])], ignore_index = True, verify_integrity = False, sort = False)
															#
														else:
															super().HandleGLobalPostRequestError(																					\
																										_reason			=	Response_revokeResetSignInSessionsTokens_HttpPost.reason				\
																									,	_status_code	=	int(Response_revokeResetSignInSessionsTokens_HttpPost.status_code)		\
																									,	_text			=	Response_revokeResetSignInSessionsTokens_HttpPost.text					\
																									,	_content		=	Response_revokeResetSignInSessionsTokens_HttpPost.content				\
																								)
													#
												#
												# ••---------------------------------------------------------------------------------->
												#
												Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD = super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																											\
																																											_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																																										,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																																										,	_P12certBytes			=	ServiceApplicationP12bytes											\
																																										,	_P12certKy				=	ServiceAppP12Kbytes													\
																																										,	_ScopeAudienceDomain	=	str('https://graph.microsoft.com')									\
																																									)
												if		Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD			!=	None	\
													and	len(Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD)	>	0:
													## ref : https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0&tabs=http
													# url
													Post_revokeResetSignInSessionsTokens_Url	=		'https://graph.microsoft.com/v1.0/users/{userId}/revokeSignInSessions'		\
																										.format(userId = super().CoalesceEmptyNorNoneThenNone(UPNasGUID))
													#
													HeadersV1					=	{
																							'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD['access_token'])
																						,	'Content-Type'					:		'application/json; charset=utf-8'
																					}
													#
													Response_revokeResetSignInSessionsTokens_HttpPost	=	requests.post(																		\
																																url				=	Post_revokeResetSignInSessionsTokens_Url	\
																															,	headers			=	HeadersV1									\
																															,	timeout			=	TimeOutInSeconds							\
																														)
													#
													if	not	Response_revokeResetSignInSessionsTokens_HttpPost is None:
														if		Response_revokeResetSignInSessionsTokens_HttpPost.status_code >= int(200)	\
															and Response_revokeResetSignInSessionsTokens_HttpPost.status_code <= int(299):
															#
															newRowAsDict	=	{}
															newRowAsDict	=	{
																						'RemediationTypeName'			:	'ForceRevokeSignInSessions'
																					,	'ExecutionSuccessfulResult'		:	True
																					,	'RemediationCode'				:	Response_revokeResetSignInSessionsTokens_HttpPost.status_code
																					,	'AzADUser_Id_AsGUID'			:	UPNasGUID
																					,	'UPN'							:	UPN
																				}
															returnActionsResultsAsPDF	=	pandas.concat([returnActionsResultsAsPDF, pandas.DataFrame([newRowAsDict])], ignore_index = True, verify_integrity = False, sort = False)
															#
															if	bForceRevokeAzADUserAllRefreshToken_Result	==	True:
																currentTry_ProcessResult	=	True
																break
															#
														else:
															super().HandleGLobalPostRequestError(																					\
																										_reason			=	Response_revokeResetSignInSessionsTokens_HttpPost.reason				\
																									,	_status_code	=	int(Response_revokeResetSignInSessionsTokens_HttpPost.status_code)		\
																									,	_text			=	Response_revokeResetSignInSessionsTokens_HttpPost.text					\
																									,	_content		=	Response_revokeResetSignInSessionsTokens_HttpPost.content				\
																								)
													#
												#
												# ••---------------------------------------------------------------------------------->
												#
											except requests.exceptions.HTTPError as httpEerr_:
												super().HandleGLobalException(httpEerr_)
											except requests.exceptions.ConnectionError as cnEerr_:
												super().HandleGLobalException(cnEerr_)
											except requests.exceptions.Timeout as toEerr_:
												super().HandleGLobalException(toEerr_)
											except requests.exceptions.RequestException as reqEx_:
												super().HandleGLobalException(reqEx_)
											except Exception as _exInst:
												super().HandleGLobalException(_exInst)
											#
											if	currentTry_ProcessResult	==	True:
												break
											else:
												time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
												continue
											#
										# end for currentTry
										#
									# end ForceRevokeAzADUserAllRefreshToken == True
								#
								# @xxxxxxxx][==============================================================>
								#
								#
								# @xxxxxxxx][==============================================================>
								#
								#
								# @xxxxxxxx][==============================================================>
								#
								#
								# @xxxxxxxx][==============================================================>
								#
								#
								# @xxxxxxxx][==============================================================>
								#
		#
		return returnActionsResultsAsPDF
		#

	def DoJoinDataFrameWithAzGraphEnabledStatusForServiceAccounts(
																		self														\
																	,	TenantId:							str						\
																	,	ServiceApplicationId:				str						\
																	,	ServiceApplicationP12bytes:			bytes					\
																	,	ServiceAppP12Kbytes:				bytes					\
																	,	inputPandasDataFrame:				pandas.DataFrame	=	pandas.DataFrame(None).dropna()		\
																	,	_TimeOutInSeconds:					int					=	int(15)		\
																) -> pandas.DataFrame:
		##
		#	@brief Do Join Input-DataFrame with Az-Graph Enabled Status for Service Accounts
		#
		#	Keyword arguments:
		#	@param TenantId							--
		#	@param ServiceApplicationId				--
		#	@param ServiceApplicationP12bytes		--
		#	@param ServiceAppP12Kbytes				--
		#	@param inputPandasDataFrame				--
		#	@param _TimeOutInSeconds				--
		"""
		Do Join Input-DataFrame with Az-Graph Enabled Status for Service Accounts
		"""
		returnPandasDataFrame	=	pandas.DataFrame(None).dropna()
		#
		if			super().CoalesceEmptyNorNoneThenNone(TenantId)														!=	None		\
			and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(TenantId))				!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)											!=	None		\
			and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId))	!=	None		\
			and		len(ServiceApplicationP12bytes)																		>	0			\
			and		len(ServiceAppP12Kbytes)																			>	0			\
			and		inputPandasDataFrame.empty	!=	True:
			#
			if		inputPandasDataFrame.shape[0]	>	0	\
				and	inputPandasDataFrame.shape[1]	>	0:
				if	'SPN'	in	inputPandasDataFrame.columns:
					if	len(inputPandasDataFrame['SPN'].tolist())	>	0:
						listSPNs_AsList				=	inputPandasDataFrame['SPN'].tolist()
						listSPNs_AsListToConvert	=	[]
						#
						for	x in range(len(listSPNs_AsList)):
							verifiedSPN_appId_AsGUID		=	None
							#
							for currentTry in range(super()._maxRetries):
							#
								#
								currentTry_ProcessResult	=	False
								#
								try:
									#
									if	re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(listSPNs_AsList[x]))	!=	None:
										guidMatch	=	re.search(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(listSPNs_AsList[x]))
										if	len(guidMatch.group(0))	==	36:
											SPNasGUID					=	guidMatch.group(0)
											verifiedSPN_appId_AsGUID	=	SPNasGUID
									#
									else:
										SPN_AsString	=	super().CoalesceEmptyNorNoneThenNone(listSPNs_AsList[x])
										Graph_AAD_RestApiTokenRequest_SPNfullToken	=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																									\
																																							_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)		\
																																						,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)					\
																																						,	_P12certBytes			=	ServiceApplicationP12bytes										\
																																						,	_P12certKy				=	ServiceAppP12Kbytes												\
																																						,	_ScopeAudienceDomain	=	str('https://graph.microsoft.com')								\
																																					)
										if		Graph_AAD_RestApiTokenRequest_SPNfullToken			!=	None	\
											and	len(Graph_AAD_RestApiTokenRequest_SPNfullToken)	>	0:
											# url
											GetSPN_InfoUrl			=		'https://graph.microsoft.com/v1.0/applications?$filter=displayName%20eq%20%27'		\
																		+	super().CoalesceEmptyNorNoneThenNone(SPN_AsString)									\
																		+	'%27'																				\
											#
											HeadersV1				=	{
																				'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = Graph_AAD_RestApiTokenRequest_SPNfullToken['access_token'])
																			,	'Content-Type'					:		'application/json; charset=utf-8'
																			,	'accept'						:		'application/json, text/plain, */*'
																		}
											#
											SPN_InfoFromHttpPost	=	requests.get(													\
																							url				=	GetSPN_InfoUrl			\
																						,	headers			=	HeadersV1				\
																						,	timeout			=	_TimeOutInSeconds		\
																					)
											#
											if	not	SPN_InfoFromHttpPost is None:
												if		SPN_InfoFromHttpPost.status_code >= int(200)	\
													and	SPN_InfoFromHttpPost.status_code <= int(299):
													if	super().CoalesceEmptyNorNoneThenNone(SPN_InfoFromHttpPost.text)	!=	None:
														SPN_InfoFromHttpPostResponseText_AsJSON		=	json.loads(super().CoalesceEmptyNorNoneThenNone(SPN_InfoFromHttpPost.text))
														if		'value'					in	SPN_InfoFromHttpPostResponseText_AsJSON:
															if	len(SPN_InfoFromHttpPostResponseText_AsJSON['value'])	==	int(1):
																if		'appId'					in	((SPN_InfoFromHttpPostResponseText_AsJSON['value'][0])):
																	verifiedSPN_appId_AsGUID	=	super().CoalesceEmptyNorNoneThenNone((SPN_InfoFromHttpPostResponseText_AsJSON['value'][0])['appId'])
																else:
																	for currentApplicationIndex in range(len(SPN_InfoFromHttpPostResponseText_AsJSON['value'])):
																		filteredAppData	=	pandas.DataFrame(None).dropna()
																		filteredAppData	=	(inputPandasDataFrame	\
																									.where(		\
																												((inputPandasDataFrame)['SPN']).str.lower()	==	str(super().fold_text(super().CoalesceEmptyNorNoneThenNone(SPN_AsString)))	\
																											)	\
																									.dropna(how = 'all')).copy()
																		if		filteredAppData.empty		!=	bool(True)	\
																			and	filteredAppData.shape[0]	==	int(1):
																			if	['Id']	in	filteredAppData:
																				if	super().CoalesceEmptyNorNoneThenNone(str(filteredAppData.iloc[0]['Id']))	!=	None:
																					if	'appId'	in	(SPN_InfoFromHttpPostResponseText_AsJSON['value'][currentApplicationIndex]):
																						if	super().fold_text(super().CoalesceEmptyNorNoneThenNone((SPN_InfoFromHttpPostResponseText_AsJSON['value'][currentApplicationIndex])['appId']))	==	super().fold_text(super().CoalesceEmptyNorNoneThenNone(str(filteredAppData.iloc[0]['Id']))):
																							verifiedSPN_appId_AsGUID	=	super().CoalesceEmptyNorNoneThenNone((SPN_InfoFromHttpPostResponseText_AsJSON['value'][currentApplicationIndex])['appId'])
																							break
												else:
													super().HandleGLobalPostRequestError(																		\
																								_reason			=	SPN_InfoFromHttpPost.reason					\
																							,	_status_code	=	int(SPN_InfoFromHttpPost.status_code)		\
																							,	_text			=	SPN_InfoFromHttpPost.text					\
																							,	_content		=	SPN_InfoFromHttpPost.content				\
																						)
											#
									#
									if	super().CoalesceEmptyNorNoneThenNone(verifiedSPN_appId_AsGUID)	!=	None:
										if	re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(verifiedSPN_appId_AsGUID))	!=	None:
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											## let's gather current status for the service account
											guidMatch	=	re.search(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(verifiedSPN_appId_AsGUID))
											if	len(guidMatch.group(0))	==	36:
												CurrentSPN_appId_AsGUID		=	super().CoalesceEmptyNorNoneThenNone(guidMatch.group(0))
												Graph_AAD_RestApiTokenRequest_SPNfullToken	=	None
												Graph_AAD_RestApiTokenRequest_SPNfullToken	=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																									\
																																									_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)		\
																																								,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)					\
																																								,	_P12certBytes			=	ServiceApplicationP12bytes										\
																																								,	_P12certKy				=	ServiceAppP12Kbytes												\
																																								,	_ScopeAudienceDomain	=	str('https://graph.microsoft.com')								\
																																							)
												if		Graph_AAD_RestApiTokenRequest_SPNfullToken			!=	None	\
														and	len(Graph_AAD_RestApiTokenRequest_SPNfullToken)	>	0:
													# url
													GetSPN_InfoUrl			=		'https://graph.microsoft.com/v1.0/applications?$filter=appId%20eq%20%27'			\
																				+	super().CoalesceEmptyNorNoneThenNone(CurrentSPN_appId_AsGUID)						\
																				+	'%27&$select=id,appId,id,displayName,appRoles,keyCredentials,passwordCredentials'	\
													#
													HeadersV2				=	{
																						'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = Graph_AAD_RestApiTokenRequest_SPNfullToken['access_token'])
																					,	'Content-Type'					:		'application/json; charset=utf-8'
																					,	'accept'						:		'application/json, text/plain, */*'
																				}
													#
													acctInfo	=	None
													acctInfo	=	requests.get(													\
																						url				=	GetSPN_InfoUrl			\
																					,	headers			=	HeadersV2				\
																					,	timeout			=	_TimeOutInSeconds		\
																				)
													#
													currentSPN_IsEnabledStatusAsBool	=	bool(False)
													#
													if	not	acctInfo is None:
														if		acctInfo.status_code >= int(200)	\
															and	acctInfo.status_code <= int(299):
															if	super().CoalesceEmptyNorNoneThenNone(acctInfo.text)	!=	None:
																acctInfo_AsJSON		=	json.loads(super().CoalesceEmptyNorNoneThenNone(acctInfo.text))
																if		'value'		in	acctInfo_AsJSON:
																	if	len(acctInfo_AsJSON['value'])	==	int(1):
																		if		'id'			in	(acctInfo_AsJSON['value'][0])	\
																			and	'appId'			in	(acctInfo_AsJSON['value'][0])	\
																			and	'displayName'	in	(acctInfo_AsJSON['value'][0]):
																			if	super().fold_text(super().CoalesceEmptyNorNoneThenNone(CurrentSPN_appId_AsGUID))	== 	super().fold_text(super().CoalesceEmptyNorNoneThenNone((acctInfo_AsJSON['value'][0])['appId'])):
																				#
																				Graph_AAD_RestApiTokenRequest_SPNfullToken	=	None
																				Graph_AAD_RestApiTokenRequest_SPNfullToken	=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																									\
																																																	_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)		\
																																																,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)					\
																																																,	_P12certBytes			=	ServiceApplicationP12bytes										\
																																																,	_P12certKy				=	ServiceAppP12Kbytes												\
																																																,	_ScopeAudienceDomain	=	str('https://graph.microsoft.com')								\
																																															)
																				if		Graph_AAD_RestApiTokenRequest_SPNfullToken			!=	None	\
																						and	len(Graph_AAD_RestApiTokenRequest_SPNfullToken)	>	0:
																					# url
																					GetSPN_InfoUrl			=		'https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId%20eq%20%27'			\
																												+	super().CoalesceEmptyNorNoneThenNone(CurrentSPN_appId_AsGUID)							\
																												+	'%27&$select=id,accountEnabled,appDisplayName,appId,displayName,passwordCredentials'	\
																					#
																					HeadersV2				=	{
																														'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = Graph_AAD_RestApiTokenRequest_SPNfullToken['access_token'])
																													,	'Content-Type'					:		'application/json; charset=utf-8'
																													,	'accept'						:		'application/json, text/plain, */*'
																												}
																					#
																					acctInfo	=	None
																					acctInfo	=	requests.get(													\
																														url				=	GetSPN_InfoUrl			\
																													,	headers			=	HeadersV2				\
																													,	timeout			=	_TimeOutInSeconds		\
																												)
																					#
																					currentSPN_IsEnabledStatusAsBool	=	bool(False)
																					#
																					if	not	acctInfo is None:
																						if		acctInfo.status_code >= int(200)	\
																							and	acctInfo.status_code <= int(299):
																							if	super().CoalesceEmptyNorNoneThenNone(acctInfo.text)	!=	None:
																								serviceAcctInfo_AsJSON		=	json.loads(super().CoalesceEmptyNorNoneThenNone(acctInfo.text))
																								if	'value'	in	serviceAcctInfo_AsJSON:
																									if	len(serviceAcctInfo_AsJSON['value'])	==	int(1):
																										if		'id'				in	(serviceAcctInfo_AsJSON['value'][0])	\
																											and	'accountEnabled'	in	(serviceAcctInfo_AsJSON['value'][0])	\
																											and	'appDisplayName'	in	(serviceAcctInfo_AsJSON['value'][0])	\
																											and	'appId'				in	(serviceAcctInfo_AsJSON['value'][0])	\
																											and	'displayName'		in	(serviceAcctInfo_AsJSON['value'][0]):
																											if	super().fold_text(super().CoalesceEmptyNorNoneThenNone(CurrentSPN_appId_AsGUID))	== 	super().fold_text(super().CoalesceEmptyNorNoneThenNone((serviceAcctInfo_AsJSON['value'][0])['appId'])):
																												#
																												#
																												#
																												if	bool((serviceAcctInfo_AsJSON['value'][0])['accountEnabled'])	==	bool(True):
																													currentSPN_IsEnabledStatusAsBool	=	bool(True)
																												else:
																													currentSPN_IsEnabledStatusAsBool	=	bool(False)
																												#
																												#
																												listSPNs_AsListToConvert.append({			\
																																							'SPN'													:	super().CoalesceEmptyNorNoneThenNone(str((acctInfo_AsJSON['value'][0])['displayName']))		\
																																						,	'AzADServiceAccount_WasEnabled_PriorRemediation_AsBool'	:	currentSPN_IsEnabledStatusAsBool															\
																																						,	'AzADServiceAccount_Id_ObjectId'						:	super().CoalesceEmptyNorNoneThenNone(str((acctInfo_AsJSON['value'][0])['id']))				\
																																						,	'AzADServiceAccount_Id_appId'							:	super().CoalesceEmptyNorNoneThenNone(str((acctInfo_AsJSON['value'][0])['appId']))			\
																																				})
																												#
																												#
																												currentTry_ProcessResult	=	True
																												break
																												#
																												#
																												#
														else:
															#
															if	currentTry	>=	int(super()._maxRetries - 1):
																listSPNs_AsListToConvert.append({			\
																											'SPN'													:	super().CoalesceEmptyNorNoneThenNone(acctInfo_AsJSON['value']['appDisplayName'])	\
																										,	'AzADServiceAccount_WasEnabled_PriorRemediation_AsBool'	:	bool(False)																			\
																										,	'AzADServiceAccount_Id_ObjectId'						:	super().CoalesceEmptyNorNoneThenNone(str(acctInfo_AsJSON['value']['id']))			\
																										,	'AzADServiceAccount_Id_appId'							:	super().CoalesceEmptyNorNoneThenNone(str(acctInfo_AsJSON['value']['appId']))		\
																								})
															#
															super().HandleGLobalPostRequestError(															\
																										_reason			=	acctInfo.reason					\
																									,	_status_code	=	int(acctInfo.status_code)		\
																									,	_text			=	acctInfo.text					\
																									,	_content		=	acctInfo.content				\
																								)
															#
													#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
											#
								except requests.exceptions.HTTPError as httpEerr_:
									super().HandleGLobalException(httpEerr_)
								except requests.exceptions.ConnectionError as cnEerr_:
									super().HandleGLobalException(cnEerr_)
								except requests.exceptions.Timeout as toEerr_:
									super().HandleGLobalException(toEerr_)
								except requests.exceptions.RequestException as reqEx_:
									super().HandleGLobalException(reqEx_)
								except Exception as _exInst:
									super().HandleGLobalException(_exInst)
								#
								if	currentTry_ProcessResult	==	True:
									break
								else:
									time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
									continue
								#
							# end for currentTry
							#
						# end for range(len(listSPNs_AsList))
						#
						if	len(listSPNs_AsListToConvert)	==	len(listSPNs_AsList):
							returnPandasDataFrame	=	pandas.DataFrame(																				\
																				data	= listSPNs_AsListToConvert										\
																			,	columns	= [																\
																								'SPN'													\
																							,	'AzADServiceAccount_WasEnabled_PriorRemediation_AsBool'	\
																							,	'AzADServiceAccount_Id_ObjectId'						\
																							,	'AzADServiceAccount_Id_appId'							\
																							]															\
																		)
						#
		#
		return returnPandasDataFrame
		#

	def DoProcessAzADServicePrincipalRemediation(
														self																										\
													,	TenantId:										str															\
													,	ServiceApplicationId:							str															\
													,	ServiceApplicationP12bytes:						bytes														\
													,	ServiceAppP12Kbytes:							bytes														\
													,	AzADServicePrincipalRemediationActionsAsDict:	dict														\
													,	AzADServicePrincipalDetailsAsPandasDataFrame:	pandas.DataFrame	=	pandas.DataFrame(None).dropna()		\
													,	TimeOutInSeconds:								int					=	int(20)								\
													,	randomPasswordLength:							int					=	int(30)								\
												) -> pandas.DataFrame:
		##
		#	@brief Read from LogAnalytics, execute KQL Query
		#
		#	Keyword arguments:
		#	@param TenantId											--
		#	@param ServiceApplicationId								--
		#	@param ServiceApplicationP12bytes						--
		#	@param ServiceAppP12Kbytes								--
		#	@param AzADServicePrincipalRemediationActionsAsDict		--
		#	@param AzADServicePrincipalDetailsAsPandasDataFrame		--
		#	@param TimeOutInSeconds									--
		#	@param randomPasswordLength
		"""
		Do Process AzADServicePrincipal Remediation
		"""
		#
		returnActionsResultsAsPDF	=	pandas.DataFrame(None).dropna()
		returnActionsResultsAsPDF	=	pandas.DataFrame({	\
																c	:	pandas.Series(dtype=t)	for	c
															,	t	in	{	\
																				'RemediationTypeName'				:	numpy.dtype('U')		\
																			,	'ExecutionSuccessfulResult'			:	numpy.dtype('?')		\
																			,	'RemediationCode'					:	numpy.dtype('i')		\
																			,	'AzADServiceAccount_Id_appId'		:	numpy.dtype('U')		\
																			,	'SPN'								:	numpy.dtype('U')		\
																		}.items()	\
														})
		#
		if		AzADServicePrincipalDetailsAsPandasDataFrame.empty	!=	True	\
			and	len(AzADServicePrincipalRemediationActionsAsDict)	>	int(0):
			if		AzADServicePrincipalDetailsAsPandasDataFrame.shape[0]	>	0	\
				and	AzADServicePrincipalDetailsAsPandasDataFrame.shape[1]	>	0:
				if		'SPN'					in	AzADServicePrincipalDetailsAsPandasDataFrame.columns	\
					and	'AzADServiceAccount_Id_appId'	in	AzADServicePrincipalDetailsAsPandasDataFrame.columns:
					if		super().CoalesceEmptyNorNoneThenNone(AzADServicePrincipalDetailsAsPandasDataFrame['SPN'].iloc[0])	!=	None		\
						and	re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(AzADServicePrincipalDetailsAsPandasDataFrame['AzADServiceAccount_Id_appId'].iloc[0]))	!=	None	\
						and	super().CoalesceEmptyNorNoneThenNone(TenantId)														!=	None		\
						and	re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(TenantId))				!=	None		\
						and	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)											!=	None		\
						and	re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId))	!=	None		\
						and	len(ServiceApplicationP12bytes)																		>	0			\
						and	len(ServiceAppP12Kbytes)																			>	0:
						#
						guidSGidMatch	=	re.search(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(AzADServicePrincipalDetailsAsPandasDataFrame['AzADServiceAccount_Id_appId'].iloc[0]))
						if	len(guidSGidMatch.group(0))	==	36:
							#
							#
							SPNasGUID		=	guidSGidMatch.group(0)
							SPN				=	super().CoalesceEmptyNorNoneThenNone(AzADServicePrincipalDetailsAsPandasDataFrame['SPN'].iloc[0])
							randomizer		=	random.SystemRandom()
							#
							#
							# @xxxxxxxx][==============================================================>
							#
							if	'DisableAccountAsNewState'	in	AzADServicePrincipalRemediationActionsAsDict:
								if	bool(AzADServicePrincipalRemediationActionsAsDict['DisableAccountAsNewState'])	==	True:
									#
									for currentTry in range(super()._maxRetries):
									#
										#
										currentTry_ProcessResult	=	False
										#
										try:
											Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD	=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																								\
																																											_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)	\
																																										,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)				\
																																										,	_P12certBytes			=	ServiceApplicationP12bytes									\
																																										,	_P12certKy				=	ServiceAppP12Kbytes											\
																																										,	_ScopeAudienceDomain	=	str('https://graph.microsoft.com')							\
																																									)
											if		Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD			!=	None	\
												and	len(Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD)	>	0:
												#
												# ref : https://learn.microsoft.com/en-us/graph/api/serviceprincipal-update
												# url
												Patch_accountEnabled_Url	=		'https://graph.microsoft.com/v1.0/servicePrincipals%28appId%3D%27'		\
																				+	super().CoalesceEmptyNorNoneThenNone(SPNasGUID)							\
																				+	'%27%29'
												#
												Patch_accountEnabled_Body	=	{
																					'accountEnabled'	:	False
																				}
												#
												HeadersV1					=	{
																						'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD['access_token'])
																					,	'Content-Type'					:		'application/json; charset=utf-8'
																				}
												#
												Response_accountEnabled_HttpPatch	=	requests.patch(																		\
																												url				=	Patch_accountEnabled_Url				\
																											,	json			=	Patch_accountEnabled_Body				\
																											,	data			=	json.dumps(Patch_accountEnabled_Body)	\
																											,	headers			=	HeadersV1								\
																											,	timeout			=	TimeOutInSeconds						\
																										)
												#
												if	not	Response_accountEnabled_HttpPatch is None:
													### ref : https://developer.mozilla.org/en-US/docs/Web/HTTP/Status#successful_responses
													if		Response_accountEnabled_HttpPatch.status_code >= int(200)	\
														and Response_accountEnabled_HttpPatch.status_code <= int(299):
														#
														newRowAsDict	=	{}
														newRowAsDict	=	{
																					'RemediationTypeName'			:	'DisableAccountAsNewState'
																				,	'ExecutionSuccessfulResult'		:	True
																				,	'RemediationCode'				:	Response_accountEnabled_HttpPatch.status_code
																				,	'AzADServiceAccount_Id_appId'	:	SPNasGUID
																				,	'SPN'							:	SPN
																			}
														returnActionsResultsAsPDF	=	pandas.concat([returnActionsResultsAsPDF, pandas.DataFrame([newRowAsDict])], ignore_index = True, verify_integrity = False, sort = False)
														#
														currentTry_ProcessResult	=	True
														break
														#
													else:
														super().HandleGLobalPostRequestError(																					\
																									_reason			=	Response_accountEnabled_HttpPatch.reason				\
																								,	_status_code	=	int(Response_accountEnabled_HttpPatch.status_code)		\
																								,	_text			=	Response_accountEnabled_HttpPatch.text					\
																								,	_content		=	Response_accountEnabled_HttpPatch.content				\
																							)
												#
										except requests.exceptions.HTTPError as httpEerr_:
											super().HandleGLobalException(httpEerr_)
										except requests.exceptions.ConnectionError as cnEerr_:
											super().HandleGLobalException(cnEerr_)
										except requests.exceptions.Timeout as toEerr_:
											super().HandleGLobalException(toEerr_)
										except requests.exceptions.RequestException as reqEx_:
											super().HandleGLobalException(reqEx_)
										except Exception as _exInst:
											super().HandleGLobalException(_exInst)
										#
										if	currentTry_ProcessResult	==	True:
											break
										else:
											time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
											continue
										#
									# end for currentTry
									#
								# end DisableAccountAsNewState == True
							#
							# @xxxxxxxx][==============================================================>
							#
							#
							if	'RemoveAllSecrets'	in	AzADServicePrincipalRemediationActionsAsDict:
								if	bool(AzADServicePrincipalRemediationActionsAsDict['RemoveAllSecrets'])	==	True:
									#
									Response_AccountInfoDetails_AsJSON	=	None
									#
									for currentTry in range(super()._maxRetries):
									#
										#
										currentTry_ProcessResult	=	False
										#
										try:
											Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD	=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																								\
																																											_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)	\
																																										,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)				\
																																										,	_P12certBytes			=	ServiceApplicationP12bytes									\
																																										,	_P12certKy				=	ServiceAppP12Kbytes											\
																																										,	_ScopeAudienceDomain	=	str('https://graph.microsoft.com')							\
																																									)
											if		Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD			!=	None	\
												and	len(Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD)	>	0:
												#
												#
												# url
												Get_AccountInfoDetails_Url	=		'https://graph.microsoft.com/v1.0/applications?$filter=appId%20eq%20%27'	\
																				+	super().CoalesceEmptyNorNoneThenNone(SPNasGUID)								\
																				+	'%27&$select=id,appId,createdDateTime,displayName,appRoles,keyCredentials,passwordCredentials'
												#
												HeadersV1					=	{
																						'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD['access_token'])
																					,	'Content-Type'					:		'application/json; charset=utf-8'
																				}
												#
												Response_AccountInfoDetails_HttpGet	=	requests.get(															\
																											url				=	Get_AccountInfoDetails_Url		\
																										,	headers			=	HeadersV1						\
																										,	timeout			=	TimeOutInSeconds				\
																									)
												#
												if	not	Response_AccountInfoDetails_HttpGet is None:
													#
													if		Response_AccountInfoDetails_HttpGet.status_code >= int(200)	\
														and Response_AccountInfoDetails_HttpGet.status_code <= int(299):
														#
														if	super().CoalesceEmptyNorNoneThenNone(Response_AccountInfoDetails_HttpGet.text)	!=	None:
															#
															Response_AccountInfoDetails_AsJSON	=	json.loads(Response_AccountInfoDetails_HttpGet.text)
															#
															currentTry_ProcessResult	=	True
															break
															#
														#
													else:
														super().HandleGLobalPostRequestError(																					\
																									_reason			=	Response_AccountInfoDetails_HttpGet.reason				\
																								,	_status_code	=	int(Response_AccountInfoDetails_HttpGet.status_code)		\
																								,	_text			=	Response_AccountInfoDetails_HttpGet.text					\
																								,	_content		=	Response_AccountInfoDetails_HttpGet.content				\
																							)
												#
												#
										except requests.exceptions.HTTPError as httpEerr_:
											super().HandleGLobalException(httpEerr_)
										except requests.exceptions.ConnectionError as cnEerr_:
											super().HandleGLobalException(cnEerr_)
										except requests.exceptions.Timeout as toEerr_:
											super().HandleGLobalException(toEerr_)
										except requests.exceptions.RequestException as reqEx_:
											super().HandleGLobalException(reqEx_)
										except Exception as _exInst:
											super().HandleGLobalException(_exInst)
										#
										if	currentTry_ProcessResult	==	True:
											break
										else:
											time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
											continue
										#
									# end for currentTry
									#
									if	Response_AccountInfoDetails_AsJSON	!=	None:
										if	'value'	in	Response_AccountInfoDetails_AsJSON:
											if	len(Response_AccountInfoDetails_AsJSON['value'])	>	int(0):
												if		'appId'					in	(Response_AccountInfoDetails_AsJSON['value'])[0]	\
													and	'passwordCredentials'	in	(Response_AccountInfoDetails_AsJSON['value'])[0]:
														if		super().CoalesceEmptyNorNoneThenNone((Response_AccountInfoDetails_AsJSON['value'][0])['appId'])	!=	None	\
															and	len((Response_AccountInfoDetails_AsJSON['value'][0])['passwordCredentials'])					>	int(0):
															if	super().fold_text(super().CoalesceEmptyNorNoneThenNone((Response_AccountInfoDetails_AsJSON['value'][0])['appId']))	==	super().fold_text(super().CoalesceEmptyNorNoneThenNone(SPNasGUID)):
																#
																for currentIteration_passwordCredentials in range(len((Response_AccountInfoDetails_AsJSON['value'][0])['passwordCredentials'])):
																	#
																	#
																	#
																	if	'keyId'	in	((Response_AccountInfoDetails_AsJSON['value'][0])['passwordCredentials'])[currentIteration_passwordCredentials]:
																		#
																		if	super().CoalesceEmptyNorNoneThenNone((((Response_AccountInfoDetails_AsJSON['value'][0])['passwordCredentials'])[currentIteration_passwordCredentials])['keyId'])	!=	None:
																			#
																			_current_keyId_AsString		=	super().fold_text(super().CoalesceEmptyNorNoneThenNone((((Response_AccountInfoDetails_AsJSON['value'][0])['passwordCredentials'])[currentIteration_passwordCredentials])['keyId']))
																			#
																			for currentTry in range(super()._maxRetries):
																			#
																				#
																				currentTry_ProcessResult	=	False
																				#
																				try:
																					Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD	=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																								\
																																																					_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)	\
																																																				,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)				\
																																																				,	_P12certBytes			=	ServiceApplicationP12bytes									\
																																																				,	_P12certKy				=	ServiceAppP12Kbytes											\
																																																				,	_ScopeAudienceDomain	=	str('https://graph.microsoft.com')							\
																																																			)
																					if		Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD			!=	None	\
																						and	len(Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD)	>	0:
																						#
																						#
																						# ref : https://learn.microsoft.com/en-us/graph/api/application-removepassword?view=graph-rest-1.0&tabs=http
																						# url
																						Post_accountEnabled_Url	=		'https://graph.microsoft.com/v1.0/applications%28appId%3D%27'		\
																														+	super().CoalesceEmptyNorNoneThenNone(SPNasGUID)							\
																														+	'%27%29/removePassword'
																						#
																						Post_accountEnabled_Body	=	{
																															'keyId'	:	_current_keyId_AsString
																														}
																						#
																						HeadersV1					=	{
																																'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD['access_token'])
																															,	'Content-Type'					:		'application/json; charset=utf-8'
																														}
																						#
																						Response_accountEnabled_HttpPost	=	requests.post(																		\
																																						url				=	Post_accountEnabled_Url				\
																																					,	json			=	Post_accountEnabled_Body				\
																																					,	data			=	json.dumps(Post_accountEnabled_Body)	\
																																					,	headers			=	HeadersV1								\
																																					,	timeout			=	TimeOutInSeconds						\
																																				)
																						#
																						if	not	Response_accountEnabled_HttpPost is None:
																							#
																							if		Response_accountEnabled_HttpPost.status_code >= int(200)	\
																								and Response_accountEnabled_HttpPost.status_code <= int(299):
																								#
																								newRowAsDict	=	{}
																								newRowAsDict	=	{
																															'RemediationTypeName'			:	'RemoveAllSecrets'
																														,	'ExecutionSuccessfulResult'		:	True
																														,	'RemediationCode'				:	Response_accountEnabled_HttpPost.status_code
																														,	'AzADServiceAccount_Id_appId'	:	SPNasGUID
																														,	'SPN'							:	SPN
																													}
																								returnActionsResultsAsPDF	=	pandas.concat([returnActionsResultsAsPDF, pandas.DataFrame([newRowAsDict])], ignore_index = True, verify_integrity = False, sort = False)
																								#
																								currentTry_ProcessResult	=	True
																								break
																								#
																							else:
																								super().HandleGLobalPostRequestError(																					\
																																			_reason			=	Response_accountEnabled_HttpPost.reason				\
																																		,	_status_code	=	int(Response_accountEnabled_HttpPost.status_code)		\
																																		,	_text			=	Response_accountEnabled_HttpPost.text					\
																																		,	_content		=	Response_accountEnabled_HttpPost.content				\
																																	)
																						#
																						#
																				except requests.exceptions.HTTPError as httpEerr_:
																					super().HandleGLobalException(httpEerr_)
																				except requests.exceptions.ConnectionError as cnEerr_:
																					super().HandleGLobalException(cnEerr_)
																				except requests.exceptions.Timeout as toEerr_:
																					super().HandleGLobalException(toEerr_)
																				except requests.exceptions.RequestException as reqEx_:
																					super().HandleGLobalException(reqEx_)
																				except Exception as _exInst:
																					super().HandleGLobalException(_exInst)
																				#
																				if	currentTry_ProcessResult	==	True:
																					break
																				else:
																					time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
																					continue
																				#
																			# end for currentTry
																			#
																		#
																	#
																	#
																	#
																# end for currentIteration_passwordCredentials
																#
									#
								# end RemoveAllSecrets == True
							#
							#
							# @xxxxxxxx][==============================================================>
							#
							#
							# @xxxxxxxx][==============================================================>
							#
							#
							# @xxxxxxxx][==============================================================>
							#
							#
							# @xxxxxxxx][==============================================================>
							#
							if		'ForceAddToRevokedSecurityGroup'	in	AzADServicePrincipalRemediationActionsAsDict	\
								and	'RevokedSecurityGroupName'				in	AzADServicePrincipalRemediationActionsAsDict:
								if		bool(AzADServicePrincipalRemediationActionsAsDict['ForceAddToRevokedSecurityGroup'])	==	True	\
									and	super().CoalesceEmptyNorNoneThenNone(str(AzADServicePrincipalRemediationActionsAsDict['RevokedSecurityGroupName']))	!=	None:
									#
									for currentTry in range(super()._maxRetries):
									#
										#
										currentTry_ProcessResult	=	False
										memberOf_Details_AsJSON		=	{}
										#
										try:
											#
											bCurrentAccountExistsOnRevokedSG	=	False
											strRevokedSecurityGroupName			=	super().CoalesceEmptyNorNoneThenNone(str(AzADServicePrincipalRemediationActionsAsDict['RevokedSecurityGroupName']))
											RevokedSecurityGroupId_AsGUID		=	None
											#
											# ••---------------------------------------------------------------------------------->
											#
											Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD = super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																																										_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)		\
																																									,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)					\
																																									,	_P12certBytes			=	ServiceApplicationP12bytes										\
																																									,	_P12certKy				=	ServiceAppP12Kbytes												\
																																									,	_ScopeAudienceDomain	=	str('https://graph.microsoft.com')								\
																																								)
											if		Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD			!=	None	\
												and	len(Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD)	>	0:


												# ### ref : https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http#example-5-use-search-to-get-groups-with-display-names-that-contain-the-letters-video-or-a-description-that-contains-the-letters-prod-including-a-count-of-returned-objects
												# url
												Get_listSGGroup_Url	=				'https://graph.microsoft.com/v1.0/groups?$filter=displayName+eq+\''		\
																				+	super().CoalesceEmptyNorNoneThenNone(strRevokedSecurityGroupName)		\
																				+	'\'&$search="displayName:'												\
																				+	super().CoalesceEmptyNorNoneThenNone(strRevokedSecurityGroupName)		\
																				+	'"'
												#
												HeadersV1					=	{
																						'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD['access_token'])
																					,	'Content-Type'					:		'application/json; charset=utf-8'
																					,	'ConsistencyLevel'				:		'eventual'
																				}
												#
												Response_listSGdetails_HttpGet	=	requests.get(														\
																										url				=	Get_listSGGroup_Url			\
																									,	headers			=	HeadersV1					\
																									,	timeout			=	TimeOutInSeconds			\
																								)
												#
												if	not	Response_listSGdetails_HttpGet is None:
													if		Response_listSGdetails_HttpGet.status_code >= int(200)	\
														and Response_listSGdetails_HttpGet.status_code <= int(299):
														if	super().CoalesceEmptyNorNoneThenNone(Response_listSGdetails_HttpGet.text)	!=	None:
															#
															sgFullDetails_AsJSONjson	=	json.loads(Response_listSGdetails_HttpGet.text)
															if		'@odata.context'	in	sgFullDetails_AsJSONjson	\
																and	'value'				in	sgFullDetails_AsJSONjson:
																if		len(list(filter(lambda x:'displayName'	in	x and 'id'	in	x, sgFullDetails_AsJSONjson['value'])))	==	1:
																	if	super().CoalesceEmptyNorNoneThenNone(str((sgFullDetails_AsJSONjson['value'][0])['displayName']))	!=	None:
																		if	re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(str((sgFullDetails_AsJSONjson['value'][0])['id'])))	!=	None:
																			guidSGidMatch	=	re.search(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(str((sgFullDetails_AsJSONjson['value'][0])['id'])))
																			if	len(guidSGidMatch.group(0))	==	36:
																				RevokedSecurityGroupId_AsGUID	=	guidSGidMatch.group(0)
															#
													else:
														super().HandleGLobalPostRequestError(																					\
																									_reason			=	Response_listSGdetails_HttpGet.reason				\
																								,	_status_code	=	int(Response_listSGdetails_HttpGet.status_code)		\
																								,	_text			=	Response_listSGdetails_HttpGet.text					\
																								,	_content		=	Response_listSGdetails_HttpGet.content				\
																							)
												#
											#
											# ••---------------------------------------------------------------------------------->
											#
											Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD = super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																									\
																																										_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)	\
																																									,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)				\
																																									,	_P12certBytes			=	ServiceApplicationP12bytes									\
																																									,	_P12certKy				=	ServiceAppP12Kbytes											\
																																									,	_ScopeAudienceDomain	=	str('https://graph.microsoft.com')							\
																																								)
											if		Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD					!=	None	\
												and	len(Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD)				>	0		\
												and	super().CoalesceEmptyNorNoneThenNone(RevokedSecurityGroupId_AsGUID)		!=	None:
												#
												### ref : https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-memberof?view=graph-rest-1.0&tabs=http
												# url
												Get_memberOfVerification_Url	=		'https://graph.microsoft.com/v1.0/servicePrincipals(appId%3D%27'	\
																					+	super().CoalesceEmptyNorNoneThenNone(SPNasGUID)						\
																					+	'%27)/memberOf'
												#
												HeadersV1					=	{
																						'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD['access_token'])
																					,	'Content-Type'					:		'application/json; charset=utf-8'
																				}
												#
												Response_memberOfVerification_HttpGet	=	requests.get(																	\
																												url				=	Get_memberOfVerification_Url			\
																											,	headers			=	HeadersV1								\
																											,	timeout			=	TimeOutInSeconds						\
																										)
												#
												if	not	Response_memberOfVerification_HttpGet is None:
													if		Response_memberOfVerification_HttpGet.status_code >= int(200)	\
														and Response_memberOfVerification_HttpGet.status_code <= int(299):
														if	super().CoalesceEmptyNorNoneThenNone(Response_memberOfVerification_HttpGet.text)	!=	None:
															#
															memberOf_Details_AsJSON		=	json.loads(super().CoalesceEmptyNorNoneThenNone(Response_memberOfVerification_HttpGet.text))
															#
															if		'value'				in	memberOf_Details_AsJSON		\
																and	'@odata.context'	in	memberOf_Details_AsJSON:
																if		len(list(filter(lambda x:'@odata.type'	in	x, memberOf_Details_AsJSON['value'])))	>	0:
																	for	currentOdataType	in	list(filter(lambda x:'@odata.type' in x, memberOf_Details_AsJSON['value'])):
																		if	super().fold_text(super().CoalesceEmptyNorNoneThenNone(str(currentOdataType['@odata.type'])))	==	super().fold_text('#microsoft.graph.group'):
																			if		'id'		in	currentOdataType:
																				if	re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(str(currentOdataType['id'])))	!=	None:
																					guidSGidMatch	=	re.search(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(str(currentOdataType['id'])))
																					if	len(guidSGidMatch.group(0))	==	36:
																						if	super().fold_text(super().CoalesceEmptyNorNoneThenNone(guidSGidMatch.group(0)))	==	super().CoalesceEmptyNorNoneThenNone(RevokedSecurityGroupId_AsGUID):
																							bCurrentAccountExistsOnRevokedSG	=	True
																							break
															#
													else:
														super().HandleGLobalPostRequestError(																					\
																									_reason			=	Response_memberOfVerification_HttpGet.reason				\
																								,	_status_code	=	int(Response_memberOfVerification_HttpGet.status_code)		\
																								,	_text			=	Response_memberOfVerification_HttpGet.text					\
																								,	_content		=	Response_memberOfVerification_HttpGet.content				\
																							)
												#
											#
											# ••---------------------------------------------------------------------------------->
											#
											Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD = super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																									\
																																										_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)	\
																																									,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)				\
																																									,	_P12certBytes			=	ServiceApplicationP12bytes									\
																																									,	_P12certKy				=	ServiceAppP12Kbytes											\
																																									,	_ScopeAudienceDomain	=	str('https://graph.microsoft.com')							\
																																								)
											if		Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD					!=	None	\
												and	len(Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD)				>	0		\
												and	super().CoalesceEmptyNorNoneThenNone(RevokedSecurityGroupId_AsGUID)		!=	None	\
												and	bCurrentAccountExistsOnRevokedSG	==	False:
												#
												### ref : https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0&tabs=http
												# url
												Patch_updateGroupMemberOf_Url	=			'https://graph.microsoft.com/v1.0/groups/{groupId}/members/$ref'				\
																							.format(groupId = super().CoalesceEmptyNorNoneThenNone(RevokedSecurityGroupId_AsGUID))
												#
												Patch_updateGroupMemberOf_Body	=	{
																						'@odata.id'	:	'https://graph.microsoft.com/v1.0/servicePrincipals/{servicePrincipalId}'		\
																										.format(servicePrincipalId = super().CoalesceEmptyNorNoneThenNone(SPNasGUID))
																					}
												#
												Patch_updateGroupMemberOf_Body	=	{
																						'@odata.id'	:	'https://graph.microsoft.com/v1.0/servicePrincipals(appId%3D%27{servicePrincipalId}%27)'	\
																										.format(servicePrincipalId = super().CoalesceEmptyNorNoneThenNone(SPNasGUID))
																					}
												#
												HeadersV1					=	{
																						'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD['access_token'])
																					,	'Content-Type'					:		'application/json; charset=utf-8'
																				}
												#
												Response_updateGroupMemberOf_HttpPost	=	requests.post(																		\
																												url				=	Patch_updateGroupMemberOf_Url				\
																											,	json			=	Patch_updateGroupMemberOf_Body				\
																											,	data			=	json.dumps(Patch_updateGroupMemberOf_Body)	\
																											,	headers			=	HeadersV1									\
																											,	timeout			=	TimeOutInSeconds							\
																										)
												#
												if	not	Response_updateGroupMemberOf_HttpPost is None:
													if		Response_updateGroupMemberOf_HttpPost.status_code >= int(200)	\
														and Response_updateGroupMemberOf_HttpPost.status_code <= int(299):
														#
														newRowAsDict	=	{}
														newRowAsDict	=	{
																					'RemediationTypeName'			:	'ForceAddToRevokedSecurityGroup'
																				,	'ExecutionSuccessfulResult'		:	True
																				,	'RemediationCode'				:	Response_updateGroupMemberOf_HttpPost.status_code
																				,	'AzADServiceAccount_Id_appId'	:	SPNasGUID
																				,	'SPN'							:	SPN
																			}
														returnActionsResultsAsPDF	=	pandas.concat([returnActionsResultsAsPDF, pandas.DataFrame([newRowAsDict])], ignore_index = True, verify_integrity = False, sort = False)
														#
														currentTry_ProcessResult	=	True
														break
														#
													else:
														super().HandleGLobalPostRequestError(																					\
																									_reason			=	Response_updateGroupMemberOf_HttpPost.reason				\
																								,	_status_code	=	int(Response_updateGroupMemberOf_HttpPost.status_code)		\
																								,	_text			=	Response_updateGroupMemberOf_HttpPost.text					\
																								,	_content		=	Response_updateGroupMemberOf_HttpPost.content				\
																							)
												#
											elif	super().CoalesceEmptyNorNoneThenNone(RevokedSecurityGroupId_AsGUID)		!=	None	\
												and	bCurrentAccountExistsOnRevokedSG	==	True:
												### NO action needed, the user already member of the SG
												#
												currentTry_ProcessResult	=	True
												break
												#
											#
											# ••---------------------------------------------------------------------------------->
											#
										except requests.exceptions.HTTPError as httpEerr_:
											super().HandleGLobalException(httpEerr_)
										except requests.exceptions.ConnectionError as cnEerr_:
											super().HandleGLobalException(cnEerr_)
										except requests.exceptions.Timeout as toEerr_:
											super().HandleGLobalException(toEerr_)
										except requests.exceptions.RequestException as reqEx_:
											super().HandleGLobalException(reqEx_)
										except Exception as _exInst:
											super().HandleGLobalException(_exInst)
										#
										if	currentTry_ProcessResult	==	True:
											break
										else:
											time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
											continue
										#
									# end for currentTry
									#
								# end ForceAddToRevokedSecurityGroup == True
							#
							# @xxxxxxxx][==============================================================>
							#
							#
							# @xxxxxxxx][==============================================================>
							#
							#
							# @xxxxxxxx][==============================================================>
							#
							#
							# @xxxxxxxx][==============================================================>
							#
							#
							# @xxxxxxxx][==============================================================>
							#
							#
							# @xxxxxxxx][==============================================================>
							#
						#
		#
		return returnActionsResultsAsPDF
		#

	def DoGetAzADUserByUPNorUserName(
											self													\
										,	TenantId:							str					\
										,	ServiceApplicationId:				str					\
										,	ServiceApplicationP12bytes:			bytes				\
										,	ServiceAppP12Kbytes:				bytes				\
										,	UPNorUserNameAsString:				str					\
										,	TimeOutInSeconds:					int		=	int(20)
									) -> pandas.DataFrame:
		##
		#	@brief Do Process AzADUser Remediation
		#
		#	Keyword arguments:
		#	@param TenantId						--
		#	@param ServiceApplicationId			--
		#	@param ServiceApplicationP12bytes	--
		#	@param ServiceAppP12Kbytes			--
		#	@param UPNorUserNameAsString		--
		"""
		Do Get Az Active Directory User By UPN or UserName
		"""
		returnAzADUserInfoAsPDF		=	pandas.DataFrame(None).dropna()
		#
		if		super().CoalesceEmptyNorNoneThenNone(UPNorUserNameAsString)	!=	None:
			#
			for currentTry in range(super()._maxRetries):
			#
				#
				currentTry_ProcessResult	=	False
				#
				try:
					Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD = super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																											\
																																				_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																																			,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																																			,	_P12certBytes			=	ServiceApplicationP12bytes											\
																																			,	_P12certKy				=	ServiceAppP12Kbytes													\
																																			,	_ScopeAudienceDomain	=	str('https://graph.microsoft.com')									\
																																		)
					if		Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD			!=	None	\
						and	len(Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD)	>	0:
						#
						# url
						Get_accountInfo_Url	=		'https://graph.microsoft.com/v1.0/users?$select=userPrincipalName,mail,displayName,id,accountEnabled&$count=true&$top=500&$search=("userPrincipalName:'		\
												+	super().fold_text(super().CoalesceEmptyNorNoneThenNone(UPNorUserNameAsString))		\
												+	'@" OR "mail:'																		\
												+	super().fold_text(super().CoalesceEmptyNorNoneThenNone(UPNorUserNameAsString))		\
												+	'@")&$filter=startsWith(mail,%27'													\
												+	super().fold_text(super().CoalesceEmptyNorNoneThenNone(UPNorUserNameAsString))		\
												+	'@%27)'
						#
						HeadersV1					=	{
																'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = Graph_AAD_RestApiTokenRequest_SPNfullToken_UpdateAAD['access_token'])
															,	'Content-Type'					:		'application/json; charset=utf-8'
															,	'ConsistencyLevel'				:		'eventual'
														}
						#
						Response_accountInfo_HttpGet	=	requests.get(													\
																				url				=	Get_accountInfo_Url		\
																			,	headers			=	HeadersV1				\
																			,	timeout			=	TimeOutInSeconds		\
																		)
						#
						if	not	Response_accountInfo_HttpGet is None:
							#
							if		Response_accountInfo_HttpGet.status_code >= int(200)	\
								and Response_accountInfo_HttpGet.status_code <= int(299):
								#
								if	super().CoalesceEmptyNorNoneThenNone(Response_accountInfo_HttpGet.text)	!=	None:
									#
									returnAzADUserInfoAsJson	=	json.loads(super().CoalesceEmptyNorNoneThenNone(Response_accountInfo_HttpGet.text))
									#
									if	len(returnAzADUserInfoAsJson)	>	int(0):
										if	len(list(filter(lambda x: 'value' in x, returnAzADUserInfoAsJson)))	> int(0):
											#
											_currentUserInfo_AsRAW_DataFrame	=	pandas.DataFrame(None).dropna()
											_currentUserInfo_AsRAW_DataFrame	=	pandas.json_normalize(returnAzADUserInfoAsJson['value'])
											#
											if	_currentUserInfo_AsRAW_DataFrame.empty	!=	True:
												if	_currentUserInfo_AsRAW_DataFrame.shape[0]	>	int(0):
													returnAzADUserInfoAsPDF	=	_currentUserInfo_AsRAW_DataFrame.copy()
													del _currentUserInfo_AsRAW_DataFrame
											#
									#
								#																#
								if	returnAzADUserInfoAsPDF.empty	!=	True:
									#
									currentTry_ProcessResult	=	True
									break
									#
								#
							else:
								super().HandleGLobalPostRequestError(																					\
																			_reason			=	Response_accountInfo_HttpGet.reason				\
																		,	_status_code	=	int(Response_accountInfo_HttpGet.status_code)		\
																		,	_text			=	Response_accountInfo_HttpGet.text					\
																		,	_content		=	Response_accountInfo_HttpGet.content				\
																	)
						#
				except requests.exceptions.HTTPError as httpEerr_:
					super().HandleGLobalException(httpEerr_)
				except requests.exceptions.ConnectionError as cnEerr_:
					super().HandleGLobalException(cnEerr_)
				except requests.exceptions.Timeout as toEerr_:
					super().HandleGLobalException(toEerr_)
				except requests.exceptions.RequestException as reqEx_:
					super().HandleGLobalException(reqEx_)
				except Exception as _exInst:
					super().HandleGLobalException(_exInst)
				#
				if	currentTry_ProcessResult	==	True:
					break
				else:
					time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
					continue
				#
			#
			# end for currentTry
			#
			#
		#
		return returnAzADUserInfoAsPDF
		#

	# end class AzGraphHandler
	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •


# In[ ]:


class AzLogAnalyticsProcessor(Base):
	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •
	##
	# @brief	Protected Member Variables
	#
	_soarGlobalSettings = {}

	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •
	##
	# @brief	Public Member Variables
	#
	T							=	TypeVar('T')

	##
	# @brief	AzLogAnalyticsProcessor Constructor
	def __init__(self, soarGlobalSettings : dict):
		self._soarGlobalSettings = soarGlobalSettings
		super(AzLogAnalyticsProcessor, self).__init__(soarGlobalSettings = self._soarGlobalSettings)
		#

	def DoReadFromLogAnalytics(
									self																\
								,	TenantId:									str						\
								,	SubscriptionId:								str						\
								,	ServiceApplicationId:						str						\
								,	ServiceApplicationP12bytes:					bytes					\
								,	ServiceAppP12Kbytes:						bytes					\
								,	LogAnalytics_WorkspaceResourceGroupName:	str						\
								,	LogAnalytics_WorkspaceName:					str						\
								,	LogAnalytics_KQLQuery_AsString:				str						\
								,	_TimeOutInSeconds:							int		=	int(15)		\
								) -> pandas.DataFrame:
		##
		#	@brief Read from LogAnalytics, execute KQL Query
		#
		#	Keyword arguments:
		#	@param TenantId										--
		#	@param SubscriptionId								--
		#	@param ServiceApplicationId							--
		#	@param ServiceApplicationP12bytes					--
		#	@param ServiceAppP12Kbytes							--
		#	@param LogAnalytics_WorkspaceResourceGroupName		--
		#	@param LogAnalytics_WorkspaceName					--
		#	@param LogAnalytics_KQLQuery_AsString				--
		#	@param _TimeOutInSeconds							--
		"""
		Read from LogAnalytics, execute KQL Query
		"""
		returnPandasDataFrame	=	pandas.DataFrame(None).dropna()
		#
		if			super().CoalesceEmptyNorNoneThenNone(TenantId)														!=	None		\
			and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(TenantId))				!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(SubscriptionId)												!=	None		\
			and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(SubscriptionId))		!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)											!=	None		\
			and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId))	!=	None		\
			and		len(ServiceApplicationP12bytes)																		>	0			\
			and		len(ServiceAppP12Kbytes)																			>	0			\
			and		super().CoalesceEmptyNorNoneThenNone(LogAnalytics_WorkspaceResourceGroupName)						!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(LogAnalytics_WorkspaceName)									!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(LogAnalytics_KQLQuery_AsString)								!=	None:
			#
			LogAnalytics_WorkspaceId_AsString		=	None
			#
			for currentTry in range(super()._maxRetries):
			#
				#
				currentTry_ProcessResult	=	False
				#
				try:
					# let's try to gather LogAnalytics WorkspaceId
					LAtoken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																											_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																										,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																										,	_P12certBytes			=	ServiceApplicationP12bytes											\
																										,	_P12certKy				=	ServiceAppP12Kbytes													\
																										,	_ScopeAudienceDomain	=	str('https://management.azure.com/')								\
																									)
					if			LAtoken			!=	None	\
						and		len(LAtoken)	>	0:
						# url
						_AzManagementUrl	=			'https://management.azure.com/subscriptions/'									\
													+	super().CoalesceEmptyNorNoneThenNone(SubscriptionId)							\
													+	'/resourcegroups/'																\
													+	super().CoalesceEmptyNorNoneThenNone(LogAnalytics_WorkspaceResourceGroupName)	\
													+	'/providers/Microsoft.OperationalInsights/workspaces/'							\
													+	super().CoalesceEmptyNorNoneThenNone(LogAnalytics_WorkspaceName)				\
													+	'?api-version=2020-08-01'														\
						#
						# Use the self-generated JWT as Authorization
						_AzManagement_ByPost_TokenHeader		=	{
																			'Authorization'		:		'Bearer {TokenJWT}'.format(TokenJWT = LAtoken['access_token'])
																		,	'Content-Type'		:		'application/json; charset=utf-8'
																	}
						#
						_AzManagement_ByPost_Token_Response		=	requests.get(																	\
																						url				=	_AzManagementUrl						\
																					,	headers			=	_AzManagement_ByPost_TokenHeader		\
																					,	timeout			=	_TimeOutInSeconds						\
																				)
						#
						if	not	_AzManagement_ByPost_Token_Response is None:
							if		_AzManagement_ByPost_Token_Response.status_code >= int(200)	\
								and	_AzManagement_ByPost_Token_Response.status_code <= int(299):
								if	super().CoalesceEmptyNorNoneThenNone(_AzManagement_ByPost_Token_Response.text)	!=	None:
									azManagement_ByPost_Token_Response	=	json.loads(super().CoalesceEmptyNorNoneThenNone(_AzManagement_ByPost_Token_Response.text))
									if	'properties'	in	azManagement_ByPost_Token_Response:
										if	'customerId'	in	azManagement_ByPost_Token_Response['properties']:
											if			super().CoalesceEmptyNorNoneThenNone(azManagement_ByPost_Token_Response['properties']['customerId'])						!=	None					\
												and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(azManagement_ByPost_Token_Response['properties']['customerId']))	!=	None:
												LogAnalytics_WorkspaceId_AsString	=	super().CoalesceEmptyNorNoneThenNone(azManagement_ByPost_Token_Response['properties']['customerId'])
						#
				except requests.exceptions.HTTPError as httpEerr_:
					super().HandleGLobalException(httpEerr_)
				except requests.exceptions.ConnectionError as cnEerr_:
					super().HandleGLobalException(cnEerr_)
				except requests.exceptions.Timeout as toEerr_:
					super().HandleGLobalException(toEerr_)
				except requests.exceptions.RequestException as reqEx_:
					super().HandleGLobalException(reqEx_)
				except Exception as _exInst:
					super().HandleGLobalException(_exInst)
				#
				if			LogAnalytics_WorkspaceId_AsString	!=	None																				\
					and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(LogAnalytics_WorkspaceId_AsString))	!=	None:
					#
					try:
						# let's try to gather LogAnalytics WorkspaceId
						LAQKQLtoken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																													_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																												,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																												,	_P12certBytes			=	ServiceApplicationP12bytes											\
																												,	_P12certKy				=	ServiceAppP12Kbytes													\
																												,	_ScopeAudienceGUID		=	str('ca7f3f0b-7d91-482c-8e09-c5d840d0eac5')							\
																											)
						if			LAQKQLtoken			!=	None	\
							and		len(LAQKQLtoken)	>	0:
							# url
							_AzKQLqueryUrl	=				'https://api.loganalytics.io/v1/workspaces/'								\
														+	super().CoalesceEmptyNorNoneThenNone(LogAnalytics_WorkspaceId_AsString)		\
														+	'/query?timespan=P9999D'																	\
							#
							# Use the self-generated JWT as Authorization
							_AzKQLquery_ByPost_TokenHeader		=	{
																			'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = LAQKQLtoken['access_token'])
																		,	'Content-Type'					:		'application/json'
																		,	'access-control-allow-origin'	:		'*'
																		,	'accept'						:		'application/json, text/plain, */*'
																	}
							#######
							#######
							####### Carriage Return	(CR)			\r		U+000D		ref:	https://www.compart.com/en/unicode/U+000D
							####### End of Line (EOL, LF, NL)		\n		U+000A		ref:	https://www.compart.com/en/unicode/U+000A
							####### Tabulation						\t		U+0009		ref:	https://www.compart.com/en/unicode/U+0009
							####### Apostrophe						'		U+0027		ref:	https://www.compart.com/en/unicode/U+0027
							####### Quotation Mark					"		U+0022		ref:	https://www.compart.com/en/unicode/U+0022
							####### Solidus							/		U+002F		ref:	https://www.compart.com/en/unicode/U+002F
							####### Reverse Solidus					\		U+005C		ref:	https://www.compart.com/en/unicode/U+005C
							#######
							#######
							####### 	requests.post
							####### • data • json • files •
							####### • When Content-Type is	application/x-www-form-urlencoded,	use data=															[requests.post(url, data=json_obj)]
							####### • Whem Content-Type is	application/json,					either use json= or use data= and set the Content-Type yourself		[requests.post(url, data=jsonstr, headers={"Content-Type":"application/json"})]
							####### • When Content-Type is	multipart/form-data,				use files=															[requests.post(url, files=xxxx)]
							#######
							###### ## default values "maxRows":30001, "truncationMaxSize":67108864 (64MB)
							LogAnalytics_KQLQuery_AsJSON_DICT	=	{																													\
																			'query'					:		super().CoalesceEmptyNorNoneThenNone(LogAnalytics_KQLQuery_AsString)		\
																		,	'maxRows'				:		30001																		\
																		,	'options'				:																					\
																											{																			\
																												'truncationMaxSize'	:	67108864										\
																											}																			\
																		,	'workspaceFilters'		:		{																			\
																												'regions'				:	[]											\
																											}																			\
																	}
							#
							_AzKQLquery_ByPost_Token_Response	=	requests.post(																			\
																						url				=	_AzKQLqueryUrl									\
																					,	headers			=	_AzKQLquery_ByPost_TokenHeader					\
																					,	json			=	LogAnalytics_KQLQuery_AsJSON_DICT				\
																					,	data			=	json.dumps(LogAnalytics_KQLQuery_AsJSON_DICT)	\
																					,	timeout			=	_TimeOutInSeconds								\
																				)
							#
							if	not	_AzKQLquery_ByPost_Token_Response is None:
								if		_AzKQLquery_ByPost_Token_Response.status_code >= int(200)	\
									and	_AzKQLquery_ByPost_Token_Response.status_code <= int(299):
									if	super().CoalesceEmptyNorNoneThenNone(_AzKQLquery_ByPost_Token_Response.text)	!=	None:
										responseText_AsJSON							=	json.loads(super().CoalesceEmptyNorNoneThenNone(_AzKQLquery_ByPost_Token_Response.text))
										if	'tables'	in	responseText_AsJSON:
											responseTables_AsJSON					=	responseText_AsJSON['tables']
											loopCompletedResult						=	False
											for	x	in	range(len(responseTables_AsJSON)):
												if		'name'		in	responseTables_AsJSON[x]	\
													and	'columns'	in	responseTables_AsJSON[x]	\
													and	'rows'		in	responseTables_AsJSON[x]:
													#
													_pandasDataSet_AsRAW_DataFrame		=	pandas.DataFrame(None).dropna()
													_columnsList						=	responseTables_AsJSON[x]['columns']
													_rowsList							=	responseTables_AsJSON[x]['rows']
													#
													_pandasDataSet_AsRAW_DataFrame	=	super().ParseColumnsListAndRowsListToStronglyTypedPandasDataFrame(		\
																																								columnsList		=	_columnsList	\
																																							,	rowsList		=	_rowsList		\
																																						)
													#
													if	_pandasDataSet_AsRAW_DataFrame.empty	!=	True:
														returnPandasDataFrame	=	_pandasDataSet_AsRAW_DataFrame.copy()
														del _pandasDataSet_AsRAW_DataFrame
													#
													loopCompletedResult				=	True
													break
												else:
													continue
											if	loopCompletedResult		==	True:
												#
												currentTry_ProcessResult	=	True
												break
												#
								else:
									super().HandleGLobalPostRequestError(																					\
																				_reason			=	_AzKQLquery_ByPost_Token_Response.reason				\
																			,	_status_code	=	int(_AzKQLquery_ByPost_Token_Response.status_code)		\
																			,	_text			=	_AzKQLquery_ByPost_Token_Response.text					\
																			,	_content		=	_AzKQLquery_ByPost_Token_Response.content				\
																		)
							#
					except requests.exceptions.HTTPError as httpEerr_:
						super().HandleGLobalException(httpEerr_)
					except requests.exceptions.ConnectionError as cnEerr_:
						super().HandleGLobalException(cnEerr_)
					except requests.exceptions.Timeout as toEerr_:
						super().HandleGLobalException(toEerr_)
					except requests.exceptions.RequestException as reqEx_:
						super().HandleGLobalException(reqEx_)
					except Exception as _exInst:
						super().HandleGLobalException(_exInst)
					#
				#
				if	currentTry_ProcessResult	==	True:
					break
				else:
					time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
					continue
				#
			# end for currentTry
		#
		return returnPandasDataFrame
		#

	# end class AzLogAnalyticsProcessor
	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •


# In[ ]:


class AzManagementProcessor(Base):
	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •
	##
	# @brief	Protected Member Variables
	#
	_soarGlobalSettings = {}

	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •
	##
	# @brief	Public Member Variables
	#
	T							=	TypeVar('T')

	##
	# @brief	AzManagementProcessor Constructor
	def __init__(self, soarGlobalSettings : dict):
		self._soarGlobalSettings = soarGlobalSettings
		super(AzManagementProcessor, self).__init__(soarGlobalSettings = self._soarGlobalSettings)
		#

	def DoReadManagementResourceGraphExplorerQueryAPI(
																self														\
															,	TenantId:							str						\
															,	ServiceApplicationId:				str						\
															,	ServiceApplicationP12bytes:			bytes					\
															,	ServiceAppP12Kbytes:				bytes					\
															,	QueryAPI_Url:						str						\
															,	QueryAPI_HttpPostBody:				str						\
															,	QueryAPI_KQL_Query:					str						\
															,	_TimeOutInSeconds:					int		=	int(15)		\
														) -> pandas.DataFrame:
		##
		#	@brief Read from LogAnalytics, execute KQL Query
		#
		#	Keyword arguments:
		#	@param TenantId							--
		#	@param ServiceApplicationId				--
		#	@param ServiceApplicationP12bytes		--
		#	@param ServiceAppP12Kbytes				--
		#	@param QueryAPI_Url						--
		#	@param QueryAPI_HttpPostBody			--
		#	@param QueryAPI_KQL_Query				--
		#	@param _TimeOutInSeconds				--
		"""
		Read from Management Resource Graph Explorer Query API, execute KQL Query
		"""
		returnPandasDataFrame	=	pandas.DataFrame(None).dropna()
		#
		if			super().CoalesceEmptyNorNoneThenNone(TenantId)														!=	None		\
			and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(TenantId))				!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)											!=	None		\
			and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId))	!=	None		\
			and		len(ServiceApplicationP12bytes)																		>	0			\
			and		len(ServiceAppP12Kbytes)																			>	0			\
			and		super().CoalesceEmptyNorNoneThenNone(QueryAPI_Url)													!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(QueryAPI_HttpPostBody)											!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(QueryAPI_KQL_Query)											!=	None:
			#
			for currentTry in range(super()._maxRetries):
			#
				#
				currentTry_ProcessResult	=	False
				#
				try:
					# let's try to gather data through API
					_ManagementToken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																														_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																													,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																													,	_P12certBytes			=	ServiceApplicationP12bytes											\
																													,	_P12certKy				=	ServiceAppP12Kbytes													\
																													,	_ScopeAudienceDomain	=	str('https://management.core.windows.net/')							\
																												)
					if			_ManagementToken			!=	None	\
						and		len(_ManagementToken)	>	0:
						#
						# Use the self-generated JWT as Authorization
						_AzManagement_ByPost_TokenHeader		=	{
																			'Authorization'		:		'Bearer {TokenJWT}'.format(TokenJWT = _ManagementToken['access_token'])
																		,	'Content-Type'		:		'application/json; charset=utf-8'
																	}
						#
						# Use re.sub() to replace the escape sequences \r\n, \t, and " with their string representations \\r\\n, \\t, and \\"
						# re.sub() is more versatile for handling multiple, pattern-based substitutions in a string, allowing for more concise and maintainable code
						_httpPostBody	=	super().CoalesceEmptyNorNoneThenNone(QueryAPI_HttpPostBody).replace(																															\
																														'<<ReplaceWithKqlQuery>>'																							\
																														,	re.sub(		r'(\r\n)|(\t)|(")', lambda x: '\\r\\n' if x.group(1) else ('\\t' if x.group(2) else '\\"')			\
																																	,	super().CoalesceEmptyNorNoneThenNone(QueryAPI_KQL_Query))											\
																												)
						#
						### ### deprecated on 2023/09/18
						# # # # _httpPostBody	=	super().CoalesceEmptyNorNoneThenNone(QueryAPI_HttpPostBody).replace(																																	\
						# # # # 																								'<<ReplaceWithKqlQuery>>'																									\
						# # # # 																							,	super().CoalesceEmptyNorNoneThenNone(QueryAPI_KQL_Query).replace("\r\n",'\\r\\n').replace("\t",'\\t').replace('"','\\"')	\
						# # # # 																						)
						#
						_Json_Body_AsArray					=	json.loads(_httpPostBody)
						#
						_AzManagement_ByPost_ApiResponse	=	requests.post(																				\
																					url				=	super().CoalesceEmptyNorNoneThenNone(QueryAPI_Url)	\
																				,	json			=	_Json_Body_AsArray									\
																				,	data			=	json.dumps(_Json_Body_AsArray)						\
																				,	headers			=	_AzManagement_ByPost_TokenHeader					\
																				,	timeout			=	_TimeOutInSeconds									\
																			)
						#
						if	not	_AzManagement_ByPost_ApiResponse is None:
							if		_AzManagement_ByPost_ApiResponse.status_code >= int(200)	\
								and	_AzManagement_ByPost_ApiResponse.status_code <= int(299):
								if	super().CoalesceEmptyNorNoneThenNone(_AzManagement_ByPost_ApiResponse.text)	!=	None:
									#
									azManagement_ByPost_Response_AsJson	=	json.loads(super().CoalesceEmptyNorNoneThenNone(_AzManagement_ByPost_ApiResponse.text))
									#
									if	'responses'	in	azManagement_ByPost_Response_AsJson:
										if	len(azManagement_ByPost_Response_AsJson['responses'])	>	0:
											if	'content'	in	(azManagement_ByPost_Response_AsJson['responses'][0]):
												if	'data'	in	((azManagement_ByPost_Response_AsJson["responses"][0])["content"]):
													if			'columns'	in	(((azManagement_ByPost_Response_AsJson["responses"][0])["content"])["data"])	\
														and		'rows'		in	(((azManagement_ByPost_Response_AsJson["responses"][0])["content"])["data"]):
														#
														_pandasDataSet_AsRAW_DataFrame		=	pandas.DataFrame(None).dropna()
														_columnsList						=	(((azManagement_ByPost_Response_AsJson["responses"][0])["content"])["data"])["columns"]
														_rowsList							=	(((azManagement_ByPost_Response_AsJson["responses"][0])["content"])["data"])["rows"]
														#
														_pandasDataSet_AsRAW_DataFrame	=	super().ParseColumnsListAndRowsListToStronglyTypedPandasDataFrame(		\
																																									columnsList		=	_columnsList	\
																																								,	rowsList		=	_rowsList		\
																																							)
														#
														if	_pandasDataSet_AsRAW_DataFrame.empty	!=	True:
															returnPandasDataFrame		=	_pandasDataSet_AsRAW_DataFrame.copy()
															del	_pandasDataSet_AsRAW_DataFrame
														#
						#
						if	returnPandasDataFrame.empty	!=	True:
							#
							currentTry_ProcessResult	=	True
							break
							#
						#
				except requests.exceptions.HTTPError as httpEerr_:
					super().HandleGLobalException(httpEerr_)
				except requests.exceptions.ConnectionError as cnEerr_:
					super().HandleGLobalException(cnEerr_)
				except requests.exceptions.Timeout as toEerr_:
					super().HandleGLobalException(toEerr_)
				except requests.exceptions.RequestException as reqEx_:
					super().HandleGLobalException(reqEx_)
				except Exception as _exInst:
					super().HandleGLobalException(_exInst)
				#
				if	currentTry_ProcessResult	==	True:
					break
				else:
					time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
					continue
				#
			# end for currentTry
			#
		#
		return returnPandasDataFrame
		#

	def DoHttpGetRequestManagementAPI(
												self																	\
											,	TenantId:										str						\
											,	ServiceApplicationId:							str						\
											,	ServiceApplicationP12bytes:						bytes					\
											,	ServiceAppP12Kbytes:							bytes					\
											,	ResponseFlagColumnName:							str						\
											,	HttpGetAPI_Url:									str						\
											,	HttpGetAPI_ResponsePropertiesFlagColumnName:	str						\
											,	_TimeOutInSeconds:								int		=	int(15)		\
										) -> pandas.DataFrame:
		##
		#	@brief Read from LogAnalytics, execute KQL Query
		#
		#	Keyword arguments:
		#	@param TenantId											--
		#	@param ServiceApplicationId								--
		#	@param ServiceApplicationP12bytes						--
		#	@param ServiceAppP12Kbytes								--
		#	@param ResponseFlagColumnName							--
		#	@param HttpGetAPI_Url									--
		#	@param HttpGetAPI_ResponsePropertiesFlagColumnName		--
		#	@param _TimeOutInSeconds								--
		"""
		Read from Azure Management API, Execute HTTP-GET
		"""
		returnPandasDataFrame	=	pandas.DataFrame(None).dropna()
		#
		if			super().CoalesceEmptyNorNoneThenNone(TenantId)														!=	None		\
			and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(TenantId))				!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)											!=	None		\
			and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId))	!=	None		\
			and		len(ServiceApplicationP12bytes)																		>	0			\
			and		len(ServiceAppP12Kbytes)																			>	0			\
			and		super().CoalesceEmptyNorNoneThenNone(ResponseFlagColumnName)										!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(HttpGetAPI_Url)												!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(HttpGetAPI_ResponsePropertiesFlagColumnName)					!=	None:
			#
			for currentTry in range(super()._maxRetries):
			#
				#
				currentTry_ProcessResult	=	False
				#
				try:
					# let's try to gather data through API
					_ManagementToken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																														_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																													,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																													,	_P12certBytes			=	ServiceApplicationP12bytes											\
																													,	_P12certKy				=	ServiceAppP12Kbytes													\
																													,	_ScopeAudienceDomain	=	str('https://management.core.windows.net/')							\
																												)
					if			_ManagementToken			!=	None	\
						and		len(_ManagementToken)	>	0:
						#
						# Use the self-generated JWT as Authorization
						_AzManagement_ByPost_TokenHeader		=	{
																			'Authorization'		:		'Bearer {TokenJWT}'.format(TokenJWT = _ManagementToken['access_token'])
																		,	'Content-Type'		:		'application/json; charset=utf-8'
																	}
						#
						_AzManagement_ByPost_ApiResponse	=	requests.get(																					\
																					url				=	super().CoalesceEmptyNorNoneThenNone(HttpGetAPI_Url)	\
																				,	headers			=	_AzManagement_ByPost_TokenHeader						\
																				,	timeout			=	_TimeOutInSeconds										\
																			)
						#
						if	not	_AzManagement_ByPost_ApiResponse is None:
							if		_AzManagement_ByPost_ApiResponse.status_code >= int(200)	\
								and	_AzManagement_ByPost_ApiResponse.status_code <= int(299):
								if	super().CoalesceEmptyNorNoneThenNone(_AzManagement_ByPost_ApiResponse.text)	!=	None:
									#
									azManagement_ByPost_Response_AsJson	=	json.loads(super().CoalesceEmptyNorNoneThenNone(_AzManagement_ByPost_ApiResponse.text))
									#
									if	'properties'	in	azManagement_ByPost_Response_AsJson:
										if	len(azManagement_ByPost_Response_AsJson['properties'])	>	0:
											if	super().CoalesceEmptyNorNoneThenNone(HttpGetAPI_ResponsePropertiesFlagColumnName)	in	(azManagement_ByPost_Response_AsJson['properties']):
												#
												bTemporaryFlag	=	True
												#
												if	super().CoalesceEmptyNorNoneThenNone((azManagement_ByPost_Response_AsJson['properties'])[super().CoalesceEmptyNorNoneThenNone(HttpGetAPI_ResponsePropertiesFlagColumnName)])	!=	None	\
													or	(
															type((azManagement_ByPost_Response_AsJson['properties'])[super().CoalesceEmptyNorNoneThenNone(HttpGetAPI_ResponsePropertiesFlagColumnName)])	is	bool
														):
													#
													if		super().fold_text(super().CoalesceEmptyNorNoneThenNone((azManagement_ByPost_Response_AsJson['properties'])[super().CoalesceEmptyNorNoneThenNone(HttpGetAPI_ResponsePropertiesFlagColumnName)]))	==	super().fold_text('Disabled')	\
														or	super().fold_text(super().CoalesceEmptyNorNoneThenNone((azManagement_ByPost_Response_AsJson['properties'])[super().CoalesceEmptyNorNoneThenNone(HttpGetAPI_ResponsePropertiesFlagColumnName)]))	==	super().fold_text('False'):
														bTemporaryFlag	=	False
													elif	super().fold_text(super().CoalesceEmptyNorNoneThenNone((azManagement_ByPost_Response_AsJson['properties'])[super().CoalesceEmptyNorNoneThenNone(HttpGetAPI_ResponsePropertiesFlagColumnName)]))	==	super().fold_text('Enabled')	\
														or	super().fold_text(super().CoalesceEmptyNorNoneThenNone((azManagement_ByPost_Response_AsJson['properties'])[super().CoalesceEmptyNorNoneThenNone(HttpGetAPI_ResponsePropertiesFlagColumnName)]))	==	super().fold_text('True'):
														bTemporaryFlag	=	True
													elif	type((azManagement_ByPost_Response_AsJson['properties'])[super().CoalesceEmptyNorNoneThenNone(HttpGetAPI_ResponsePropertiesFlagColumnName)])	is	bool:
														bTemporaryFlag	=	((azManagement_ByPost_Response_AsJson['properties'])[super().CoalesceEmptyNorNoneThenNone(HttpGetAPI_ResponsePropertiesFlagColumnName)])
													#
												#
												srtId	=	None
												if	'id'	in	azManagement_ByPost_Response_AsJson:
													if	super().CoalesceEmptyNorNoneThenNone(azManagement_ByPost_Response_AsJson['id'])		!=	None:
														srtId	=	super().CoalesceEmptyNorNoneThenNone(azManagement_ByPost_Response_AsJson['id'])
												#
												srtType	=	None
												if	'type'	in	azManagement_ByPost_Response_AsJson:
													if	super().CoalesceEmptyNorNoneThenNone(azManagement_ByPost_Response_AsJson['type'])	!=	None:
														srtType	=	super().CoalesceEmptyNorNoneThenNone(azManagement_ByPost_Response_AsJson['type'])
												#
												tmpData					=	[[bTemporaryFlag, srtId, srtType]]
												returnPandasDataFrame	=	pandas.DataFrame(tmpData, columns=[super().CoalesceEmptyNorNoneThenNone(ResponseFlagColumnName), 'Id', 'Type'])
												#
						#
						if	returnPandasDataFrame.empty	!=	True:
							#
							currentTry_ProcessResult	=	True
							break
							#
						#
				except requests.exceptions.HTTPError as httpEerr_:
					super().HandleGLobalException(httpEerr_)
				except requests.exceptions.ConnectionError as cnEerr_:
					super().HandleGLobalException(cnEerr_)
				except requests.exceptions.Timeout as toEerr_:
					super().HandleGLobalException(toEerr_)
				except requests.exceptions.RequestException as reqEx_:
					super().HandleGLobalException(reqEx_)
				except Exception as _exInst:
					super().HandleGLobalException(_exInst)
				#
				if	currentTry_ProcessResult	==	True:
					break
				else:
					time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
					continue
				#
			# end for currentTry
			#
		#
		return returnPandasDataFrame
		#

	def DoHttpPutRemediationManagementAPI(
													self														\
												,	ResourceId:							str						\
												,	ResourceName:						str						\
												,	ResourceType:						str						\
												,	RemediationTypeName:				str						\
												,	TenantId:							str						\
												,	ServiceApplicationId:				str						\
												,	ServiceApplicationP12bytes:			bytes					\
												,	ServiceAppP12Kbytes:				bytes					\
												,	HttpPutManagementAPI_Url:			str						\
												,	HttpPutManagementAPI_HttpPutBody:	str						\
												,	_TimeOutInSeconds:					int		=	int(15)		\
											) -> pandas.DataFrame:
		##
		#	@brief Read from LogAnalytics, execute KQL Query
		#
		#	Keyword arguments:
		#	@param ResourceId							--
		#	@param ResourceName							--
		#	@param ResourceType							--
		#	@param RemediationTypeName					--
		#	@param TenantId								--
		#	@param ServiceApplicationId					--
		#	@param ServiceApplicationP12bytes			--
		#	@param ServiceAppP12Kbytes					--
		#	@param HttpPutManagementAPI_Url				--
		#	@param HttpPutManagementAPI_HttpPutBody		--
		#	@param _TimeOutInSeconds					--
		"""
		Read from Management Resource Graph Explorer Query API, execute KQL Query
		"""
		returnPandasDataFrame	=	pandas.DataFrame(None).dropna()
		returnPandasDataFrame	=	pandas.DataFrame({	\
															c	:	pandas.Series(dtype=t)	for	c
														,	t	in	{	\
																			'RemediationTypeName'		:	numpy.dtype('U')		\
																		,	'ExecutionSuccessfulResult'	:	numpy.dtype('?')		\
																		,	'RemediationCode'			:	numpy.dtype('i')		\
																		,	'id'						:	numpy.dtype('U')		\
																		,	'name'						:	numpy.dtype('U')		\
																		,	'type'						:	numpy.dtype('U')		\
																	}.items()	\
													})
		#
		if			super().CoalesceEmptyNorNoneThenNone(RemediationTypeName)											!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(ResourceId)													!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(TenantId)														!=	None		\
			and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(TenantId))				!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)											!=	None		\
			and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId))	!=	None		\
			and		len(ServiceApplicationP12bytes)																		>	0			\
			and		len(ServiceAppP12Kbytes)																			>	0			\
			and		super().CoalesceEmptyNorNoneThenNone(HttpPutManagementAPI_Url)													!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(HttpPutManagementAPI_HttpPutBody)											!=	None:
			#
			for currentTry in range(super()._maxRetries):
			#
				#
				currentTry_ProcessResult	=	False
				#
				try:
					# let's try to gather data through API
					_ManagementToken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																														_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																													,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																													,	_P12certBytes			=	ServiceApplicationP12bytes											\
																													,	_P12certKy				=	ServiceAppP12Kbytes													\
																													,	_ScopeAudienceDomain	=	str('https://management.core.windows.net/')							\
																												)
					if			_ManagementToken			!=	None	\
						and		len(_ManagementToken)	>	0:
						#
						# Use the self-generated JWT as Authorization
						_AzManagement_ByPost_TokenHeader		=	{
																			'Authorization'		:		'Bearer {TokenJWT}'.format(TokenJWT = _ManagementToken['access_token'])
																		,	'Content-Type'		:		'application/json; charset=utf-8'
																	}
						#
						_Json_Body_AsArray					=	json.loads(HttpPutManagementAPI_HttpPutBody)
						#
						_AzManagement_ByPost_ApiResponse	=	requests.put(																							\
																					url				=	super().CoalesceEmptyNorNoneThenNone(HttpPutManagementAPI_Url)	\
																				,	json			=	_Json_Body_AsArray												\
																				,	data			=	json.dumps(_Json_Body_AsArray)									\
																				,	headers			=	_AzManagement_ByPost_TokenHeader								\
																				,	timeout			=	_TimeOutInSeconds												\
																			)
						#
						if	not	_AzManagement_ByPost_ApiResponse is None:
							if		_AzManagement_ByPost_ApiResponse.status_code >= int(200)	\
								and _AzManagement_ByPost_ApiResponse.status_code <= int(299):
								if	super().CoalesceEmptyNorNoneThenNone(_AzManagement_ByPost_ApiResponse.text)	!=	None:
									#
									azManagement_ByPut_Response_AsJson					=	json.loads(super().CoalesceEmptyNorNoneThenNone(_AzManagement_ByPost_ApiResponse.text))
									azManagement_ByPut_Response_AsJson['status_code']	=	_AzManagement_ByPost_ApiResponse.status_code
									azManagement_ByPut_Response_AsJson['url']			=	_AzManagement_ByPost_ApiResponse.url
									### ### deprecated on 2023/09/21
									### returnPandasDataFrame								=	pandas.json_normalize(azManagement_ByPut_Response_AsJson)
									#
									newRowAsDict	=	{}
									newRowAsDict	=	{
																'RemediationTypeName'			:	super().CoalesceEmptyNorNoneThenNone(RemediationTypeName)
															,	'ExecutionSuccessfulResult'		:	True
															,	'RemediationCode'				:	_AzManagement_ByPost_ApiResponse.status_code
															,	'id'							:	super().CoalesceEmptyNorNoneThenNone(ResourceId)
															,	'name'							:	super().CoalesceEmptyNorNoneThenNone(ResourceName)
															,	'type'							:	super().CoalesceEmptyNorNoneThenNone(ResourceType)
														}
									returnPandasDataFrame	=	pandas.concat([returnPandasDataFrame, pandas.DataFrame([newRowAsDict])], ignore_index = True, verify_integrity = False, sort = False)
									#
						#
						if	returnPandasDataFrame.empty	!=	True:
							#
							currentTry_ProcessResult	=	True
							break
							#
						#
				except requests.exceptions.HTTPError as httpEerr_:
					super().HandleGLobalException(httpEerr_)
				except requests.exceptions.ConnectionError as cnEerr_:
					super().HandleGLobalException(cnEerr_)
				except requests.exceptions.Timeout as toEerr_:
					super().HandleGLobalException(toEerr_)
				except requests.exceptions.RequestException as reqEx_:
					super().HandleGLobalException(reqEx_)
				except Exception as _exInst:
					super().HandleGLobalException(_exInst)
				#
				if	currentTry_ProcessResult	==	True:
					break
				else:
					time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
					continue
				#
			# end for currentTry
			#
		#
		return returnPandasDataFrame
		#

	# end class AzManagementProcessor
	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •


# In[ ]:


class AzKustoDataExplorerClusterProcessor(Base):
	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •
	##
	# @brief	Protected Member Variables
	#
	_soarGlobalSettings = {}

	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •
	##
	# @brief	Public Member Variables
	#
	T							=	TypeVar('T')

	##
	# @brief	AzKustoDataExplorerClusterProcessor Constructor
	def __init__(self, soarGlobalSettings : dict):
		self._soarGlobalSettings = soarGlobalSettings
		super(AzKustoDataExplorerClusterProcessor, self).__init__(soarGlobalSettings = self._soarGlobalSettings)
		#

	def DoRunKQLqueryOnAzKustoDataExplorerClusterProcessorAPI(
																	self														\
																,	TenantId:							str						\
																,	ServiceApplicationId:				str						\
																,	ServiceApplicationP12bytes:			bytes					\
																,	ServiceAppP12Kbytes:				bytes					\
																,	QueryAPI_Url:						str						\
																,	QueryAPI_HttpPostBody:				str						\
																,	QueryAPI_KQL_Query:					str						\
																,	_TimeOutInSeconds:					int		=	int(180)	\
															) -> pandas.DataFrame:
		##
		#	@brief Read from LogAnalytics, execute KQL Query
		#
		#	Keyword arguments:
		#	@param TenantId							--
		#	@param ServiceApplicationId				--
		#	@param ServiceApplicationP12bytes		--
		#	@param ServiceAppP12Kbytes				--
		#	@param QueryAPI_Url						--
		#	@param QueryAPI_HttpPostBody			--
		#	@param QueryAPI_KQL_Query				--
		#	@param _TimeOutInSeconds				--
		"""
		Read from Management Resource Graph Explorer Query API, execute KQL Query
		"""
		returnPandasDataFrame	=	pandas.DataFrame(None).dropna()
		#
		if			super().CoalesceEmptyNorNoneThenNone(TenantId)														!=	None		\
			and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(TenantId))				!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)											!=	None		\
			and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId))	!=	None		\
			and		len(ServiceApplicationP12bytes)																		>	0			\
			and		len(ServiceAppP12Kbytes)																			>	0			\
			and		super().CoalesceEmptyNorNoneThenNone(QueryAPI_Url)													!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(QueryAPI_HttpPostBody)											!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(QueryAPI_KQL_Query)											!=	None:
			#
			for currentTry in range(super()._maxRetries):
			#
				#
				currentTry_ProcessResult	=	False
				#
				try:
					# let's try to gather data through API
					_AzKustoDataExplorerClusterToken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																																		_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																																	,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																																	,	_P12certBytes			=	ServiceApplicationP12bytes											\
																																	,	_P12certKy				=	ServiceAppP12Kbytes													\
																																	,	_ScopeAudienceDomain	=	str('https://help.kusto.windows.net')								\
																																)
					if			_AzKustoDataExplorerClusterToken		!=	None	\
						and		len(_AzKustoDataExplorerClusterToken)	>	0:
						#
						# Use the self-generated JWT as Authorization
						_AzKustoDataExplorerCluster_ByPost_TokenHeader		=	{
																						'Authorization'		:		'Bearer {TokenJWT}'.format(TokenJWT = _AzKustoDataExplorerClusterToken['access_token'])
																					,	'Content-Type'		:		'application/json; charset=utf-8'
																				}
						#
						# Use re.sub() to replace the escape sequences \r\n, \t, and " with their string representations \\r\\n, \\t, and \\"
						# re.sub() is more versatile for handling multiple, pattern-based substitutions in a string, allowing for more concise and maintainable code
						_httpPostBody	=	super().CoalesceEmptyNorNoneThenNone(QueryAPI_HttpPostBody).replace(																																\
																														'<<ReplaceWithKqlQuery>>'																								\
																														,	re.sub(		r'(\r\n)|(\t)|(")', lambda x: '\\r\\n' if x.group(1) else ('\\t' if x.group(2) else '\\"')				\
																																	,	super().CoalesceEmptyNorNoneThenNone(QueryAPI_KQL_Query))												\
																												)
						#
						### ### deprecated on 2023/09/18
						# # # # _httpPostBody	=	super().CoalesceEmptyNorNoneThenNone(QueryAPI_HttpPostBody).replace(																																	\
						# # # # 																								'<<ReplaceWithKqlQuery>>'																									\
						# # # # 																							,	super().CoalesceEmptyNorNoneThenNone(QueryAPI_KQL_Query).replace("\r\n",'\\r\\n').replace("\t",'\\t').replace('"','\\"')	\
						# # # # 																						)
						#
						_Json_Body_AsArray					=	json.loads(_httpPostBody)
						#
						_AzKustoDataExplorerCluster_ByPost_ApiResponse	=	requests.post(																				\
																								url				=	super().CoalesceEmptyNorNoneThenNone(QueryAPI_Url)	\
																							,	json			=	_Json_Body_AsArray									\
																							,	data			=	json.dumps(_Json_Body_AsArray)						\
																							,	headers			=	_AzKustoDataExplorerCluster_ByPost_TokenHeader		\
																							,	timeout			=	_TimeOutInSeconds									\
																						)
						#
						if	not	_AzKustoDataExplorerCluster_ByPost_ApiResponse is None:
							if		_AzKustoDataExplorerCluster_ByPost_ApiResponse.status_code >= int(200)	\
								and	_AzKustoDataExplorerCluster_ByPost_ApiResponse.status_code <= int(299):
								if	super().CoalesceEmptyNorNoneThenNone(_AzKustoDataExplorerCluster_ByPost_ApiResponse.text)	!=	None:
									#
									azKustoDataExplorerCluster_ByPost_Response_AsJson	=	json.loads(super().CoalesceEmptyNorNoneThenNone(_AzKustoDataExplorerCluster_ByPost_ApiResponse.text))
									#
									if	len(azKustoDataExplorerCluster_ByPost_Response_AsJson)	>	0:
										if	len(list(filter(lambda x: 'FrameType' in x and 'TableKind' in x and 'TableName' in x and 'Columns' in x and 'Rows' in x, azKustoDataExplorerCluster_ByPost_Response_AsJson)))	> int(0):
											if	len(list(filter(lambda x: x['FrameType'] == 'DataTable' and x['TableKind'] == 'PrimaryResult' and len(x['Columns']) > int(0) and len(x['Rows']) > int(0), azKustoDataExplorerCluster_ByPost_Response_AsJson)))	> int(0):
												_rawColumnsList		=	(list(filter(lambda x: x['FrameType'] == 'DataTable' and x['TableKind'] == 'PrimaryResult' and len(x['Columns']) > int(0) and len(x['Rows']) > int(0), azKustoDataExplorerCluster_ByPost_Response_AsJson)))[0]['Columns']
												_columnsList		=	[]
												[_columnsList.append({'name':item['ColumnName'],'type':item['ColumnType']}) for item in _rawColumnsList]
												_rowsList		=	(list(filter(lambda x: x['FrameType'] == 'DataTable' and x['TableKind'] == 'PrimaryResult' and len(x['Columns']) > int(0) and len(x['Rows']) > int(0), azKustoDataExplorerCluster_ByPost_Response_AsJson)))[0]['Rows']
												#
												#
												#
												_pandasDataSet_AsRAW_DataFrame	=	pandas.DataFrame(None).dropna()
												#
												_pandasDataSet_AsRAW_DataFrame	=	super().ParseColumnsListAndRowsListToStronglyTypedPandasDataFrame(		\
																																							columnsList		=	_columnsList	\
																																						,	rowsList		=	_rowsList		\
																																					)
												#
												if	_pandasDataSet_AsRAW_DataFrame.empty	!=	True:
													returnPandasDataFrame	=	_pandasDataSet_AsRAW_DataFrame.copy()
													del _pandasDataSet_AsRAW_DataFrame
												#
												#
												#
						#
						if	returnPandasDataFrame.empty	!=	True:
							#
							currentTry_ProcessResult	=	True
							break
							#
						#
				except requests.exceptions.HTTPError as httpEerr_:
					super().HandleGLobalException(httpEerr_)
				except requests.exceptions.ConnectionError as cnEerr_:
					super().HandleGLobalException(cnEerr_)
				except requests.exceptions.Timeout as toEerr_:
					super().HandleGLobalException(toEerr_)
				except requests.exceptions.RequestException as reqEx_:
					super().HandleGLobalException(reqEx_)
				except Exception as _exInst:
					super().HandleGLobalException(_exInst)
				#
				if	currentTry_ProcessResult	==	True:
					break
				else:
					time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
					continue
				#
			# end for currentTry
			#
		#
		return returnPandasDataFrame
		#

	def DoRunIngestInlineFromPDFintoAzKustoDataExplorerClusterByAPI(
																			self														\
																		,	TenantId:							str						\
																		,	ServiceApplicationId:				str						\
																		,	ServiceApplicationP12bytes:			bytes					\
																		,	ServiceAppP12Kbytes:				bytes					\
																		,	AzKustoDataExplorerCluster_Url:		str						\
																		,	TableName:							str						\
																		,	DBname:								str						\
																		,	PandasDataFrame:					pandas.DataFrame		\
																		,	_TimeOutInSeconds:					int		=	int(360)	\
																	) -> bool:
		##
		#	@brief Read from LogAnalytics, execute KQL Query
		#
		#	Keyword arguments:
		#	@param TenantId							--
		#	@param ServiceApplicationId				--
		#	@param ServiceApplicationP12bytes		--
		#	@param ServiceAppP12Kbytes				--
		#	@param AzKustoDataExplorerCluster_Url	--
		#	@param TableName						--
		#	@param DBname							--
		#	@param PandasDataFrame					--
		#	@param _TimeOutInSeconds				--
		"""
		Ingest Inline from Pandas DataFrame into Azure Kusto Data Explorer Cluster by API
		"""
		returnExecutionResult	=	False
		#
		if			super().CoalesceEmptyNorNoneThenNone(TenantId)														!=	None		\
			and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(TenantId))				!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)											!=	None		\
			and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId))	!=	None		\
			and		len(ServiceApplicationP12bytes)																		>	0			\
			and		len(ServiceAppP12Kbytes)																			>	0			\
			and		super().CoalesceEmptyNorNoneThenNone(AzKustoDataExplorerCluster_Url)								!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(TableName)														!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(DBname)														!=	None		\
			and		PandasDataFrame.empty																				!=	True:
			if	PandasDataFrame.shape[0]	>	int(0):
				#
				#
				#
				#
				#
				### let's send to create the table
				#
				for currentTry in range(super()._maxRetries):
				#
					#
					currentTry_ProcessResult	=	False
					#
					try:
						# let's try to gather data through API
						_AzKustoDataExplorerClusterToken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																																			_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																																		,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																																		,	_P12certBytes			=	ServiceApplicationP12bytes											\
																																		,	_P12certKy				=	ServiceAppP12Kbytes													\
																																		,	_ScopeAudienceDomain	=	str('https://help.kusto.windows.net')								\
																																	)
						if			_AzKustoDataExplorerClusterToken		!=	None	\
							and		len(_AzKustoDataExplorerClusterToken)	>	0:
							#
							# Use the self-generated JWT as Authorization
							_AzKustoDataExplorerCluster_ByPost_TokenHeader		=	{
																							'Authorization'		:		'Bearer {TokenJWT}'.format(TokenJWT = _AzKustoDataExplorerClusterToken['access_token'])
																						,	'Content-Type'		:		'application/json; charset=utf-8'
																					}
							#
							_Json_Body_AsArray	=	{
															'db'			: '{0}'.format(super().CoalesceEmptyNorNoneThenNone(DBname))
														,	'csl'			: '.create table {0}(NoExists:int32);'.format(super().CoalesceEmptyNorNoneThenNone(TableName))
														,	'properties'	:	{
																				'Options'		:	{
																											'query_language'			: 'csl'
																										,	'servertimeout'				: '01:00:00'
																										,	'queryconsistency'			: 'strongconsistency'
																										,	'request_readonly'			: False
																										,	'request_readonly_hardline'	: False
																									}
																				}
													}
							#
							_AzKustoDataExplorerCluster_ByPost_ApiResponse	=	requests.post(																				\
																									url				=	'{0}/v1/rest/mgmt'.format(super().CoalesceEmptyNorNoneThenNone(AzKustoDataExplorerCluster_Url))	\
																								,	json			=	_Json_Body_AsArray									\
																								,	data			=	json.dumps(_Json_Body_AsArray)						\
																								,	headers			=	_AzKustoDataExplorerCluster_ByPost_TokenHeader		\
																								,	timeout			=	_TimeOutInSeconds									\
																							)
							#
							if	not	_AzKustoDataExplorerCluster_ByPost_ApiResponse is None:
								if		_AzKustoDataExplorerCluster_ByPost_ApiResponse.status_code >= int(200)	\
									and	_AzKustoDataExplorerCluster_ByPost_ApiResponse.status_code <= int(299):
									if	super().CoalesceEmptyNorNoneThenNone(_AzKustoDataExplorerCluster_ByPost_ApiResponse.text)	!=	None:
										#
										azKustoDataExplorerCluster_ByPost_Response_AsJson	=	json.loads(super().CoalesceEmptyNorNoneThenNone(_AzKustoDataExplorerCluster_ByPost_ApiResponse.text))
										#
										if	len(azKustoDataExplorerCluster_ByPost_Response_AsJson)	>	0:
											if	len(list(filter(lambda x: 'Tables' in x, azKustoDataExplorerCluster_ByPost_Response_AsJson)))	> int(0):
												if	len(list(filter(lambda x: 'Rows' in x, azKustoDataExplorerCluster_ByPost_Response_AsJson['Tables'][0])))	> int(0):
													if	len(list(filter(lambda x: len(x) > int(0), azKustoDataExplorerCluster_ByPost_Response_AsJson['Tables'][0]['Rows'])))	> int(0):
														#
														currentTry_ProcessResult	=	True
														break
														#
							#
					except requests.exceptions.HTTPError as httpEerr_:
						super().HandleGLobalException(httpEerr_)
					except requests.exceptions.ConnectionError as cnEerr_:
						super().HandleGLobalException(cnEerr_)
					except requests.exceptions.Timeout as toEerr_:
						super().HandleGLobalException(toEerr_)
					except requests.exceptions.RequestException as reqEx_:
						super().HandleGLobalException(reqEx_)
					except Exception as _exInst:
						super().HandleGLobalException(_exInst)
					#
					if	currentTry_ProcessResult	==	True:
						break
					else:
						time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
						continue
					#
				# end for currentTry
				#
				#
				#
				#
				#
				### let's send to clear the table
				#
				for currentTry in range(super()._maxRetries):
				#
					#
					currentTry_ProcessResult	=	False
					#
					try:
						# let's try to gather data through API
						_AzKustoDataExplorerClusterToken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																																			_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																																		,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																																		,	_P12certBytes			=	ServiceApplicationP12bytes											\
																																		,	_P12certKy				=	ServiceAppP12Kbytes													\
																																		,	_ScopeAudienceDomain	=	str('https://help.kusto.windows.net')								\
																																	)
						if			_AzKustoDataExplorerClusterToken		!=	None	\
							and		len(_AzKustoDataExplorerClusterToken)	>	0:
							#
							# Use the self-generated JWT as Authorization
							_AzKustoDataExplorerCluster_ByPost_TokenHeader		=	{
																							'Authorization'		:		'Bearer {TokenJWT}'.format(TokenJWT = _AzKustoDataExplorerClusterToken['access_token'])
																						,	'Content-Type'		:		'application/json; charset=utf-8'
																					}
							#
							_Json_Body_AsArray	=	{
															'db'			: '{0}'.format(super().CoalesceEmptyNorNoneThenNone(DBname))
														,	'csl'			: '.clear table {0} data;'.format(super().CoalesceEmptyNorNoneThenNone(TableName))
														,	'properties'	:	{
																				'Options'		:	{
																											'query_language'			: 'csl'
																										,	'servertimeout'				: '01:00:00'
																										,	'queryconsistency'			: 'strongconsistency'
																										,	'request_readonly'			: False
																										,	'request_readonly_hardline'	: False
																									}
																				}
													}
							#
							_AzKustoDataExplorerCluster_ByPost_ApiResponse	=	requests.post(																				\
																									url				=	'{0}/v1/rest/mgmt'.format(super().CoalesceEmptyNorNoneThenNone(AzKustoDataExplorerCluster_Url))	\
																								,	json			=	_Json_Body_AsArray									\
																								,	data			=	json.dumps(_Json_Body_AsArray)						\
																								,	headers			=	_AzKustoDataExplorerCluster_ByPost_TokenHeader		\
																								,	timeout			=	_TimeOutInSeconds									\
																							)
							#
							if	not	_AzKustoDataExplorerCluster_ByPost_ApiResponse is None:
								if		_AzKustoDataExplorerCluster_ByPost_ApiResponse.status_code >= int(200)	\
									and	_AzKustoDataExplorerCluster_ByPost_ApiResponse.status_code <= int(299):
									if	super().CoalesceEmptyNorNoneThenNone(_AzKustoDataExplorerCluster_ByPost_ApiResponse.text)	!=	None:
										#
										azKustoDataExplorerCluster_ByPost_Response_AsJson	=	json.loads(super().CoalesceEmptyNorNoneThenNone(_AzKustoDataExplorerCluster_ByPost_ApiResponse.text))
										#
										if	len(azKustoDataExplorerCluster_ByPost_Response_AsJson)	>	0:
											if	len(list(filter(lambda x: 'Tables' in x, azKustoDataExplorerCluster_ByPost_Response_AsJson)))	> int(0):
												if	len(list(filter(lambda x: 'Rows' in x, azKustoDataExplorerCluster_ByPost_Response_AsJson['Tables'][0])))	> int(0):
													if	len(list(filter(lambda x: len(x) > int(0), azKustoDataExplorerCluster_ByPost_Response_AsJson['Tables'][0]['Rows'])))	> int(0):
														if	'Success' in list(filter(lambda x: len(x) > int(0), azKustoDataExplorerCluster_ByPost_Response_AsJson['Tables'][0]['Rows']))[0]:
															#
															currentTry_ProcessResult	=	True
															break
															#
							#
					except requests.exceptions.HTTPError as httpEerr_:
						super().HandleGLobalException(httpEerr_)
					except requests.exceptions.ConnectionError as cnEerr_:
						super().HandleGLobalException(cnEerr_)
					except requests.exceptions.Timeout as toEerr_:
						super().HandleGLobalException(toEerr_)
					except requests.exceptions.RequestException as reqEx_:
						super().HandleGLobalException(reqEx_)
					except Exception as _exInst:
						super().HandleGLobalException(_exInst)
					#
					if	currentTry_ProcessResult	==	True:
						break
					else:
						time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
						continue
					#
				# end for currentTry
				#
				#
				#
				#
				#
				### let's create the table structure
				#
				_allColumnsSeries	=	PandasDataFrame.columns.to_series()
				_allColumns_AsList	=	[]
				for	icC	in	range(len(_allColumnsSeries)):
					#
					_columnName	=	super().CoalesceEmptyNorNoneThenNone(_allColumnsSeries[icC])
					_columnType	=	None
					#
					### --------------------------------------
					###	Pandas/SQL				|	Kusto
					###	------------------------|-------------
					###	bool					|	bool
					###	datetime				|	datetime
					###	datetimeoffset[UTC]		|
					### datetimeoffset[ANY]		|
					### Json					|	dynamic
					### int						|	int
					### int64					|	long
					### float					|	real
					### object					|	string
					### uniqueidentifier		|	guid
					### --------------------------------------
					#
					# bool
					if		PandasDataFrame.dtypes[_columnName] is numpy.dtype('bool'):
						_columnType	=	'bool'
					# float
					elif		PandasDataFrame.dtypes[_columnName] is numpy.dtype('float64')	\
							or	PandasDataFrame.dtypes[_columnName] is numpy.dtype('float'):
						_columnType	=	'real'
					# int, int64
					elif	PandasDataFrame.dtypes[_columnName] is numpy.dtype('int64'):
						_columnType	=	'long'
					# varchar, nvarchar, uniqueidentifier, date, smalldatetime
					elif	PandasDataFrame.dtypes[_columnName] is numpy.dtype('object'):
						_columnType	=	'string'
					# datetime
					elif	PandasDataFrame.dtypes[_columnName] == numpy.dtype('<M8[ns]'):
						_columnType	=	'datetime'
					# datetimeoffset[UTC], datetimeoffset[ANY]
					elif	type(PandasDataFrame.dtypes[_columnName]) is pandas.core.dtypes.dtypes.DatetimeTZDtype:
						_columnType	=	'datetime'
					else:
						_columnType	=	'string'
					#
					_allColumns_AsList.append('{0}:{1}'.format(_columnName, _columnType))
					#
					### end for	icC	in	range(len(_allColumnsSeries))
				#
				_allColumnsCombinedString = ','.join(_allColumns_AsList)
				del	_allColumnsSeries
				del	_allColumns_AsList
				#
				### let's send to recreate the table structure
				#
				for currentTry in range(super()._maxRetries):
				#
					#
					currentTry_ProcessResult	=	False
					#
					try:
						# let's try to gather data through API
						_AzKustoDataExplorerClusterToken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																																			_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																																		,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																																		,	_P12certBytes			=	ServiceApplicationP12bytes											\
																																		,	_P12certKy				=	ServiceAppP12Kbytes													\
																																		,	_ScopeAudienceDomain	=	str('https://help.kusto.windows.net')								\
																																	)
						if			_AzKustoDataExplorerClusterToken		!=	None	\
							and		len(_AzKustoDataExplorerClusterToken)	>	0:
							#
							# Use the self-generated JWT as Authorization
							_AzKustoDataExplorerCluster_ByPost_TokenHeader		=	{
																							'Authorization'		:		'Bearer {TokenJWT}'.format(TokenJWT = _AzKustoDataExplorerClusterToken['access_token'])
																						,	'Content-Type'		:		'application/json; charset=utf-8'
																					}
							#
							_Json_Body_AsArray	=	{
															'db'			: '{0}'.format(super().CoalesceEmptyNorNoneThenNone(DBname))
														,	'csl'			: '.alter table {0} ({1});'.format(super().CoalesceEmptyNorNoneThenNone(TableName), super().CoalesceEmptyNorNoneThenNone(_allColumnsCombinedString))
														,	'properties'	:	{
																				'Options'		:	{
																											'query_language'			: 'csl'
																										,	'servertimeout'				: '01:00:00'
																										,	'queryconsistency'			: 'strongconsistency'
																										,	'request_readonly'			: False
																										,	'request_readonly_hardline'	: False
																									}
																				}
													}
							#
							_AzKustoDataExplorerCluster_ByPost_ApiResponse	=	requests.post(																				\
																									url				=	'{0}/v1/rest/mgmt'.format(super().CoalesceEmptyNorNoneThenNone(AzKustoDataExplorerCluster_Url))	\
																								,	json			=	_Json_Body_AsArray									\
																								,	data			=	json.dumps(_Json_Body_AsArray)						\
																								,	headers			=	_AzKustoDataExplorerCluster_ByPost_TokenHeader		\
																								,	timeout			=	_TimeOutInSeconds									\
																							)
							#
							if	not	_AzKustoDataExplorerCluster_ByPost_ApiResponse is None:
								if		_AzKustoDataExplorerCluster_ByPost_ApiResponse.status_code >= int(200)	\
									and	_AzKustoDataExplorerCluster_ByPost_ApiResponse.status_code <= int(299):
									if	super().CoalesceEmptyNorNoneThenNone(_AzKustoDataExplorerCluster_ByPost_ApiResponse.text)	!=	None:
										#
										azKustoDataExplorerCluster_ByPost_Response_AsJson	=	json.loads(super().CoalesceEmptyNorNoneThenNone(_AzKustoDataExplorerCluster_ByPost_ApiResponse.text))
										#
										if	len(azKustoDataExplorerCluster_ByPost_Response_AsJson)	>	0:
											if	len(list(filter(lambda x: 'Tables' in x, azKustoDataExplorerCluster_ByPost_Response_AsJson)))	> int(0):
												if	len(list(filter(lambda x: 'Rows' in x, azKustoDataExplorerCluster_ByPost_Response_AsJson['Tables'][0])))	> int(0):
													if	len(list(filter(lambda x: len(x) > int(0), azKustoDataExplorerCluster_ByPost_Response_AsJson['Tables'][0]['Rows'])))	> int(0):
														#
														currentTry_ProcessResult	=	True
														break
														#
							#
					except requests.exceptions.HTTPError as httpEerr_:
						super().HandleGLobalException(httpEerr_)
					except requests.exceptions.ConnectionError as cnEerr_:
						super().HandleGLobalException(cnEerr_)
					except requests.exceptions.Timeout as toEerr_:
						super().HandleGLobalException(toEerr_)
					except requests.exceptions.RequestException as reqEx_:
						super().HandleGLobalException(reqEx_)
					except Exception as _exInst:
						super().HandleGLobalException(_exInst)
					#
					if	currentTry_ProcessResult	==	True:
						break
					else:
						time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
						continue
					#
				# end for currentTry
				#
				#
				#
				#
				#
				### let's create the data structure
				_allColumnsSeries	=	PandasDataFrame.columns.to_series()
				_allRows_AsList		=	[]
				for	rRw	in	range(PandasDataFrame.shape[0]):
					#
					_currentRowValue_AsList	=	[]
					#
					for	cCl	in	range(PandasDataFrame.shape[1]):
						#
						_columnName	=	super().CoalesceEmptyNorNoneThenNone(_allColumnsSeries[cCl])
						#
						if		PandasDataFrame.dtypes[_columnName] is numpy.dtype('bool')		\
							or	PandasDataFrame.dtypes[_columnName] is numpy.dtype('float64')	\
							or	PandasDataFrame.dtypes[_columnName] is numpy.dtype('float')		\
							or	PandasDataFrame.dtypes[_columnName] is numpy.dtype('int64'):
							_currentRowValue_AsList.append('{0}'.format(PandasDataFrame.iloc[rRw][cCl]))
						elif	PandasDataFrame.dtypes[_columnName] is numpy.dtype('object'):
							if	super().CoalesceEmptyNorNoneThenNone(PandasDataFrame.iloc[rRw][cCl])	!=	None:
								_currentRowValue_AsList.append(('\"{0}\"'.format(super().CoalesceEmptyNorNoneThenNone(PandasDataFrame.iloc[rRw][cCl]))).replace('[','(').replace(']',')'))
							else:
								_currentRowValue_AsList.append('')
						elif	PandasDataFrame.dtypes[_columnName] == numpy.dtype('<M8[ns]'):
							if		PandasDataFrame.iloc[rRw][cCl] != None			\
								and	PandasDataFrame.iloc[rRw][cCl] != pandas.NaT	\
								and	PandasDataFrame.iloc[rRw][cCl] != numpy.NaN		\
								and len(str(PandasDataFrame.iloc[rRw][cCl])) > 8:
								_currentRowValue_AsList.append(('\"{0}\"'.format(str(PandasDataFrame.iloc[rRw][cCl].strftime('%Y-%m-%d %H:%M:%S.%f').rstrip('0')))))
							else:
								_currentRowValue_AsList.append('')
						elif	type(PandasDataFrame.dtypes[_columnName]) is pandas.core.dtypes.dtypes.DatetimeTZDtype:
							if		PandasDataFrame.iloc[rRw][cCl] != None			\
								and	PandasDataFrame.iloc[rRw][cCl] != pandas.NaT	\
								and	PandasDataFrame.iloc[rRw][cCl] != numpy.NaN		\
								and len(str(PandasDataFrame.iloc[rRw][cCl])) > 8:
								_currentRowValue_AsList.append(('\"{0}:00\"'.format(str(PandasDataFrame.iloc[rRw][cCl].strftime('%Y-%m-%d %H:%M:%S.%f %z')[:-2]))))
							else:
								_currentRowValue_AsList.append('')
						else:
							if	super().CoalesceEmptyNorNoneThenNone(PandasDataFrame.iloc[rRw][cCl])	!=	None:
								_currentRowValue_AsList.append(('\"{0}\"'.format(super().CoalesceEmptyNorNoneThenNone(PandasDataFrame.iloc[rRw][cCl]))).replace('[','(').replace(']',')'))
							else:
								_currentRowValue_AsList.append('')
						#
						#
						## end for cCl in range(PandasDataFrame.shape[1])
					#
					## enf for rRw in range(PandasDataFrame.shape[0])
					_currentRowValue_AsString	=	'[{0}]'.format((','.join(_currentRowValue_AsList)))
					_allRows_AsList.append(_currentRowValue_AsString)
					#
				#
				del _allColumnsSeries
				del _currentRowValue_AsList
				#
				_size	=	len(_allRows_AsList)
				_start	=	0
				_step	=	50
				#
				while	_start	<	_size:
					#
					_stop = _start + (_step - 1)
					#
					## let's work here
					#
					_subRowsSetment	=	_allRows_AsList[_start:_stop+1]
					#
					#
					#
					## •-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•
					#
					#
					#
					#
					#
					### let's ingest (insert) data into the table
					#
					for currentTry in range(super()._maxRetries):
					#
						#
						currentTry_ProcessResult	=	False
						#
						try:
							# let's try to gather data through API
							_AzKustoDataExplorerClusterToken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																																				_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																																			,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																																			,	_P12certBytes			=	ServiceApplicationP12bytes											\
																																			,	_P12certKy				=	ServiceAppP12Kbytes													\
																																			,	_ScopeAudienceDomain	=	str('https://help.kusto.windows.net')								\
																																		)
							if			_AzKustoDataExplorerClusterToken		!=	None	\
								and		len(_AzKustoDataExplorerClusterToken)	>	0:
								#
								# Use the self-generated JWT as Authorization
								_AzKustoDataExplorerCluster_ByPost_TokenHeader		=	{
																								'Authorization'		:		'Bearer {TokenJWT}'.format(TokenJWT = _AzKustoDataExplorerClusterToken['access_token'])
																							,	'Content-Type'		:		'application/json; charset=utf-8'
																						}
								#
								_rowsForIngestion_AsString	=	'\r\n\t'.join([str(i).strip() for i in _subRowsSetment])
								#
								_insertCommand	=	'.ingest inline into table {0}\r\n\t{1}'.format(super().CoalesceEmptyNorNoneThenNone(TableName), super().CoalesceEmptyNorNoneThenNone(_rowsForIngestion_AsString))
								#
								_Json_Body_AsArray	=	{
																'db'			: '{0}'.format(super().CoalesceEmptyNorNoneThenNone(DBname))
															,	'csl'			: '{0};'.format(super().CoalesceEmptyNorNoneThenNone(_insertCommand))
															,	'properties'	:	{
																					'Options'		:	{
																												'query_language'			: 'csl'
																											,	'servertimeout'				: '01:00:00'
																											,	'queryconsistency'			: 'strongconsistency'
																											,	'request_readonly'			: False
																											,	'request_readonly_hardline'	: False
																										}
																					}
														}
								#
								_AzKustoDataExplorerCluster_ByPost_ApiResponse	=	requests.post(																				\
																										url				=	'{0}/v1/rest/mgmt'.format(super().CoalesceEmptyNorNoneThenNone(AzKustoDataExplorerCluster_Url))	\
																									,	json			=	_Json_Body_AsArray									\
																									,	data			=	json.dumps(_Json_Body_AsArray)						\
																									,	headers			=	_AzKustoDataExplorerCluster_ByPost_TokenHeader		\
																									,	timeout			=	_TimeOutInSeconds									\
																								)
								#
								if	not	_AzKustoDataExplorerCluster_ByPost_ApiResponse is None:
									if		_AzKustoDataExplorerCluster_ByPost_ApiResponse.status_code >= int(200)	\
										and	_AzKustoDataExplorerCluster_ByPost_ApiResponse.status_code <= int(299):
										if	super().CoalesceEmptyNorNoneThenNone(_AzKustoDataExplorerCluster_ByPost_ApiResponse.text)	!=	None:
											#
											azKustoDataExplorerCluster_ByPost_Response_AsJson	=	json.loads(super().CoalesceEmptyNorNoneThenNone(_AzKustoDataExplorerCluster_ByPost_ApiResponse.text))
											#
											if	len(azKustoDataExplorerCluster_ByPost_Response_AsJson)	>	0:
												if	len(list(filter(lambda x: 'Tables' in x, azKustoDataExplorerCluster_ByPost_Response_AsJson)))	> int(0):
													if	len(list(filter(lambda x: 'Rows' in x, azKustoDataExplorerCluster_ByPost_Response_AsJson['Tables'][0])))	> int(0):
														if	len(list(filter(lambda x: len(x) > int(0), azKustoDataExplorerCluster_ByPost_Response_AsJson['Tables'][0]['Rows'])))	> int(0):
															#
															currentTry_ProcessResult	=	True
															break
															#
								#
						except requests.exceptions.HTTPError as httpEerr_:
							super().HandleGLobalException(httpEerr_)
						except requests.exceptions.ConnectionError as cnEerr_:
							super().HandleGLobalException(cnEerr_)
						except requests.exceptions.Timeout as toEerr_:
							super().HandleGLobalException(toEerr_)
						except requests.exceptions.RequestException as reqEx_:
							super().HandleGLobalException(reqEx_)
						except Exception as _exInst:
							super().HandleGLobalException(_exInst)
						#
						if	currentTry_ProcessResult	==	True:
							break
						else:
							time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
							continue
						#
					# end for currentTry
					#
					#
					#
					#
					#
					## •-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•-•
					#
					#
					#
					_start	=	_start	+	_step
					if	_start	>	_size:
						break
					#
				### end while _start < _size
				#
			#
		#
		return returnExecutionResult
		#

	# end class AzKustoDataExplorerClusterProcessor
	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •


# In[ ]:


class DefenderForEndpointsProcessor(Base):
	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •
	##
	# @brief	Protected Member Variables
	#
	_soarGlobalSettings = {}

	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •
	##
	# @brief	Public Member Variables
	#
	T							=	TypeVar('T')

	##
	# @brief	DefenderForEndpointsProcessor Constructor
	def __init__(self, soarGlobalSettings : dict):
		self._soarGlobalSettings = soarGlobalSettings
		super(DefenderForEndpointsProcessor, self).__init__(soarGlobalSettings = self._soarGlobalSettings)
		#

	def DoRunGetAlertsByQueryOnDefenderForEndpointsAPI(
															self																							\
														,	TenantId:							str															\
														,	ServiceApplicationId:				str															\
														,	ServiceApplicationP12bytes:			bytes														\
														,	ServiceAppP12Kbytes:				bytes														\
														,	WindowsDefenderHostAPIurl:			str															\
														,	QueryAPI_Url:						str															\
														,	ScopeAudienceDomain:				str		=	'https://api.securitycenter.microsoft.com/'		\
														,	_TimeOutInSeconds:					int		=	int(900)										\
													) -> pandas.DataFrame:
		##
		#	@brief Read from LogAnalytics, execute KQL Query
		#
		#	Keyword arguments:
		#	@param TenantId							--
		#	@param ServiceApplicationId				--
		#	@param ServiceApplicationP12bytes		--
		#	@param ServiceAppP12Kbytes				--
		#	@param ScopeAudienceDomain				--
		#	@param WindowsDefenderHostAPIurl		--
		#	@param QueryAPI_Url						--
		#	@param _TimeOutInSeconds				--
		"""
		Read from Management Resource Graph Explorer Query API, execute KQL Query
		"""
		returnPandasDataFrame	=	pandas.DataFrame(None).dropna()
		#
		if			super().CoalesceEmptyNorNoneThenNone(TenantId)														!=	None		\
			and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(TenantId))				!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)											!=	None		\
			and		re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId))	!=	None		\
			and		len(ServiceApplicationP12bytes)																		>	0			\
			and		len(ServiceAppP12Kbytes)																			>	0			\
			and		super().CoalesceEmptyNorNoneThenNone(ScopeAudienceDomain)											!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(WindowsDefenderHostAPIurl)										!=	None		\
			and		super().CoalesceEmptyNorNoneThenNone(QueryAPI_Url)													!=	None:
			#
			azAzGrapProcessorInstance		=	AzGraphHandler(self._soarGlobalSettings)
			_alertsDataSet_AsRAW_DataFrame	=	pandas.DataFrame(None).dropna()
			#
			# # # let's try retrieve ALL alerts from Defender for Endpoint API as RAW
			for currentTry in range(super()._maxRetries):
			#
				#
				currentTry_ProcessResult	=	False
				#
				try:
					# let's try to gather data through API
					_DefenderForEndpointsAPIToken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																																	_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																																,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																																,	_P12certBytes			=	ServiceApplicationP12bytes											\
																																,	_P12certKy				=	ServiceAppP12Kbytes													\
																																,	_ScopeAudienceDomain	=	super().CoalesceEmptyNorNoneThenNone(ScopeAudienceDomain)			\
																															)
					if			_DefenderForEndpointsAPIToken		!=	None	\
						and		len(_DefenderForEndpointsAPIToken)	>	0:
						#
						# Use the self-generated JWT as Authorization
						_DefenderForEndpointsAPI_ByGet_TokenHeader		=	{
																					'Authorization'		:		'Bearer {TokenJWT}'.format(TokenJWT = _DefenderForEndpointsAPIToken['access_token'])
																				,	'Content-Type'		:		'application/json; charset=utf-8'
																			}
						#
						_DefenderForEndpointsAPI_ByGet_ApiResponse	=	requests.get(																				\
																							url				=	super().CoalesceEmptyNorNoneThenNone(QueryAPI_Url)	\
																						,	headers			=	_DefenderForEndpointsAPI_ByGet_TokenHeader			\
																						,	timeout			=	_TimeOutInSeconds									\
																					)
						#
						if	not	_DefenderForEndpointsAPI_ByGet_ApiResponse is None:
							if		_DefenderForEndpointsAPI_ByGet_ApiResponse.status_code >= int(200)	\
								and _DefenderForEndpointsAPI_ByGet_ApiResponse.status_code <= int(299):
								#
								if	super().CoalesceEmptyNorNoneThenNone(_DefenderForEndpointsAPI_ByGet_ApiResponse.text)	!=	None:
									#
									defenderForEndpointsAlerts_ByGet_Response_AsJson	=	json.loads(super().CoalesceEmptyNorNoneThenNone(_DefenderForEndpointsAPI_ByGet_ApiResponse.text))
									#
									if	len(defenderForEndpointsAlerts_ByGet_Response_AsJson)	>	0:
										if	len(list(filter(lambda x: 'value' in x, defenderForEndpointsAlerts_ByGet_Response_AsJson)))	> int(0):
											#
											_pandasDataSet_AsRAW_DataFrame	=	pandas.DataFrame(None).dropna()
											_pandasDataSet_AsRAW_DataFrame	=	pandas.json_normalize(defenderForEndpointsAlerts_ByGet_Response_AsJson['value'])
											#
											# ref : https://www.geeksforgeeks.org/change-data-type-for-one-or-more-columns-in-pandas-dataframe/
											#
											if	'alertCreationTime'	in	_pandasDataSet_AsRAW_DataFrame:
												_pandasDataSet_AsRAW_DataFrame[['alertCreationTime']]	=	_pandasDataSet_AsRAW_DataFrame[['alertCreationTime']].apply(pandas.to_datetime)
											#
											if	'firstEventTime'	in	_pandasDataSet_AsRAW_DataFrame:
												_pandasDataSet_AsRAW_DataFrame[['firstEventTime']]	=	_pandasDataSet_AsRAW_DataFrame[['firstEventTime']].apply(pandas.to_datetime)
											#
											if	'lastEventTime'	in	_pandasDataSet_AsRAW_DataFrame:
												_pandasDataSet_AsRAW_DataFrame[['lastEventTime']]	=	_pandasDataSet_AsRAW_DataFrame[['lastEventTime']].apply(pandas.to_datetime)
											#
											if	'lastUpdateTime'	in	_pandasDataSet_AsRAW_DataFrame:
												_pandasDataSet_AsRAW_DataFrame[['lastUpdateTime']]	=	_pandasDataSet_AsRAW_DataFrame[['lastUpdateTime']].apply(pandas.to_datetime)
											#
											if	'resolvedTime'	in	_pandasDataSet_AsRAW_DataFrame:
												_pandasDataSet_AsRAW_DataFrame[['resolvedTime']]	=	_pandasDataSet_AsRAW_DataFrame[['resolvedTime']].apply(pandas.to_datetime)
											#
											if	_pandasDataSet_AsRAW_DataFrame.empty	!=	True:
												if	_pandasDataSet_AsRAW_DataFrame.shape[0]	>	int(0):
													_alertsDataSet_AsRAW_DataFrame	=	_pandasDataSet_AsRAW_DataFrame.copy()
													del _pandasDataSet_AsRAW_DataFrame
											#
									#
								#
						#
						if	_alertsDataSet_AsRAW_DataFrame.empty	!=	True:
							#
							currentTry_ProcessResult	=	True
							break
							#
						#
				except requests.exceptions.HTTPError as httpEerr_:
					super().HandleGLobalException(httpEerr_)
				except requests.exceptions.ConnectionError as cnEerr_:
					super().HandleGLobalException(cnEerr_)
				except requests.exceptions.Timeout as toEerr_:
					super().HandleGLobalException(toEerr_)
				except requests.exceptions.RequestException as reqEx_:
					super().HandleGLobalException(reqEx_)
				except Exception as _exInst:
					super().HandleGLobalException(_exInst)
				#
				if	currentTry_ProcessResult	==	True:
					break
				else:
					time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
					continue
				#
			# end for currentTry
			#
			# # # let's try to gather additional alert information, one by one
			if	_alertsDataSet_AsRAW_DataFrame.empty	!=	True:
				if	_alertsDataSet_AsRAW_DataFrame.shape[0]	>	int(0):
					#
					_tmpUsersDetailsAsPDF	=	pandas.DataFrame(None).dropna()
					_tmpUsersDetailsAsPDF	=	pandas.DataFrame({	\
																			c	:	pandas.Series(dtype=t)	for	c
																		,	t	in	{	\
																							'id'				:	numpy.dtype('U')		\
																						,	'machineId'			:	numpy.dtype('U')		\
																						,	'UPN'				:	numpy.dtype('U')		\
																						,	'displayName'		:	numpy.dtype('U')		\
																						,	'Id'				:	numpy.dtype('U')		\
																						,	'accountEnabled'	:	numpy.dtype('?')		\
																						,	'accountName'		:	numpy.dtype('U')		\
																						,	'accountDomain'		:	numpy.dtype('U')		\
																						,	'isDomainAdmin'		:	numpy.dtype('?')		\
																					}.items()	\
																	})
					#
					_tmpAlertsEvidencesGroupedListAsPDF		=	pandas.DataFrame(None).dropna()
					_tmpAlertsEvidencesGroupedListAsPDF		=	pandas.DataFrame({	\
																							c	:	pandas.Series(dtype=t)	for	c
																						,	t	in	{	\
																											'id'					:	'str'		\
																										,	'machineId'				:	'str'		\
																										,	'EvidenceCreationTime'	:	'str'		\
																										,	'UPN(s)'				:	'str'		\
																										,	'IP'					:	'str'		\
																										,	'Url'					:	'str'		\
																										,	'Process'				:	'str'		\
																										,	'File'					:	'str'		\
																										,	'Other'					:	'str'		\
																									}.items()	\
																					})
					#
					### let's start gathering info of users logued on computer during incident/alert
					for	r	in	range(_alertsDataSet_AsRAW_DataFrame.shape[0]):
						#
						_allAlertsDetails_AsPDF				=	pandas.DataFrame(None).dropna()
						_CurrentLogOnUsersList_AsPDF		=	pandas.DataFrame(None).dropna()
						_AccountUserPrincipalNameFromAPI	=	None
						#
						if		'id'				in	(_alertsDataSet_AsRAW_DataFrame.iloc[r])	\
							and	'computerDnsName'	in	(_alertsDataSet_AsRAW_DataFrame.iloc[r])	\
							and	'machineId'			in	(_alertsDataSet_AsRAW_DataFrame.iloc[r]):
							#
							if		super().CoalesceEmptyNorNoneThenNone((_alertsDataSet_AsRAW_DataFrame.iloc[r])['id'])				!=	None	\
								and	super().CoalesceEmptyNorNoneThenNone((_alertsDataSet_AsRAW_DataFrame.iloc[r])['computerDnsName'])	!=	None	\
								and	super().CoalesceEmptyNorNoneThenNone((_alertsDataSet_AsRAW_DataFrame.iloc[r])['machineId'])			!=	None:
								#
								_alertByIdURL	=	'{0}/api/alerts/{1}'.format(																								\
																						super().CoalesceEmptyNorNoneThenNone(WindowsDefenderHostAPIurl)							\
																					,	super().CoalesceEmptyNorNoneThenNone((_alertsDataSet_AsRAW_DataFrame.iloc[r])['id'])	\
																				)
								#
								for currentTry in range(super()._maxRetries):
								#
									#
									currentTry_ProcessResult	=	False
									#
									try:
										# let's try to gather data through API
										_DefenderForEndpointsAPIToken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																																						_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																																					,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																																					,	_P12certBytes			=	ServiceApplicationP12bytes											\
																																					,	_P12certKy				=	ServiceAppP12Kbytes													\
																																					,	_ScopeAudienceDomain	=	super().CoalesceEmptyNorNoneThenNone(ScopeAudienceDomain)			\
																																				)
										if		_DefenderForEndpointsAPIToken		!=	None	\
											and	len(_DefenderForEndpointsAPIToken)	>	0:
											#
											# Use the self-generated JWT as Authorization
											_DefenderForEndpointsAPI_ByGet_TokenHeader		=	{
																										'Authorization'		:		'Bearer {TokenJWT}'.format(TokenJWT = _DefenderForEndpointsAPIToken['access_token'])
																									,	'Content-Type'		:		'application/json; charset=utf-8'
																								}
											#
											_DefenderForEndpointsAPI_ByGet_ApiResponse	=	requests.get(																				\
																												url				=	super().CoalesceEmptyNorNoneThenNone(_alertByIdURL)	\
																											,	headers			=	_DefenderForEndpointsAPI_ByGet_TokenHeader			\
																											,	timeout			=	_TimeOutInSeconds									\
																										)
											#
											if	not	_DefenderForEndpointsAPI_ByGet_ApiResponse is None:
												if		_DefenderForEndpointsAPI_ByGet_ApiResponse.status_code >= int(200)	\
													and _DefenderForEndpointsAPI_ByGet_ApiResponse.status_code <= int(299):
													#
													if	super().CoalesceEmptyNorNoneThenNone(_DefenderForEndpointsAPI_ByGet_ApiResponse.text)	!=	None:
														#
														defenderForEndpointsAlerts_ByGet_Response_AsJson	=	json.loads(super().CoalesceEmptyNorNoneThenNone(_DefenderForEndpointsAPI_ByGet_ApiResponse.text))
														#
														if	len(defenderForEndpointsAlerts_ByGet_Response_AsJson)	>	int(0):
															if		'id'				in	defenderForEndpointsAlerts_ByGet_Response_AsJson	\
																and	'machineId'			in	defenderForEndpointsAlerts_ByGet_Response_AsJson	\
																and	'computerDnsName'	in	defenderForEndpointsAlerts_ByGet_Response_AsJson:
																#
																_alertsReadedDataSet_AsRAW_DataFrame	=	pandas.DataFrame(None).dropna()
																_alertsReadedDataSet_AsRAW_DataFrame	=	pandas.json_normalize(defenderForEndpointsAlerts_ByGet_Response_AsJson)
																#
																if	'alertCreationTime'	in	_alertsReadedDataSet_AsRAW_DataFrame:
																	_alertsReadedDataSet_AsRAW_DataFrame[['alertCreationTime']]	=	_alertsReadedDataSet_AsRAW_DataFrame[['alertCreationTime']].apply(pandas.to_datetime)
																#
																if	'firstEventTime'	in	_alertsReadedDataSet_AsRAW_DataFrame:
																	_alertsReadedDataSet_AsRAW_DataFrame[['firstEventTime']]	=	_alertsReadedDataSet_AsRAW_DataFrame[['firstEventTime']].apply(pandas.to_datetime)
																#
																if	'lastEventTime'	in	_alertsReadedDataSet_AsRAW_DataFrame:
																	_alertsReadedDataSet_AsRAW_DataFrame[['lastEventTime']]	=	_alertsReadedDataSet_AsRAW_DataFrame[['lastEventTime']].apply(pandas.to_datetime)
																#
																if	'lastUpdateTime'	in	_alertsReadedDataSet_AsRAW_DataFrame:
																	_alertsReadedDataSet_AsRAW_DataFrame[['lastUpdateTime']]	=	_alertsReadedDataSet_AsRAW_DataFrame[['lastUpdateTime']].apply(pandas.to_datetime)
																#
																if	'resolvedTime'	in	_alertsReadedDataSet_AsRAW_DataFrame:
																	_alertsReadedDataSet_AsRAW_DataFrame[['resolvedTime']]	=	_alertsReadedDataSet_AsRAW_DataFrame[['resolvedTime']].apply(pandas.to_datetime)
																#
																if	_alertsReadedDataSet_AsRAW_DataFrame.empty	!=	True:
																	if	_alertsReadedDataSet_AsRAW_DataFrame.shape[0]	>	int(0):
																		_allAlertsDetails_AsPDF		=	_alertsReadedDataSet_AsRAW_DataFrame.copy()
																		del _alertsReadedDataSet_AsRAW_DataFrame
																#
														#
													#
											#
											if	_allAlertsDetails_AsPDF.empty	!=	True:
												#
												currentTry_ProcessResult	=	True
												break
												#
											#
									except requests.exceptions.HTTPError as httpEerr_:
										super().HandleGLobalException(httpEerr_)
									except requests.exceptions.ConnectionError as cnEerr_:
										super().HandleGLobalException(cnEerr_)
									except requests.exceptions.Timeout as toEerr_:
										super().HandleGLobalException(toEerr_)
									except requests.exceptions.RequestException as reqEx_:
										super().HandleGLobalException(reqEx_)
									except Exception as _exInst:
										super().HandleGLobalException(_exInst)
									#
									if	currentTry_ProcessResult	==	True:
										break
									else:
										time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
										continue
									#
								# end for currentTry
								#
							#
						#
						if	_allAlertsDetails_AsPDF.empty	!=	True:
							if	_allAlertsDetails_AsPDF.shape[0]	>	int(0):
								#
								### let's start gathering logued users infi
								if		'loggedOnUsers'	in	_allAlertsDetails_AsPDF	\
									and	'machineId'		in	_allAlertsDetails_AsPDF	\
									and	'id'			in	_allAlertsDetails_AsPDF:
									#
									_loggedOnUsers_AsJson	=	json.loads((_allAlertsDetails_AsPDF['loggedOnUsers']).to_json(orient='records'))
									#
									if	len(_loggedOnUsers_AsJson)	>	int(0):
										#
										for	c1	in range(len(_loggedOnUsers_AsJson)):
											if	len(list(filter(lambda x: 'accountName' in x and 'domainName' in x, _loggedOnUsers_AsJson[c1])))	>	int(0):
												for	c2	in	range(len(list(filter(lambda x: 'accountName' in x and 'domainName' in x, _loggedOnUsers_AsJson[c1])))):
													#
													_currentAcctRecord	=	(list(filter(lambda x: 'accountName' in x and 'domainName' in x, _loggedOnUsers_AsJson[c1])))[c2]
													#
													#
													_logOnUserURL	=	'{0}/api/machines/{1}/logonusers'.format(																				\
																														super().CoalesceEmptyNorNoneThenNone(WindowsDefenderHostAPIurl)			\
																													,	super().CoalesceEmptyNorNoneThenNone(_allAlertsDetails_AsPDF.iloc[0]['machineId'])	\
																												)
													#
													for currentTry in range(super()._maxRetries):
													#
														#
														currentTry_ProcessResult	=	False
														#
														try:
															# let's try to gather data through API
															_DefenderForEndpointsAPIToken			=	super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																										\
																																											_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)			\
																																										,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)						\
																																										,	_P12certBytes			=	ServiceApplicationP12bytes											\
																																										,	_P12certKy				=	ServiceAppP12Kbytes													\
																																										,	_ScopeAudienceDomain	=	super().CoalesceEmptyNorNoneThenNone(ScopeAudienceDomain)			\
																																									)
															if		_DefenderForEndpointsAPIToken		!=	None	\
																and	len(_DefenderForEndpointsAPIToken)	>	0:
																#
																# Use the self-generated JWT as Authorization
																_DefenderForEndpointsAPI_ByGet_TokenHeader		=	{
																															'Authorization'		:		'Bearer {TokenJWT}'.format(TokenJWT = _DefenderForEndpointsAPIToken['access_token'])
																														,	'Content-Type'		:		'application/json; charset=utf-8'
																													}
																#
																_DefenderForEndpointsAPI_ByGet_ApiResponse	=	requests.get(																				\
																																	url				=	super().CoalesceEmptyNorNoneThenNone(_logOnUserURL)	\
																																,	headers			=	_DefenderForEndpointsAPI_ByGet_TokenHeader			\
																																,	timeout			=	_TimeOutInSeconds									\
																															)
																#
																if	not	_DefenderForEndpointsAPI_ByGet_ApiResponse is None:
																	if		_DefenderForEndpointsAPI_ByGet_ApiResponse.status_code >= int(200)	\
																		and _DefenderForEndpointsAPI_ByGet_ApiResponse.status_code <= int(299):
																		#
																		if	super().CoalesceEmptyNorNoneThenNone(_DefenderForEndpointsAPI_ByGet_ApiResponse.text)	!=	None:
																			#
																			defenderForEndpointsLogOnUser_ByGet_Response_AsJson	=	json.loads(super().CoalesceEmptyNorNoneThenNone(_DefenderForEndpointsAPI_ByGet_ApiResponse.text))
																			#
																			if	len(defenderForEndpointsLogOnUser_ByGet_Response_AsJson)	>	int(0):
																				if	len(list(filter(lambda x: 'value' in x, defenderForEndpointsLogOnUser_ByGet_Response_AsJson)))	> int(0):
																					#
																					_alertsReadedDataSet_AsRAW_DataFrame	=	pandas.DataFrame(None).dropna()
																					_alertsReadedDataSet_AsRAW_DataFrame	=	pandas.json_normalize(defenderForEndpointsLogOnUser_ByGet_Response_AsJson['value'])
																					#
																					if	_alertsReadedDataSet_AsRAW_DataFrame.empty	!=	True:
																						if	_alertsReadedDataSet_AsRAW_DataFrame.shape[0]	>	int(0):
																							_CurrentLogOnUsersList_AsPDF	=	_alertsReadedDataSet_AsRAW_DataFrame.copy()
																							del _alertsReadedDataSet_AsRAW_DataFrame
																					#
																			#
																		#
																#
																if	_CurrentLogOnUsersList_AsPDF.empty	!=	True:
																	#
																	currentTry_ProcessResult	=	True
																	break
																	#
																#
														except requests.exceptions.HTTPError as httpEerr_:
															super().HandleGLobalException(httpEerr_)
														except requests.exceptions.ConnectionError as cnEerr_:
															super().HandleGLobalException(cnEerr_)
														except requests.exceptions.Timeout as toEerr_:
															super().HandleGLobalException(toEerr_)
														except requests.exceptions.RequestException as reqEx_:
															super().HandleGLobalException(reqEx_)
														except Exception as _exInst:
															super().HandleGLobalException(_exInst)
														#
														if	currentTry_ProcessResult	==	True:
															break
														else:
															time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
															continue
														#
													# end for currentTry
													#
													#
													if	_CurrentLogOnUsersList_AsPDF.empty	!=	True:
														#
														if		'id'			in	_CurrentLogOnUsersList_AsPDF		\
															and	'accountName'	in	_CurrentLogOnUsersList_AsPDF		\
															and	'accountDomain'	in	_CurrentLogOnUsersList_AsPDF		\
															and	'isDomainAdmin'	in	_CurrentLogOnUsersList_AsPDF		\
															and	_CurrentLogOnUsersList_AsPDF.shape[0]	>	int(0):
															#
															_foundAzureADaccountFlag	=	False
															#
															### let's iterate on ALL users who have authenticated and accessed the VM
															for	cU	in	range(_CurrentLogOnUsersList_AsPDF.shape[0]):
																#
																_accountName		=	(_CurrentLogOnUsersList_AsPDF.iloc[cU])['accountName']
																_accountDomain		=	(_CurrentLogOnUsersList_AsPDF.iloc[cU])['accountDomain']
																_isDomainAdmin		=	(_CurrentLogOnUsersList_AsPDF.iloc[cU])['isDomainAdmin']
																#
																if		super().CoalesceEmptyNorNoneThenNone(_accountName)		!=	None	\
																	and	super().CoalesceEmptyNorNoneThenNone(_accountDomain)	!=	None:
																	#
																	### if the user is an AAD user, the "accountDomain" will contains "AzureAD", if not, the "accountDomain" will contains "computerDnsName" value
																	if	super().fold_text(super().CoalesceEmptyNorNoneThenNone(_accountDomain))	==	super().fold_text('azuread'):
																		#
																		_currentUserDetailInfoFromGraph_AsPDF	=	pandas.DataFrame(None).dropna()
																		#
																		_currentUserDetailInfoFromGraph_AsPDF	=	azAzGrapProcessorInstance.DoGetAzADUserByUPNorUserName(	\
																															TenantId					=	super().CoalesceEmptyNorNoneThenNone(TenantId)				\
																														,	ServiceApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)	\
																														,	ServiceApplicationP12bytes	=	ServiceApplicationP12bytes									\
																														,	ServiceAppP12Kbytes			=	ServiceAppP12Kbytes											\
																														,	UPNorUserNameAsString		=	super().CoalesceEmptyNorNoneThenNone(_accountName))
																		#
																		if	_currentUserDetailInfoFromGraph_AsPDF.empty	!=	True:
																			if		'userPrincipalName'	in	_currentUserDetailInfoFromGraph_AsPDF	\
																				and	'displayName'		in	_currentUserDetailInfoFromGraph_AsPDF	\
																				and	'id'				in	_currentUserDetailInfoFromGraph_AsPDF	\
																				and	'accountEnabled'	in	_currentUserDetailInfoFromGraph_AsPDF	\
																				and	_currentUserDetailInfoFromGraph_AsPDF.shape[0]	>	int(0):
																				#
																				### let's try to verify if this user gathered is the current user
																				if		super().get_similarity(_currentAcctRecord['accountName'],	_accountName)													>=	float(0.9)	\
																					or	super().get_similarity(_currentAcctRecord['accountName'],	_currentUserDetailInfoFromGraph_AsPDF.iloc[0]['displayName'])	>=	float(0.9):
																					#
																					_foundAzureADaccountFlag	=	True
																					#
																					newRowAsDict	=	{}
																					newRowAsDict	=	{
																												'id'				:	_allAlertsDetails_AsPDF.iloc[0]['id']
																											,	'machineId'			:	_allAlertsDetails_AsPDF.iloc[0]['machineId']
																											,	'UPN'				:	_currentUserDetailInfoFromGraph_AsPDF.iloc[0]['userPrincipalName']
																											,	'displayName'		:	_currentUserDetailInfoFromGraph_AsPDF.iloc[0]['displayName']
																											,	'Id'				:	_currentUserDetailInfoFromGraph_AsPDF.iloc[0]['id']
																											,	'accountEnabled'	:	_currentUserDetailInfoFromGraph_AsPDF.iloc[0]['accountEnabled']
																											,	'accountName'		:	_accountName
																											,	'accountDomain'		:	'AzureAD'
																											,	'isDomainAdmin'		:	_isDomainAdmin
																										}
																					_tmpUsersDetailsAsPDF	=	pandas.concat([_tmpUsersDetailsAsPDF, pandas.DataFrame([newRowAsDict])], ignore_index = True, verify_integrity = False, sort = False)
																					del	newRowAsDict
																					#
																				#
																		#
																	#
																#
																### end for cU in range(_CurrentLogOnUser_AsPDF.shape[0])
															#
															### let's check if we were unable to find an AzureAD user, then it was a local computer user
															if	_foundAzureADaccountFlag	!=	True:
																#
																_filteredLocalComputerUser	=	(_CurrentLogOnUsersList_AsPDF	\
																									.where(		\
																													(((_CurrentLogOnUsersList_AsPDF)['accountName']).str.lower()	==	str(super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentAcctRecord['accountName']))))	\
																											)	\
																									.dropna(how = 'all')).copy()
																#
																if	_filteredLocalComputerUser.empty	!=	True:
																	if		_filteredLocalComputerUser.shape[0]	>	int(0)	\
																		and	'id'			in	_filteredLocalComputerUser	\
																		and	'accountName'	in	_filteredLocalComputerUser	\
																		and	'accountDomain'	in	_filteredLocalComputerUser	\
																		and	'isDomainAdmin'	in	_filteredLocalComputerUser:
																		#
																		### let's join the data frames
																		newRowAsDict	=	{}
																		newRowAsDict	=	{
																									'id'				:	_allAlertsDetails_AsPDF.iloc[0]['id']
																								,	'machineId'			:	_allAlertsDetails_AsPDF.iloc[0]['machineId']
																								,	'UPN'				:	None
																								,	'displayName'		:	_filteredLocalComputerUser.iloc[0]['id']
																								,	'Id'				:	None
																								,	'accountEnabled'	:	True
																								,	'accountName'		:	_filteredLocalComputerUser.iloc[0]['accountName']
																								,	'accountDomain'		:	_filteredLocalComputerUser.iloc[0]['accountDomain']
																								,	'isDomainAdmin'		:	_filteredLocalComputerUser.iloc[0]['isDomainAdmin']
																							}
																		_tmpUsersDetailsAsPDF	=	pandas.concat([_tmpUsersDetailsAsPDF, pandas.DataFrame([newRowAsDict])], ignore_index = True, verify_integrity = False, sort = False)
																		del	newRowAsDict
																		#
																#
															#
														#
										#
									#
								#
								#
								#
								#
								### updated 2024/09/25
								### let's continue gather evidence data
								if		'evidence'	in	_allAlertsDetails_AsPDF:
									if	len(_allAlertsDetails_AsPDF['evidence']) > 0:
										if		type(_allAlertsDetails_AsPDF['evidence'].iloc[0])	is	list	\
											and	'id'			in	_allAlertsDetails_AsPDF						\
											and	'machineId'		in	_allAlertsDetails_AsPDF:
											#
											_currentEvidenceAsPDF	=	pandas.DataFrame(_allAlertsDetails_AsPDF['evidence'].iloc[0])
											#
											_currentEvidenceAsPDF['id']				=	_allAlertsDetails_AsPDF.iloc[0]['id']
											_currentEvidenceAsPDF['machineId']		=	_allAlertsDetails_AsPDF.iloc[0]['machineId']
											#
											_currentEvidence_GroupBy_id_machineId	=	_currentEvidenceAsPDF.groupby(by=['id','machineId'], dropna=True)
											#
											for _currentEvidence_GroupBy_id_machineId_NameOfGroup, _currentEvidence_GroupBy_id_machineId_ContentsOfGroup in _currentEvidence_GroupBy_id_machineId:
												#
												## ## ## _currentEvidence_GroupBy_id_machineId_NameOfGroup[0] contains _currentEvidenceAsPDF['id']
												## ## ## _currentEvidence_GroupBy_id_machineId_NameOfGroup[1] contains _currentEvidenceAsPDF['machineId']
												#
												_listOfUPNs	=	[]
												_listOfUPNs	=	_currentEvidence_GroupBy_id_machineId_ContentsOfGroup		\
																		.where(		\
																					(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['userPrincipalName'].str.strip().str.len()	>	int(0))					\
																				&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['userPrincipalName']							!=	None)					\
																				&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType']								!=	None)						
																				&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType'].str.strip().str.lower()		==	'User'.strip().lower())	\
																				)	\
																			.groupby(['userPrincipalName'], group_keys=False)['userPrincipalName'].apply(lambda x: x).unique().tolist()
												#
												_numOfRowsWithExistentUPN	=	len(_tmpUsersDetailsAsPDF[_tmpUsersDetailsAsPDF['UPN'].str.strip().str.lower().isin(x.strip().lower() for x in _listOfUPNs)])
												#
												if	(											\
														_numOfRowsWithExistentUPN	>	int(0)	\
													and	len(_listOfUPNs)			>	int(0)	\
													)											\
													or											\
													(											\
														_numOfRowsWithExistentUPN	<=	int(0)	\
													and	len(_listOfUPNs)			>	int(0)	\
													):
													#
													### deprecate datetime.fromisoformat 2024/06/19 because <import datetime> datetime.date.fromisoformat('2024-04-16T18:35:11.6Z') | datetime.datetime.fromisoformat('2024-04-16T18:35:11.6Z') throws exception : Invalid isoformat string: '2024-04-16T18:35:11.6Z'
													#
													newRowAsDict	=	{}
													newRowAsDict	=	{
																				'id'					:	_allAlertsDetails_AsPDF.iloc[0]['id']
																			,	'machineId'				:	_allAlertsDetails_AsPDF.iloc[0]['machineId']
																			,	'EvidenceCreationTime'	:	str(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup	\
																													.where(		\
																																	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['evidenceCreationTime'].str.strip().str.len()	>	int(0))	\
																																&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['evidenceCreationTime']							!=	None)	\
																															)	\
																													.groupby(['evidenceCreationTime'], group_keys=False)['evidenceCreationTime'].apply(lambda x: x).unique().tolist()).replace('[]', '')
																			,	'UPN(s)'				:	str(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup	\
																													.where(		\
																																	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['userPrincipalName'].str.strip().str.len()	>	int(0))					\
																																&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['userPrincipalName']							!=	None)					\
																																&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType']								!=	None)					\
																																&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType'].str.strip().str.len()			>	int(0))					\
																																&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType'].str.strip().str.lower()		==	'User'.strip().lower())	\
																															)	\
																													.groupby(['userPrincipalName'], group_keys=False)['userPrincipalName'].apply(lambda x: x).unique().tolist()).replace('[]', '')
																			,	'IP'					:	str(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup	\
																													.where(		\
																																	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['ipAddress'].str.strip().str.len()		>	int(0))					\
																																&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['ipAddress']								!=	None)					\
																																&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType']							!=	None)					\
																																&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType'].str.strip().str.len()		>	int(0))					\
																																&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType'].str.strip().str.lower()	==	'Ip'.strip().lower())	\
																															)	\
																													.groupby(['ipAddress'], group_keys=False)['ipAddress'].apply(lambda x: x).unique().tolist()).replace('[]', '')
																			,	'Url'					:	str(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup	\
																													.where(		\
																																	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['url'].str.strip().str.len()				>	int(0))					\
																																&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['url']									!=	None)					\
																																&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType']							!=	None)					\
																																&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType'].str.strip().str.len()		>	int(0))					\
																																&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType'].str.strip().str.lower()	==	'Url'.strip().lower())	\
																															)	\
																													.groupby(['url'], group_keys=False)['url'].apply(lambda x: x).unique().tolist()).replace('[]', '')
																			,	'Process'				:	str(_currentEvidenceAsPDF	\
																													.where(		\
																																	(_currentEvidenceAsPDF['id'].str.strip().str.lower()		==	super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentEvidence_GroupBy_id_machineId_NameOfGroup[0])))	\
																																&	(_currentEvidenceAsPDF['machineId'].str.strip().str.lower()	==	super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentEvidence_GroupBy_id_machineId_NameOfGroup[1])))	\
																																&	(_currentEvidenceAsPDF['entityType']									!=	None)						\
																																&	(_currentEvidenceAsPDF['entityType'].str.strip().str.len()				>	int(0))						\
																																&	(_currentEvidenceAsPDF['entityType'].str.strip().str.lower()			==	'Process'.strip().lower())	\
																														)	\
																													[[								\
																															'id'					\
																														,	'machineId'				\
																														,	'fileName'				\
																														,	'filePath'				\
																														,	'processCommandLine'	\
																														,	'processCreationTime'	\
																														,	'parentProcessFileName'	\
																														,	'parentProcessFilePath'	\
																														,	'detectionStatus'		\
																														,	'userPrincipalName'		\
																													]]	\
																													.dropna(how = 'all')	\
																													.groupby(by=['id','machineId'], dropna=True)	\
																													[[								\
																															'fileName'				\
																														,	'filePath'				\
																														,	'processCommandLine'	\
																														,	'processCreationTime'	\
																														,	'parentProcessFileName'	\
																														,	'parentProcessFilePath'	\
																														,	'detectionStatus'		\
																														,	'userPrincipalName'		\
																													]]	\
																													.agg(lambda x: numpy.NaN if x.isnull().all() else x.dropna())	\
																													[[								\
																															'fileName'				\
																														,	'filePath'				\
																														,	'processCommandLine'	\
																														,	'processCreationTime'	\
																														,	'parentProcessFileName'	\
																														,	'parentProcessFilePath'	\
																														,	'detectionStatus'		\
																														,	'userPrincipalName'		\
																													]]	\
																													.to_json(orient='records')).replace('[]', '')
																			,	'File'					:	str(_currentEvidenceAsPDF	\
																													.where(		\
																																	(_currentEvidenceAsPDF['id'].str.strip().str.lower()		==	super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentEvidence_GroupBy_id_machineId_NameOfGroup[0])))	\
																																&	(_currentEvidenceAsPDF['machineId'].str.strip().str.lower()	==	super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentEvidence_GroupBy_id_machineId_NameOfGroup[1])))	\
																																&	(_currentEvidenceAsPDF['entityType']									!=	None)						\
																																&	(_currentEvidenceAsPDF['entityType'].str.strip().str.len()				>	int(0))						\
																																&	(_currentEvidenceAsPDF['entityType'].str.strip().str.lower()			==	'File'.strip().lower())		\
																														)	\
																													[[								\
																															'id'					\
																														,	'machineId'				\
																														,	'fileName'				\
																														,	'filePath'				\
																														,	'detectionStatus'		\
																													]]	\
																													.dropna(how = 'all')	\
																													.groupby(by=['id','machineId'], dropna=True)	\
																													[[								\
																															'fileName'				\
																														,	'filePath'				\
																														,	'detectionStatus'		\
																													]]	\
																													.agg(lambda x: numpy.NaN if x.isnull().all() else x.dropna())	\
																													[[								\
																															'fileName'				\
																														,	'filePath'				\
																														,	'detectionStatus'		\
																													]]	\
																													.to_json(orient='records')).replace('[]', '')
																			,	'Other'					:	str(_currentEvidenceAsPDF	\
																													.where(		\
																																	(_currentEvidenceAsPDF['id'].str.strip().str.lower()		==	super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentEvidence_GroupBy_id_machineId_NameOfGroup[0])))	\
																																&	(_currentEvidenceAsPDF['machineId'].str.strip().str.lower()	==	super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentEvidence_GroupBy_id_machineId_NameOfGroup[1])))	\
																																&	(_currentEvidenceAsPDF['entityType']									!=	None)						\
																																&	(_currentEvidenceAsPDF['entityType'].str.strip().str.len()				>	int(0))						\
																																&	(_currentEvidenceAsPDF['entityType'].str.strip().str.lower()			!=	'Ip'.strip().lower())		\
																																&	(_currentEvidenceAsPDF['entityType'].str.strip().str.lower()			!=	'Url'.strip().lower())		\
																																&	(_currentEvidenceAsPDF['entityType'].str.strip().str.lower()			!=	'Process'.strip().lower())	\
																																&	(_currentEvidenceAsPDF['entityType'].str.strip().str.lower()			!=	'User'.strip().lower())		\
																																&	(_currentEvidenceAsPDF['entityType'].str.strip().str.lower()			!=	'File'.strip().lower())		\
																														)	\
																													[[								\
																															'id'					\
																														,	'machineId'				\
																														,	'entityType'			\
																														,	'registryKey'			\
																														,	'registryHive'			\
																														,	'registryValueType'		\
																														,	'registryValue'			\
																														,	'registryValueName'		\
																													]]	\
																													.dropna(how = 'all')	\
																													.groupby(by=['id','machineId'], dropna=True)	\
																													[[								\
																															'entityType'			\
																														,	'registryKey'			\
																														,	'registryHive'			\
																														,	'registryValueType'		\
																														,	'registryValue'			\
																														,	'registryValueName'		\
																													]]	\
																													.agg(lambda x: numpy.NaN if x.isnull().all() else x.dropna())	\
																													[[								\
																															'entityType'			\
																														,	'registryKey'			\
																														,	'registryHive'			\
																														,	'registryValueType'		\
																														,	'registryValue'			\
																														,	'registryValueName'		\
																													]]	\
																													.to_json(orient='records')).replace('[]', '')
																		}
													_tmpAlertsEvidencesGroupedListAsPDF	=	pandas.concat([_tmpAlertsEvidencesGroupedListAsPDF, pandas.DataFrame([newRowAsDict])], ignore_index = True, verify_integrity = False, sort = False)
													del	newRowAsDict
													#
												elif	_numOfRowsWithExistentUPN	<=	int(0)	\
													and	len(_listOfUPNs)			<=	int(0):
													#
													### let's try to gather users ('aadUserId') from 'User' or 'Process' entityType of 'evidence'
													#
													_listOfUPNs	=	[]
													_listOfUPNs	=	_currentEvidence_GroupBy_id_machineId_ContentsOfGroup		\
																			.where(		\
																						(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['aadUserId'].str.strip().str.len()	>	int(0))	\
																					&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['aadUserId']							!=	None)	\
																					&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType']						!=	None)	\
																					&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType'].str.strip().str.len()	>	int(0))	\
																					&	(	\
																							(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType'].str.strip().str.lower()	==	'User'.strip().lower())		\
																						|	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType'].str.strip().str.lower()	==	'Process'.strip().lower())	\
																						)	\
																					)	\
																				.groupby(['aadUserId'], group_keys=False)['aadUserId'].apply(lambda x: x).unique().tolist()
													#
													_numOfRowsWithExistentUPN	=	len(_tmpUsersDetailsAsPDF[_tmpUsersDetailsAsPDF['UPN'].str.strip().str.lower().isin(x.strip().lower() for x in _listOfUPNs)])
													#
													if	(											\
															_numOfRowsWithExistentUPN	>	int(0)	\
														and	len(_listOfUPNs)			>	int(0)	\
														)											\
														or											\
														(											\
															_numOfRowsWithExistentUPN	<=	int(0)	\
														and	len(_listOfUPNs)			>	int(0)	\
														):
														#
														### deprecate datetime.fromisoformat 2024/06/19 because <import datetime> datetime.date.fromisoformat('2024-04-16T18:35:11.6Z') | datetime.datetime.fromisoformat('2024-04-16T18:35:11.6Z') throws exception : Invalid isoformat string: '2024-04-16T18:35:11.6Z'
														#
														newRowAsDict	=	{}
														newRowAsDict	=	{
																					'id'					:	_allAlertsDetails_AsPDF.iloc[0]['id']
																				,	'machineId'				:	_allAlertsDetails_AsPDF.iloc[0]['machineId']
																				,	'EvidenceCreationTime'	:	str(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup	\
																														.where(		\
																																		(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['evidenceCreationTime'].str.strip().str.len()	>	int(0))	\
																																	&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['evidenceCreationTime']							!=	None)	\
																																)	\
																														.groupby(['evidenceCreationTime'], group_keys=False)['evidenceCreationTime'].apply(lambda x: x).unique().tolist()).replace('[]', '')
																				,	'UPN(s)'				:	str(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup	\
																														.where(		\
																																		(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['aadUserId'].str.strip().str.len()	>	int(0))	\
																																	&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['aadUserId']							!=	None)	\
																																	&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType']						!=	None)	\
																																	&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType'].str.strip().str.len()	>	int(0))	\
																																	&	(	\
																																			(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType'].str.strip().str.lower()	==	'User'.strip().lower())		\
																																		|	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType'].str.strip().str.lower()	==	'Process'.strip().lower())	\
																																		)
																																)	\
																														.groupby(['aadUserId'], group_keys=False)['aadUserId'].apply(lambda x: x).unique().tolist()).replace('[]', '')
																				,	'IP'					:	str(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup	\
																														.where(		\
																																		(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['ipAddress'].str.strip().str.len()		>	int(0))					\
																																	&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['ipAddress']								!=	None)					\
																																	&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType']							!=	None)					\
																																	&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType'].str.strip().str.len()		>	int(0))					\
																																	&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType'].str.strip().str.lower()	==	'Ip'.strip().lower())	\
																																)	\
																														.groupby(['ipAddress'], group_keys=False)['ipAddress'].apply(lambda x: x).unique().tolist()).replace('[]', '')
																				,	'Url'					:	str(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup	\
																														.where(		\
																																		(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['url'].str.strip().str.len()				>	int(0))					\
																																	&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['url']									!=	None)					\
																																	&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType']							!=	None)					\
																																	&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType'].str.strip().str.len()		>	int(0))					\
																																	&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType'].str.strip().str.lower()	==	'Url'.strip().lower())	\
																																)	\
																														.groupby(['url'], group_keys=False)['url'].apply(lambda x: x).unique().tolist()).replace('[]', '')
																				,	'Process'				:	str(_currentEvidenceAsPDF	\
																														.where(		\
																																		(_currentEvidenceAsPDF['id'].str.strip().str.lower()		==	super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentEvidence_GroupBy_id_machineId_NameOfGroup[0])))	\
																																	&	(_currentEvidenceAsPDF['machineId'].str.strip().str.lower()	==	super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentEvidence_GroupBy_id_machineId_NameOfGroup[1])))	\
																																	&	(_currentEvidenceAsPDF['entityType']									!=	None)						\
																																	&	(_currentEvidenceAsPDF['entityType'].str.strip().str.len()				>	int(0))						\
																																	&	(_currentEvidenceAsPDF['entityType'].str.strip().str.lower()			==	'Process'.strip().lower())	\
																															)	\
																														[[								\
																																'id'					\
																															,	'machineId'				\
																															,	'fileName'				\
																															,	'filePath'				\
																															,	'processCommandLine'	\
																															,	'processCreationTime'	\
																															,	'parentProcessFileName'	\
																															,	'parentProcessFilePath'	\
																															,	'detectionStatus'		\
																															,	'userPrincipalName'		\
																														]]	\
																														.dropna(how = 'all')	\
																														.groupby(by=['id','machineId'], dropna=True)	\
																														[[								\
																																'fileName'				\
																															,	'filePath'				\
																															,	'processCommandLine'	\
																															,	'processCreationTime'	\
																															,	'parentProcessFileName'	\
																															,	'parentProcessFilePath'	\
																															,	'detectionStatus'		\
																															,	'userPrincipalName'		\
																														]]	\
																														.agg(lambda x: numpy.NaN if x.isnull().all() else x.dropna())	\
																														[[								\
																																'fileName'				\
																															,	'filePath'				\
																															,	'processCommandLine'	\
																															,	'processCreationTime'	\
																															,	'parentProcessFileName'	\
																															,	'parentProcessFilePath'	\
																															,	'detectionStatus'		\
																															,	'userPrincipalName'		\
																														]]	\
																														.to_json(orient='records')).replace('[]', '')
																				,	'File'					:	str(_currentEvidenceAsPDF	\
																														.where(		\
																																		(_currentEvidenceAsPDF['id'].str.strip().str.lower()		==	super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentEvidence_GroupBy_id_machineId_NameOfGroup[0])))	\
																																	&	(_currentEvidenceAsPDF['machineId'].str.strip().str.lower()	==	super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentEvidence_GroupBy_id_machineId_NameOfGroup[1])))	\
																																	&	(_currentEvidenceAsPDF['entityType']									!=	None)						\
																																	&	(_currentEvidenceAsPDF['entityType'].str.strip().str.len()				>	int(0))						\
																																	&	(_currentEvidenceAsPDF['entityType'].str.strip().str.lower()			==	'File'.strip().lower())		\
																															)	\
																														[[								\
																																'id'					\
																															,	'machineId'				\
																															,	'fileName'				\
																															,	'filePath'				\
																															,	'detectionStatus'		\
																														]]	\
																														.dropna(how = 'all')	\
																														.groupby(by=['id','machineId'], dropna=True)	\
																														[[								\
																																'fileName'				\
																															,	'filePath'				\
																															,	'detectionStatus'		\
																														]]	\
																														.agg(lambda x: numpy.NaN if x.isnull().all() else x.dropna())	\
																														[[								\
																																'fileName'				\
																															,	'filePath'				\
																															,	'detectionStatus'		\
																														]]	\
																														.to_json(orient='records')).replace('[]', '')
																				,	'Other'					:	str(_currentEvidenceAsPDF	\
																														.where(		\
																																		(_currentEvidenceAsPDF['id'].str.strip().str.lower()		==	super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentEvidence_GroupBy_id_machineId_NameOfGroup[0])))	\
																																	&	(_currentEvidenceAsPDF['machineId'].str.strip().str.lower()	==	super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentEvidence_GroupBy_id_machineId_NameOfGroup[1])))	\
																																	&	(_currentEvidenceAsPDF['entityType']									!=	None)						\
																																	&	(_currentEvidenceAsPDF['entityType'].str.strip().str.len()				>	int(0))						\
																																	&	(_currentEvidenceAsPDF['entityType'].str.strip().str.lower()			!=	'Ip'.strip().lower())		\
																																	&	(_currentEvidenceAsPDF['entityType'].str.strip().str.lower()			!=	'Url'.strip().lower())		\
																																	&	(_currentEvidenceAsPDF['entityType'].str.strip().str.lower()			!=	'Process'.strip().lower())	\
																																	&	(_currentEvidenceAsPDF['entityType'].str.strip().str.lower()			!=	'User'.strip().lower())		\
																																	&	(_currentEvidenceAsPDF['entityType'].str.strip().str.lower()			!=	'File'.strip().lower())		\
																															)	\
																														[[								\
																																'id'					\
																															,	'machineId'				\
																															,	'entityType'			\
																															,	'registryKey'			\
																															,	'registryHive'			\
																															,	'registryValueType'		\
																															,	'registryValue'			\
																															,	'registryValueName'		\
																														]]	\
																														.dropna(how = 'all')	\
																														.groupby(by=['id','machineId'], dropna=True)	\
																														[[								\
																																'entityType'			\
																															,	'registryKey'			\
																															,	'registryHive'			\
																															,	'registryValueType'		\
																															,	'registryValue'			\
																															,	'registryValueName'		\
																														]]	\
																														.agg(lambda x: numpy.NaN if x.isnull().all() else x.dropna())	\
																														[[								\
																																'entityType'			\
																															,	'registryKey'			\
																															,	'registryHive'			\
																															,	'registryValueType'		\
																															,	'registryValue'			\
																															,	'registryValueName'		\
																														]]	\
																														.to_json(orient='records')).replace('[]', '')
																			}
														_tmpAlertsEvidencesGroupedListAsPDF	=	pandas.concat([_tmpAlertsEvidencesGroupedListAsPDF, pandas.DataFrame([newRowAsDict])], ignore_index = True, verify_integrity = False, sort = False)
														del	newRowAsDict
														#
													else:
														#
														### deprecate datetime.fromisoformat 2024/06/19 because <import datetime> datetime.date.fromisoformat('2024-04-16T18:35:11.6Z') | datetime.datetime.fromisoformat('2024-04-16T18:35:11.6Z') throws exception : Invalid isoformat string: '2024-04-16T18:35:11.6Z'
														#
														newRowAsDict	=	{}
														newRowAsDict	=	{
																					'id'					:	_allAlertsDetails_AsPDF.iloc[0]['id']
																				,	'machineId'				:	_allAlertsDetails_AsPDF.iloc[0]['machineId']
																				,	'EvidenceCreationTime'	:	str(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup	\
																														.where(		\
																																		(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['evidenceCreationTime'].str.strip().str.len()	>	int(0))	\
																																	&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['evidenceCreationTime']							!=	None)	\
																																)	\
																														.groupby(['evidenceCreationTime'], group_keys=False)['evidenceCreationTime'].apply(lambda x: x).unique().tolist()).replace('[]', '')
																				,	'UPN(s)'				:	None
																				,	'IP'					:	str(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup	\
																														.where(		\
																																		(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['ipAddress'].str.strip().str.len()		>	int(0))					\
																																	&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['ipAddress']								!=	None)					\
																																	&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType']							!=	None)					\
																																	&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType'].str.strip().str.len()		>	int(0))					\
																																	&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType'].str.strip().str.lower()	==	'Ip'.strip().lower())	\
																																)	\
																														.groupby(['ipAddress'], group_keys=False)['ipAddress'].apply(lambda x: x).unique().tolist()).replace('[]', '')
																				,	'Url'					:	str(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup	\
																														.where(		\
																																		(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['url'].str.strip().str.len()				>	int(0))					\
																																	&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['url']									!=	None)					\
																																	&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType']							!=	None)					\
																																	&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType'].str.strip().str.len()		>	int(0))					\
																																	&	(_currentEvidence_GroupBy_id_machineId_ContentsOfGroup['entityType'].str.strip().str.lower()	==	'Url'.strip().lower())	\
																																)	\
																														.groupby(['url'], group_keys=False)['url'].apply(lambda x: x).unique().tolist()).replace('[]', '')
																				,	'Process'				:	str(_currentEvidenceAsPDF	\
																														.where(		\
																																		(_currentEvidenceAsPDF['id'].str.strip().str.lower()		==	super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentEvidence_GroupBy_id_machineId_NameOfGroup[0])))	\
																																	&	(_currentEvidenceAsPDF['machineId'].str.strip().str.lower()	==	super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentEvidence_GroupBy_id_machineId_NameOfGroup[1])))	\
																																	&	(_currentEvidenceAsPDF['entityType']									!=	None)						\
																																	&	(_currentEvidenceAsPDF['entityType'].str.strip().str.len()				>	int(0))						\
																																	&	(_currentEvidenceAsPDF['entityType'].str.strip().str.lower()			==	'Process'.strip().lower())	\
																															)	\
																														[[								\
																																'id'					\
																															,	'machineId'				\
																															,	'fileName'				\
																															,	'filePath'				\
																															,	'processCommandLine'	\
																															,	'processCreationTime'	\
																															,	'parentProcessFileName'	\
																															,	'parentProcessFilePath'	\
																															,	'detectionStatus'		\
																															,	'userPrincipalName'		\
																														]]	\
																														.dropna(how = 'all')	\
																														.groupby(by=['id','machineId'], dropna=True)	\
																														[[								\
																																'fileName'				\
																															,	'filePath'				\
																															,	'processCommandLine'	\
																															,	'processCreationTime'	\
																															,	'parentProcessFileName'	\
																															,	'parentProcessFilePath'	\
																															,	'detectionStatus'		\
																															,	'userPrincipalName'		\
																														]]	\
																														.agg(lambda x: numpy.NaN if x.isnull().all() else x.dropna())	\
																														[[								\
																																'fileName'				\
																															,	'filePath'				\
																															,	'processCommandLine'	\
																															,	'processCreationTime'	\
																															,	'parentProcessFileName'	\
																															,	'parentProcessFilePath'	\
																															,	'detectionStatus'		\
																															,	'userPrincipalName'		\
																														]]	\
																														.to_json(orient='records')).replace('[]', '')
																				,	'File'					:	str(_currentEvidenceAsPDF	\
																														.where(		\
																																		(_currentEvidenceAsPDF['id'].str.strip().str.lower()		==	super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentEvidence_GroupBy_id_machineId_NameOfGroup[0])))	\
																																	&	(_currentEvidenceAsPDF['machineId'].str.strip().str.lower()	==	super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentEvidence_GroupBy_id_machineId_NameOfGroup[1])))	\
																																	&	(_currentEvidenceAsPDF['entityType']									!=	None)						\
																																	&	(_currentEvidenceAsPDF['entityType'].str.strip().str.len()				>	int(0))						\
																																	&	(_currentEvidenceAsPDF['entityType'].str.strip().str.lower()			==	'File'.strip().lower())		\
																															)	\
																														[[								\
																																'id'					\
																															,	'machineId'				\
																															,	'fileName'				\
																															,	'filePath'				\
																															,	'detectionStatus'		\
																														]]	\
																														.dropna(how = 'all')	\
																														.groupby(by=['id','machineId'], dropna=True)	\
																														[[								\
																																'fileName'				\
																															,	'filePath'				\
																															,	'detectionStatus'		\
																														]]	\
																														.agg(lambda x: numpy.NaN if x.isnull().all() else x.dropna())	\
																														[[								\
																																'fileName'				\
																															,	'filePath'				\
																															,	'detectionStatus'		\
																														]]	\
																														.to_json(orient='records')).replace('[]', '')
																				,	'Other'					:	str(_currentEvidenceAsPDF	\
																														.where(		\
																																		(_currentEvidenceAsPDF['id'].str.strip().str.lower()		==	super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentEvidence_GroupBy_id_machineId_NameOfGroup[0])))	\
																																	&	(_currentEvidenceAsPDF['machineId'].str.strip().str.lower()	==	super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentEvidence_GroupBy_id_machineId_NameOfGroup[1])))	\
																																	&	(_currentEvidenceAsPDF['entityType']									!=	None)						\
																																	&	(_currentEvidenceAsPDF['entityType'].str.strip().str.len()				>	int(0))						\
																																	&	(_currentEvidenceAsPDF['entityType'].str.strip().str.lower()			!=	'Ip'.strip().lower())		\
																																	&	(_currentEvidenceAsPDF['entityType'].str.strip().str.lower()			!=	'Url'.strip().lower())		\
																																	&	(_currentEvidenceAsPDF['entityType'].str.strip().str.lower()			!=	'Process'.strip().lower())	\
																																	&	(_currentEvidenceAsPDF['entityType'].str.strip().str.lower()			!=	'User'.strip().lower())		\
																																	&	(_currentEvidenceAsPDF['entityType'].str.strip().str.lower()			!=	'File'.strip().lower())		\
																															)	\
																														[[								\
																																'id'					\
																															,	'machineId'				\
																															,	'entityType'			\
																															,	'registryKey'			\
																															,	'registryHive'			\
																															,	'registryValueType'		\
																															,	'registryValue'			\
																															,	'registryValueName'		\
																														]]	\
																														.dropna(how = 'all')	\
																														.groupby(by=['id','machineId'], dropna=True)	\
																														[[								\
																																'entityType'			\
																															,	'registryKey'			\
																															,	'registryHive'			\
																															,	'registryValueType'		\
																															,	'registryValue'			\
																															,	'registryValueName'		\
																														]]	\
																														.agg(lambda x: numpy.NaN if x.isnull().all() else x.dropna())	\
																														[[								\
																																'entityType'			\
																															,	'registryKey'			\
																															,	'registryHive'			\
																															,	'registryValueType'		\
																															,	'registryValue'			\
																															,	'registryValueName'		\
																														]]	\
																														.to_json(orient='records')).replace('[]', '')
																			}
														_tmpAlertsEvidencesGroupedListAsPDF	=	pandas.concat([_tmpAlertsEvidencesGroupedListAsPDF, pandas.DataFrame([newRowAsDict])], ignore_index = True, verify_integrity = False, sort = False)
														del	newRowAsDict
														#
													#
													#
												#
												## ## ## end for _currentEvidence_GroupBy_id_machineId
											#
								#
								#
								#
								#
								#
						#
						# # # end for r	in	range(_alertsDataSet_AsRAW_DataFrame.shape[0])
					#
					### let's join the users with raw data
					if	_tmpUsersDetailsAsPDF.empty	!=	True:
						#
						if	_tmpUsersDetailsAsPDF.shape[0]	>	int(0):
							#
							_synthesizedUsersDS	=	pandas.DataFrame(None).dropna()
							_upnDS				=	pandas.DataFrame(None).dropna()
							_dnDS				=	pandas.DataFrame(None).dropna()
							_aeDS				=	pandas.DataFrame(None).dropna()
							_anDS				=	pandas.DataFrame(None).dropna()
							_adDS				=	pandas.DataFrame(None).dropna()
							_idaDS				=	pandas.DataFrame(None).dropna()
							#
							_upnDS				=	_tmpUsersDetailsAsPDF[['id','machineId','UPN','Id']]			\
																.groupby(by=['id','machineId'], dropna=True)		\
																.first()											\
																.reset_index()										\
							#
							_dnDS				=	_tmpUsersDetailsAsPDF[['id','machineId','displayName']]									\
																	.groupby(by=['id','machineId'], dropna=True)							\
																	.apply(lambda x: str(list(set(											\
																								filter(lambda y:(		y != None			\
																													and y != pandas.NaT		\
																													and y != numpy.NaN)		\
																												, x['displayName'])))))		\
																	.reset_index()															\
																	.rename(columns={0:'displayName'})										\
							#
							_aeDS				=	_tmpUsersDetailsAsPDF[['id','machineId','accountEnabled']]								\
																	.groupby(by=['id','machineId'], dropna=True)							\
																	.apply(lambda x: str(list(set(											\
																								filter(lambda y:(		y != None			\
																													and y != pandas.NaT		\
																													and y != numpy.NaN)		\
																												, x['accountEnabled'])))))	\
																	.reset_index()															\
																	.rename(columns={0:'accountEnabled'})									\
							#
							_anDS				=	_tmpUsersDetailsAsPDF[['id','machineId','accountName']]									\
																	.groupby(by=['id','machineId'], dropna=True)							\
																	.apply(lambda x: str(list(set(											\
																								filter(lambda y:(		y != None			\
																													and y != pandas.NaT		\
																													and y != numpy.NaN)		\
																												, x['accountName'])))))		\
																	.reset_index()															\
																	.rename(columns={0:'accountName'})										\
							#
							_adDS				=	_tmpUsersDetailsAsPDF[['id','machineId','accountDomain']]								\
																	.groupby(by=['id','machineId'], dropna=True)							\
																	.apply(lambda x: str(list(set(											\
																								filter(lambda y:(		y != None			\
																													and y != pandas.NaT		\
																													and y != numpy.NaN)		\
																												, x['accountDomain'])))))	\
																	.reset_index()															\
																	.rename(columns={0:'accountDomain'})									\
							#
							_idaDS				=	_tmpUsersDetailsAsPDF[['id','machineId','isDomainAdmin']]								\
																	.groupby(by=['id','machineId'], dropna=True)							\
																	.apply(lambda x: str(list(set(											\
																								filter(lambda y:(		y != None			\
																													and y != pandas.NaT		\
																													and y != numpy.NaN)		\
																												, x['isDomainAdmin'])))))	\
																	.reset_index()															\
																	.rename(columns={0:'isDomainAdmin'})									\
							#
							_synthesizedUsersDS		=	_upnDS[['id','machineId','UPN','Id']]						\
															.set_index(['id','machineId'], verify_integrity=True)	\
															.join(													\
																		_dnDS[[										\
																					'id'							\
																				,	'machineId'						\
																				,	'displayName'					\
																			]]										\
																			.set_index(['id','machineId'], verify_integrity=True)	\
																	,	on=['id','machineId']	\
																	,	how='left'				\
																	,	lsuffix='_left'			\
																	,	rsuffix='_right'		\
																)								\
															.join(													\
																		_aeDS[[										\
																					'id'							\
																				,	'machineId'						\
																				,	'accountEnabled'				\
																			]]										\
																			.set_index(['id','machineId'], verify_integrity=True)	\
																	,	on=['id','machineId']	\
																	,	how='left'				\
																	,	lsuffix='_left'			\
																	,	rsuffix='_right'		\
																)								\
															.join(													\
																		_anDS[[										\
																					'id'							\
																				,	'machineId'						\
																				,	'accountName'					\
																			]]										\
																			.set_index(['id','machineId'], verify_integrity=True)	\
																	,	on=['id','machineId']	\
																	,	how='left'				\
																	,	lsuffix='_left'			\
																	,	rsuffix='_right'		\
																)								\
															.join(													\
																		_adDS[[										\
																					'id'							\
																				,	'machineId'						\
																				,	'accountDomain'					\
																			]]										\
																			.set_index(['id','machineId'], verify_integrity=True)	\
																	,	on=['id','machineId']	\
																	,	how='left'				\
																	,	lsuffix='_left'			\
																	,	rsuffix='_right'		\
																)								\
															.join(													\
																		_idaDS[[									\
																					'id'							\
																				,	'machineId'						\
																				,	'isDomainAdmin'					\
																			]]										\
																			.set_index(['id','machineId'], verify_integrity=True)	\
																	,	on=['id','machineId']	\
																	,	how='left'				\
																	,	lsuffix='_left'			\
																	,	rsuffix='_right'		\
																)								\
															.reset_index()
							#
							_alertsDataSet_AsRAW_DataFrame = (_alertsDataSet_AsRAW_DataFrame[[								\
																									'id'					\
																								,	'incidentId'			\
																								,	'investigationId'		\
																								,	'assignedTo'			\
																								,	'severity'				\
																								,	'status'				\
																								,	'classification'		\
																								,	'determination'			\
																								,	'investigationState'	\
																								,	'detectionSource'		\
																								,	'detectorId'			\
																								,	'category'				\
																								,	'threatFamilyName'		\
																								,	'title'					\
																								,	'description'			\
																								,	'alertCreationTime'		\
																								,	'firstEventTime'		\
																								,	'lastEventTime'			\
																								,	'lastUpdateTime'		\
																								,	'resolvedTime'			\
																								,	'machineId'				\
																								,	'computerDnsName'		\
																								,	'rbacGroupName'			\
																								,	'aadTenantId'			\
																								,	'threatName'			\
																								,	'mitreTechniques'		\
																								,	'relatedUser'			\
																								,	'loggedOnUsers'			\
																								,	'comments'				\
																								,	'evidence'				\
																								,	'domains'				\
																							]])								\
																.set_index(['id','machineId'])								\
																.join(														\
																			_synthesizedUsersDS[[							\
																										'id'				\
																									,	'machineId'			\
																									,	'UPN'				\
																									,	'displayName'		\
																									,	'Id'				\
																									,	'accountEnabled'	\
																									,	'accountName'		\
																									,	'accountDomain'		\
																									,	'isDomainAdmin'		\
																								]]							\
																								.set_index(['id','machineId'])	\
																		,	on=['id','machineId']	\
																		,	how='left'				\
																		,	lsuffix='_left'			\
																		,	rsuffix='_right'		\
																	)								\
																.reset_index()
							#
						#
					#
					del _synthesizedUsersDS
					del _upnDS
					del _dnDS
					del _aeDS
					del _anDS
					del _adDS
					del _idaDS
					del _tmpUsersDetailsAsPDF
					#
					if		not	('UPN'				in	_alertsDataSet_AsRAW_DataFrame)	\
						and	not	('displayName'		in	_alertsDataSet_AsRAW_DataFrame)	\
						and	not	('Id'				in	_alertsDataSet_AsRAW_DataFrame)	\
						and	not	('accountEnabled'	in	_alertsDataSet_AsRAW_DataFrame)	\
						and	not	('accountName'		in	_alertsDataSet_AsRAW_DataFrame)	\
						and	not	('accountDomain'	in	_alertsDataSet_AsRAW_DataFrame)	\
						and	not	('isDomainAdmin'	in	_alertsDataSet_AsRAW_DataFrame):
						#
						_alertsDataSet_AsRAW_DataFrame = _alertsDataSet_AsRAW_DataFrame	\
																	.reindex(			\
																			columns = _alertsDataSet_AsRAW_DataFrame.columns.tolist()	\
																			+	[	\
																						'UPN'				\
																					,	'displayName'		\
																					,	'Id'				\
																					,	'accountEnabled'	\
																					,	'accountName'		\
																					,	'accountDomain'		\
																					,	'isDomainAdmin'		\
																				])
						#
					#
					### let's join the users with raw data
					if	_tmpAlertsEvidencesGroupedListAsPDF.empty	!=	True:
						#
						if	_tmpAlertsEvidencesGroupedListAsPDF.shape[0]	>	int(0):
							#
							_alertsDataSet_AsRAW_DataFrame = (_alertsDataSet_AsRAW_DataFrame[[								\
																									'id'					\
																								,	'incidentId'			\
																								,	'investigationId'		\
																								,	'assignedTo'			\
																								,	'severity'				\
																								,	'status'				\
																								,	'classification'		\
																								,	'determination'			\
																								,	'investigationState'	\
																								,	'detectionSource'		\
																								,	'detectorId'			\
																								,	'category'				\
																								,	'threatFamilyName'		\
																								,	'title'					\
																								,	'description'			\
																								,	'alertCreationTime'		\
																								,	'firstEventTime'		\
																								,	'lastEventTime'			\
																								,	'lastUpdateTime'		\
																								,	'resolvedTime'			\
																								,	'machineId'				\
																								,	'computerDnsName'		\
																								,	'rbacGroupName'			\
																								,	'aadTenantId'			\
																								,	'threatName'			\
																								,	'mitreTechniques'		\
																								,	'relatedUser'			\
																								,	'loggedOnUsers'			\
																								,	'comments'				\
																								,	'evidence'				\
																								,	'domains'				\
																								,	'UPN'					\
																								,	'displayName'			\
																								,	'Id'					\
																								,	'accountEnabled'		\
																								,	'accountName'			\
																								,	'accountDomain'			\
																								,	'isDomainAdmin'			\
																							]])								\
																.set_index(['id','machineId'])								\
																.join(														\
																			_tmpAlertsEvidencesGroupedListAsPDF[[			\
																									'id'					\
																								,	'machineId'				\
																								,	'EvidenceCreationTime'	\
																								,	'UPN(s)'				\
																								,	'IP'					\
																								,	'Url'					\
																								,	'Process'				\
																								,	'File'					\
																								,	'Other'					\
																							]]								\
																							.set_index(['id','machineId'])	\
																		,	on=['id','machineId']	\
																		,	how='left'				\
																		,	lsuffix='_left'			\
																		,	rsuffix='_right'		\
																	)								\
																.reset_index()
							#
						#
					#
					del	_tmpAlertsEvidencesGroupedListAsPDF
					#
					if		not	('EvidenceCreationTime'	in	_alertsDataSet_AsRAW_DataFrame)	\
						and	not	('UPN(s)'				in	_alertsDataSet_AsRAW_DataFrame)	\
						and	not	('IP'					in	_alertsDataSet_AsRAW_DataFrame)	\
						and	not	('Url'					in	_alertsDataSet_AsRAW_DataFrame)	\
						and	not	('Process'				in	_alertsDataSet_AsRAW_DataFrame)	\
						and	not	('File'					in	_alertsDataSet_AsRAW_DataFrame)	\
						and	not	('Other'				in	_alertsDataSet_AsRAW_DataFrame):
						#
						_alertsDataSet_AsRAW_DataFrame = _alertsDataSet_AsRAW_DataFrame	\
																	.reindex(			\
																			columns = _alertsDataSet_AsRAW_DataFrame.columns.tolist()	\
																			+	[	\
																						'EvidenceCreationTime'	\
																					,	'UPN(s)'				\
																					,	'IP'					\
																					,	'Url'					\
																					,	'Process'				\
																					,	'File'					\
																					,	'Other'					\
																				])
						#
					#
					#
					#
					#
					#
					#
				#
			#
			if	_alertsDataSet_AsRAW_DataFrame.empty	!=	True:
				if	_alertsDataSet_AsRAW_DataFrame.shape[0]	>	int(0):
					#
					### let's append more columns with the alertUrl and machineUrl
					_alertsDataSet_AsRAW_DataFrame['alertUrl']		=	pandas.Series(dtype='str')
					_alertsDataSet_AsRAW_DataFrame['machineUrl']	=	pandas.Series(dtype='str')
					_alertsDataSet_AsRAW_DataFrame[['alertUrl', 'machineUrl']]	=	None
					_alertsDataSet_AsRAW_DataFrame['alertUrl']		=	['https://security.microsoft.com/alerts/{0}'.format(x.strip()) if ((x != None) & (len(x.strip()) >= int(0))) else None for x in _alertsDataSet_AsRAW_DataFrame['id']]
					_alertsDataSet_AsRAW_DataFrame['machineUrl']	=	['https://security.microsoft.com/machines/v2/{0}/overview'.format(x.strip()) if ((x != None) & (len(x.strip()) >= int(0))) else None for x in _alertsDataSet_AsRAW_DataFrame['machineId']]
					#
					### let's verify if there's no available 'UPN', then let's try to gather it from 'UserPrincipalName'
					### ## ref : https://saturncloud.io/blog/python-pandas-selecting-rows-whose-column-value-is-null-none-nan/
					if	(	\
							len(	\
								_alertsDataSet_AsRAW_DataFrame[['UPN','id']]	\
									.where(		\
													(_alertsDataSet_AsRAW_DataFrame[['UPN','id']].isnull().any(axis = 1))	\
											)	\
									.dropna(how = 'all')	\
									.groupby(['id'], group_keys=False)['id']	\
									.apply(lambda x: x)	\
									.unique()	\
									.tolist()
								)
						)	>	int(0):
						#
						_listOfAlertIds	=	_alertsDataSet_AsRAW_DataFrame[['UPN','id']].where((_alertsDataSet_AsRAW_DataFrame[['UPN','id']].isnull().any(axis = 1))).dropna(how = 'all').groupby(['id'], group_keys=False)['id'].apply(lambda x: x).unique().tolist()
						#
						### let's iterate on each one just to check if 'UPN(s)' is NOT null
						for iterL in range(len(_listOfAlertIds)):
							#
							_currentIterAlertId	=	_listOfAlertIds[iterL]
							if	len(	\
									_alertsDataSet_AsRAW_DataFrame	\
										.where(		\
														(_alertsDataSet_AsRAW_DataFrame['UPN(s)'].str.strip().str.len()		>	int(0))	\
													&	(_alertsDataSet_AsRAW_DataFrame['UPN(s)']							!=	None)	\
													&	(_alertsDataSet_AsRAW_DataFrame['id'].str.strip().str.len()			>	int(0))	\
													&	(_alertsDataSet_AsRAW_DataFrame['id']								!=	None)	\
													&	(_alertsDataSet_AsRAW_DataFrame['id'].str.strip().str.lower()		==	super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentIterAlertId)))	\
												)	\
										.dropna(how = 'all')	\
										.groupby(['id'], group_keys=False)['id']	\
										.apply(lambda x: x)	\
										.unique()	\
										.tolist()
									)	>	int(0):
								#
								_upnToReplaceValueAsString	=	super().CoalesceEmptyNorNoneThenNone(str(_alertsDataSet_AsRAW_DataFrame.loc[_alertsDataSet_AsRAW_DataFrame['id'].str.strip().str.lower() == super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentIterAlertId)), 'UPN(s)'].iloc[0]))
								if	super().CoalesceEmptyNorNoneThenNone(_upnToReplaceValueAsString)	!=	None:
									_upnList	=	list(set(eval(_upnToReplaceValueAsString)))
									if	len(_upnList)	>	int(0):
										_upnToReplaceValueAsString	=	'{0}'.format(str(_upnList[0]))
										_alertsDataSet_AsRAW_DataFrame.loc[_alertsDataSet_AsRAW_DataFrame['id'].str.strip().str.lower() == super().fold_text(super().CoalesceEmptyNorNoneThenNone(_currentIterAlertId)), 'UPN'] = _upnToReplaceValueAsString
								#
							#
						#
					#
					returnPandasDataFrame	=	_alertsDataSet_AsRAW_DataFrame.copy()
					del _alertsDataSet_AsRAW_DataFrame
					#
			#
		#
		return returnPandasDataFrame
		#

	def DoProcessComputerRemediations(
											self																							\
										,	TenantId:							str															\
										,	ServiceApplicationId:				str															\
										,	ServiceApplicationP12bytes:			bytes														\
										,	ServiceAppP12Kbytes:				bytes														\
										,	machineId:							str															\
										,	computerDnsName:					str															\
										,	id:									str															\
										,	ComputerRemediationActionsAsDict:	dict														\
										,	WindowsDefenderHostAPIurl:			str															\
										,	ScopeAudienceDomain:				str		=	'https://api.securitycenter.microsoft.com/'		\
										,	_TimeOutInSeconds:					int		=	int(900)										\
									) -> pandas.DataFrame:
		##
		#	@brief Do Process Computer Remediations
		#
		#	Keyword arguments:
		#	@param TenantId								--
		#	@param ServiceApplicationId					--
		#	@param ServiceApplicationP12bytes			--
		#	@param ServiceAppP12Kbytes					--
		#	@param machineId							--
		#	@param computerDnsName						--
		#	@param id									--
		#	@param ComputerRemediationActionsAsDict		--
		#	@param WindowsDefenderHostAPIurl			--
		#	@param ScopeAudienceDomain					--
		#	@param _TimeOutInSeconds					--
		"""
		Do Process Computer Remediations
		"""
		returnActionsResultsAsPDF	=	pandas.DataFrame(None).dropna()
		returnActionsResultsAsPDF	=	pandas.DataFrame({	\
															c	:	pandas.Series(dtype=t)	for	c
														,	t	in	{	\
																			'RemediationTypeName'			:	numpy.dtype('U')	\
																		,	'ExecutionSuccessfulResult'		:	numpy.dtype('?')	\
																		,	'RemediationCode'				:	numpy.dtype('i')	\
																		,	'id'							:	numpy.dtype('U')	\
																		,	'machineId'						:	numpy.dtype('U')	\
																		,	'computerDnsName'				:	numpy.dtype('U')	\
																		,	'RemediationResponseAsString'	:	numpy.dtype('U')	\
																	}.items()	\
													})
		#
		if		len(ComputerRemediationActionsAsDict)																>	int(0)	\
			and	super().CoalesceEmptyNorNoneThenNone(TenantId)														!=	None	\
			and	re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(TenantId))				!=	None	\
			and	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)											!=	None	\
			and	re.fullmatch(super()._GUIDregExPattern, super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId))	!=	None	\
			and	len(ServiceApplicationP12bytes)																		>	0		\
			and	len(ServiceAppP12Kbytes)																			>	0		\
			and	super().CoalesceEmptyNorNoneThenNone(machineId)														!=	None	\
			and	super().CoalesceEmptyNorNoneThenNone(computerDnsName)												!=	None	\
			and	super().CoalesceEmptyNorNoneThenNone(id)															!=	None	\
			and	super().CoalesceEmptyNorNoneThenNone(WindowsDefenderHostAPIurl)										!=	None	\
			and	super().CoalesceEmptyNorNoneThenNone(ScopeAudienceDomain)											!=	None:
			#
			#
			# @xxxxxxxx][==============================================================>
			#
			if	'WindowsDefenderRunAntiVirusScan'	in	ComputerRemediationActionsAsDict:
				if	bool(ComputerRemediationActionsAsDict['WindowsDefenderRunAntiVirusScan'])	==	True:
					#
					for currentTry in range(super()._maxRetries):
					#
						#
						currentTry_ProcessResult	=	False
						#
						try:
							#
							_DefenderForEndpointsAPIToken = super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																								\
																																_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)	\
																															,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)				\
																															,	_P12certBytes			=	ServiceApplicationP12bytes									\
																															,	_P12certKy				=	ServiceAppP12Kbytes											\
																															,	_ScopeAudienceDomain	=	super().CoalesceEmptyNorNoneThenNone(ScopeAudienceDomain)	\
																														)
							#
							if		_DefenderForEndpointsAPIToken			!=	None	\
								and	len(_DefenderForEndpointsAPIToken)	>	0:
								#
								#
								WindowsDefenderToRunAntiVirusScanAPIurl	=		super().CoalesceEmptyNorNoneThenNone(WindowsDefenderHostAPIurl)		\
																			+	'/api/machines/'													\
																			+	super().CoalesceEmptyNorNoneThenNone(machineId)						\
																			+	'/runAntiVirusScan'
								#
								WindowsDefenderToRunAntiVirusScan_POST_Body	=	{
																						'Comment'	:	'Run Full AntiVirus Scan by Defender Alert id : [{AlertId}]'.format(AlertId = super().CoalesceEmptyNorNoneThenNone(id))
																					,	'ScanType'	:	'Full'
																				}
								#
								HeadersV1					=	{
																		'Authorization'		:	'Bearer {TokenJWT}'.format(TokenJWT = _DefenderForEndpointsAPIToken['access_token'])
																	,	'Content-Type'		:	'application/json'
																}
								#
								InvokeWindowsDefenderToRunAntiVirusScanResponse	=	requests.post(																					\
																										url				=	WindowsDefenderToRunAntiVirusScanAPIurl					\
																									,	json			=	WindowsDefenderToRunAntiVirusScan_POST_Body				\
																									,	data			=	json.dumps(WindowsDefenderToRunAntiVirusScan_POST_Body)	\
																									,	headers			=	HeadersV1												\
																									,	timeout			=	_TimeOutInSeconds										\
																								)
								#
								if	not	InvokeWindowsDefenderToRunAntiVirusScanResponse is None:
									if		InvokeWindowsDefenderToRunAntiVirusScanResponse.status_code >= int(200)	\
										and InvokeWindowsDefenderToRunAntiVirusScanResponse.status_code <= int(299):
										#
										newRowAsDict	=	{}
										newRowAsDict	=	{
																	'RemediationTypeName'			:	'WindowsDefenderRunAntiVirusScan'
																,	'ExecutionSuccessfulResult'		:	True
																,	'RemediationCode'				:	InvokeWindowsDefenderToRunAntiVirusScanResponse.status_code
																,	'id'							:	super().CoalesceEmptyNorNoneThenNone(id)
																,	'machineId'						:	super().CoalesceEmptyNorNoneThenNone(machineId)
																,	'computerDnsName'				:	super().CoalesceEmptyNorNoneThenNone(computerDnsName)
																,	'RemediationResponseAsString'	:	InvokeWindowsDefenderToRunAntiVirusScanResponse.text
															}
										#
										returnActionsResultsAsPDF	=	pandas.concat([returnActionsResultsAsPDF, pandas.DataFrame([newRowAsDict])], ignore_index = True, verify_integrity = False, sort = False)
										#
										currentTry_ProcessResult	=	True
										break
										#
									else:
										super().HandleGLobalPostRequestError(																								\
																					_reason			=	InvokeWindowsDefenderToRunAntiVirusScanResponse.reason				\
																				,	_status_code	=	int(InvokeWindowsDefenderToRunAntiVirusScanResponse.status_code)	\
																				,	_text			=	InvokeWindowsDefenderToRunAntiVirusScanResponse.text				\
																				,	_content		=	InvokeWindowsDefenderToRunAntiVirusScanResponse.content				\
																			)
								#
								#
							#
						except requests.exceptions.HTTPError as httpEerr_:
							super().HandleGLobalException(httpEerr_)
						except requests.exceptions.ConnectionError as cnEerr_:
							super().HandleGLobalException(cnEerr_)
						except requests.exceptions.Timeout as toEerr_:
							super().HandleGLobalException(toEerr_)
						except requests.exceptions.RequestException as reqEx_:
							super().HandleGLobalException(reqEx_)
						except Exception as _exInst:
							super().HandleGLobalException(_exInst)
						#
						if	currentTry_ProcessResult	==	True:
							break
						else:
							time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
							continue
						#
					# end for currentTry
					#
				# end WindowsDefenderRunAntiVirusScan == True
			#
			# @xxxxxxxx][==============================================================>
			#
			if	'WindowsDefenderIsolateComputer'	in	ComputerRemediationActionsAsDict:
				if	bool(ComputerRemediationActionsAsDict['WindowsDefenderIsolateComputer'])	==	True:
					#
					for currentTry in range(super()._maxRetries):
					#
						#
						currentTry_ProcessResult	=	False
						#
						try:
							#
							_DefenderForEndpointsAPIToken = super().GetAccessTokenForSPNbyCertAuthenticationThroughPost(																								\
																																_SPN_ApplicationId		=	super().CoalesceEmptyNorNoneThenNone(ServiceApplicationId)	\
																															,	_TenantId				=	super().CoalesceEmptyNorNoneThenNone(TenantId)				\
																															,	_P12certBytes			=	ServiceApplicationP12bytes									\
																															,	_P12certKy				=	ServiceAppP12Kbytes											\
																															,	_ScopeAudienceDomain	=	super().CoalesceEmptyNorNoneThenNone(ScopeAudienceDomain)	\
																														)
							if		_DefenderForEndpointsAPIToken			!=	None	\
								and	len(_DefenderForEndpointsAPIToken)	>	0:
								#
								#
								WindowsDefenderToInvokeComputerIsolationAPIurl	=		super().CoalesceEmptyNorNoneThenNone(WindowsDefenderHostAPIurl)		\
																					+	'/api/machines/'													\
																					+	super().CoalesceEmptyNorNoneThenNone(machineId)						\
																					+	'/isolate'
								#
								WindowsDefenderToInvokeComputerIsolation_POST_Body	=	{
																								'Comment'		:	'Invoke Computer Isolation by Defender Alert id : [{AlertId}]'.format(AlertId = super().CoalesceEmptyNorNoneThenNone(id))
																							,	'IsolationType'	:	'Full'
																						}
								#
								HeadersV1					=	{
																		'Authorization'					:		'Bearer {TokenJWT}'.format(TokenJWT = _DefenderForEndpointsAPIToken['access_token'])
																	,	'Content-Type'					:		'application/json; charset=utf-8'
																}
								#
								InvokeWindowsDefenderToInvokeComputerIsolationResponse	=	requests.post(																							\
																												url				=	WindowsDefenderToInvokeComputerIsolationAPIurl					\
																											,	json			=	WindowsDefenderToInvokeComputerIsolation_POST_Body				\
																											,	data			=	json.dumps(WindowsDefenderToInvokeComputerIsolation_POST_Body)	\
																											,	headers			=	HeadersV1														\
																											,	timeout			=	_TimeOutInSeconds												\
																										)
								#
								if	not	InvokeWindowsDefenderToInvokeComputerIsolationResponse is None:
									### ref : https://developer.mozilla.org/en-US/docs/Web/HTTP/Status#successful_responses
									if		InvokeWindowsDefenderToInvokeComputerIsolationResponse.status_code >= int(200)	\
										and InvokeWindowsDefenderToInvokeComputerIsolationResponse.status_code <= int(299):
										#
										newRowAsDict	=	{}
										newRowAsDict	=	{
																	'RemediationTypeName'			:	'WindowsDefenderIsolateComputer'
																,	'ExecutionSuccessfulResult'		:	True
																,	'RemediationCode'				:	InvokeWindowsDefenderToInvokeComputerIsolationResponse.status_code
																,	'id'							:	super().CoalesceEmptyNorNoneThenNone(id)
																,	'machineId'						:	super().CoalesceEmptyNorNoneThenNone(machineId)
																,	'computerDnsName'				:	super().CoalesceEmptyNorNoneThenNone(computerDnsName)
																,	'RemediationResponseAsString'	:	InvokeWindowsDefenderToInvokeComputerIsolationResponse.text
															}
										#
										returnActionsResultsAsPDF	=	pandas.concat([returnActionsResultsAsPDF, pandas.DataFrame([newRowAsDict])], ignore_index = True, verify_integrity = False, sort = False)
										#
										currentTry_ProcessResult	=	True
										break
										#
									else:
										super().HandleGLobalPostRequestError(																					\
																					_reason			=	InvokeWindowsDefenderToInvokeComputerIsolationResponse.reason				\
																				,	_status_code	=	int(InvokeWindowsDefenderToInvokeComputerIsolationResponse.status_code)		\
																				,	_text			=	InvokeWindowsDefenderToInvokeComputerIsolationResponse.text					\
																				,	_content		=	InvokeWindowsDefenderToInvokeComputerIsolationResponse.content				\
																			)
								#
								#
						except requests.exceptions.HTTPError as httpEerr_:
							super().HandleGLobalException(httpEerr_)
						except requests.exceptions.ConnectionError as cnEerr_:
							super().HandleGLobalException(cnEerr_)
						except requests.exceptions.Timeout as toEerr_:
							super().HandleGLobalException(toEerr_)
						except requests.exceptions.RequestException as reqEx_:
							super().HandleGLobalException(reqEx_)
						except Exception as _exInst:
							super().HandleGLobalException(_exInst)
						#
						if	currentTry_ProcessResult	==	True:
							break
						else:
							time.sleep(int(super()._sleepTimeAsMiliseconds/1000))
							continue
						#
					# end for currentTry
					#
				# end WindowsDefenderIsolateComputer == True
			#
			# @xxxxxxxx][==============================================================>
			#
			#
			# @xxxxxxxx][==============================================================>
			#
			#
			# @xxxxxxxx][==============================================================>
			#
			#
		#
		return returnActionsResultsAsPDF
		#

	# end class DefenderForEndpointsProcessor
	# • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • • •



# In[ ]:
