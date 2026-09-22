#!/usr/bin/env python3
"""
配置管理模块
"""

import json
import os
from dataclasses import dataclass
from typing import Dict, List, Literal


@dataclass
class ProviderConfig:
	"""Provider 配置"""

	name: str
	domain: str
	login_path: str = '/login'
	sign_in_path: str | None = '/api/user/sign_in'
	login_api_path: str | None = None
	user_info_path: str = '/api/user/self'
	api_user_key: str = 'new-api-user'
	bypass_method: Literal['waf_cookies'] | None = None
	waf_cookie_names: List[str] | None = None

	def __post_init__(self):
		required_waf_cookies = set()
		if self.waf_cookie_names and isinstance(self.waf_cookie_names, List):
			for item in self.waf_cookie_names:
				name = '' if not item or not isinstance(item, str) else item.strip()
				if not name:
					print(f'[WARNING] Found invalid WAF cookie name: {item}')
					continue

				required_waf_cookies.add(name)

		if not required_waf_cookies:
			self.bypass_method = None

		self.waf_cookie_names = list(required_waf_cookies)

	@classmethod
	def from_dict(cls, name: str, data: dict) -> 'ProviderConfig':
		"""从字典创建 ProviderConfig

		配置格式:
		- 基础: {"domain": "https://example.com"}
		- 完整: {"domain": "https://example.com", "login_path": "/login", "api_user_key": "x-api-user", "bypass_method": "waf_cookies", ...}
		"""
		return cls(
			name=name,
			domain=data['domain'],
			login_path=data.get('login_path', '/login'),
			sign_in_path=data.get('sign_in_path', '/api/user/sign_in'),
			login_api_path=data.get('login_api_path'),
			user_info_path=data.get('user_info_path', '/api/user/self'),
			api_user_key=data.get('api_user_key', 'new-api-user'),
			bypass_method=data.get('bypass_method'),
			waf_cookie_names=data.get('waf_cookie_names'),
		)

	def needs_waf_cookies(self) -> bool:
		"""判断是否需要获取 WAF cookies"""
		return self.bypass_method == 'waf_cookies'

	def needs_login(self) -> bool:
		"""判断是否需要先用账号密码登录换取会话（可替代易过期的 cookies）"""
		return self.login_api_path is not None

	def needs_login_check_in(self) -> bool:
		"""判断签到是否由登录动作**本身**完成（该站点没有独立的签到接口，如 AgentRouter）"""
		return self.login_api_path is not None and self.sign_in_path is None

	def needs_manual_check_in(self) -> bool:
		"""判断是否需要手动调用签到接口"""
		return self.sign_in_path is not None


@dataclass
class AppConfig:
	"""应用配置"""

	providers: Dict[str, ProviderConfig]

	@classmethod
	def load_from_env(cls) -> 'AppConfig':
		"""从环境变量加载配置"""
		providers = {
			'anyrouter': ProviderConfig(
				name='anyrouter',
				domain='https://anyrouter.top',
				login_path='/login',
				sign_in_path='/api/user/sign_in',
				# 配了账号密码时先用它换新会话，免去 session 频繁过期之扰；
				# 未配账号密码的账号不受影响，仍走原有的 cookies 方式
				login_api_path='/api/user/login',
				user_info_path='/api/user/self',
				api_user_key='new-api-user',
				bypass_method='waf_cookies',
				waf_cookie_names=['acw_tc', 'cdn_sec_tc', 'acw_sc__v2'],
			),
			'agentrouter': ProviderConfig(
				name='agentrouter',
				domain='https://agentrouter.org',
				login_path='/login',
				# AgentRouter 不存在 /api/user/sign_in（实测 404），
				# 其每日额度由「登录动作」发放，故签到改走登录接口
				sign_in_path=None,
				login_api_path='/api/user/login',
				user_info_path='/api/user/self',
				api_user_key='new-api-user',
				bypass_method='waf_cookies',
				waf_cookie_names=['acw_tc'],
			),
		}

		# 尝试从环境变量加载自定义 providers
		providers_str = os.getenv('PROVIDERS')
		if providers_str:
			try:
				providers_data = json.loads(providers_str)

				if not isinstance(providers_data, dict):
					print('[WARNING] PROVIDERS must be a JSON object, ignoring custom providers')
					return cls(providers=providers)

				# 解析自定义 providers,会覆盖默认配置
				for name, provider_data in providers_data.items():
					try:
						providers[name] = ProviderConfig.from_dict(name, provider_data)
					except Exception as e:
						print(f'[WARNING] Failed to parse provider "{name}": {e}, skipping')
						continue

				print(f'[INFO] Loaded {len(providers_data)} custom provider(s) from PROVIDERS environment variable')
			except json.JSONDecodeError as e:
				print(
					f'[WARNING] Failed to parse PROVIDERS environment variable: {e}, using default configuration only'
				)
			except Exception as e:
				print(f'[WARNING] Error loading PROVIDERS: {e}, using default configuration only')

		return cls(providers=providers)

	def get_provider(self, name: str) -> ProviderConfig | None:
		"""获取指定 provider 配置"""
		return self.providers.get(name)


@dataclass
class AccountConfig:
	"""账号配置"""

	cookies: dict | str
	api_user: str
	provider: str = 'anyrouter'
	name: str | None = None
	username: str | None = None
	password: str | None = None

	@classmethod
	def from_dict(cls, data: dict, index: int) -> 'AccountConfig':
		"""从字典创建 AccountConfig"""
		provider = data.get('provider', 'anyrouter')
		name = data.get('name', f'Account {index + 1}')

		return cls(
			cookies=data.get('cookies', ''),
			api_user=data.get('api_user', ''),
			provider=provider,
			name=name if name else None,
			username=data.get('username'),
			password=data.get('password'),
		)

	def has_credentials(self) -> bool:
		"""判断是否配置了账号密码（用于登录触发签到的平台）"""
		return bool(self.username and self.password)

	def get_display_name(self, index: int) -> str:
		"""获取显示名称"""
		return self.name if self.name else f'Account {index + 1}'


def load_accounts_config() -> list[AccountConfig] | None:
	"""从环境变量加载账号配置"""
	accounts_str = os.getenv('ANYROUTER_ACCOUNTS')
	if not accounts_str:
		print('ERROR: ANYROUTER_ACCOUNTS environment variable not found')
		return None

	try:
		accounts_data = json.loads(accounts_str)

		if not isinstance(accounts_data, list):
			print('ERROR: Account configuration must use array format [{}]')
			return None

		accounts = []
		for i, account_dict in enumerate(accounts_data):
			if not isinstance(account_dict, dict):
				print(f'ERROR: Account {i + 1} configuration format is incorrect')
				return None

			has_cookies = bool(account_dict.get('cookies'))
			has_credentials = bool(account_dict.get('username')) and bool(account_dict.get('password'))

			if not has_cookies and not has_credentials:
				print(f'ERROR: Account {i + 1} must provide either "cookies" or "username" + "password"')
				return None

			if bool(account_dict.get('username')) != bool(account_dict.get('password')):
				print(f'ERROR: Account {i + 1} "username" and "password" must be provided together')
				return None

			# 走 cookies 的账号必须显式给 api_user；走账号密码的可从登录响应里的用户 ID 推断
			if has_cookies and not account_dict.get('api_user'):
				print(f'ERROR: Account {i + 1} missing required field (api_user)')
				return None

			if 'name' in account_dict and not account_dict['name']:
				print(f'ERROR: Account {i + 1} name field cannot be empty')
				return None

			accounts.append(AccountConfig.from_dict(account_dict, i))

		return accounts
	except Exception as e:
		print(f'ERROR: Account configuration format is incorrect: {e}')
		return None
