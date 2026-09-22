#!/usr/bin/env python3
"""
AnyRouter.top 自动签到脚本
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv
from playwright.async_api import async_playwright

from utils.config import AccountConfig, AppConfig, load_accounts_config
from utils.notify import notify

load_dotenv()

BALANCE_HASH_FILE = 'balance_hash.txt'

USER_AGENT = (
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
	'(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36'
)

# 从浏览器里收集 WAF cookie 时要排除的登录态 cookie，
# 避免把上一个会话的身份带进本次请求
AUTH_COOKIE_NAMES = {'session'}


def load_balance_hash():
	"""加载余额hash"""
	try:
		if os.path.exists(BALANCE_HASH_FILE):
			with open(BALANCE_HASH_FILE, 'r', encoding='utf-8') as f:
				return f.read().strip()
	except Exception:  # nosec B110
		pass
	return None


def save_balance_hash(balance_hash):
	"""保存余额hash"""
	try:
		with open(BALANCE_HASH_FILE, 'w', encoding='utf-8') as f:
			f.write(balance_hash)
	except Exception as e:
		print(f'Warning: Failed to save balance hash: {e}')


def generate_balance_hash(balances):
	"""生成余额数据的hash"""
	# 将包含 quota 和 used 的结构转换为简单的 quota 值用于 hash 计算
	simple_balances = {k: v['quota'] for k, v in balances.items()} if balances else {}
	balance_json = json.dumps(simple_balances, sort_keys=True, separators=(',', ':'))
	return hashlib.sha256(balance_json.encode('utf-8')).hexdigest()[:16]


def parse_cookies(cookies_data):
	"""解析 cookies 数据"""
	if isinstance(cookies_data, dict):
		return cookies_data

	if isinstance(cookies_data, str):
		cookies_dict = {}
		for cookie in cookies_data.split(';'):
			if '=' in cookie:
				key, value = cookie.strip().split('=', 1)
				cookies_dict[key] = value
		return cookies_dict
	return {}


async def get_waf_cookies_with_playwright(account_name: str, login_url: str, required_cookies: list[str]):
	"""使用 Playwright 获取 WAF cookies（隐私模式）"""
	print(f'[PROCESSING] {account_name}: Starting browser to get WAF cookies...')

	async with async_playwright() as p:
		import tempfile

		with tempfile.TemporaryDirectory() as temp_dir:
			context = await p.chromium.launch_persistent_context(
				user_data_dir=temp_dir,
				headless=False,
				user_agent=USER_AGENT,
				viewport={'width': 1920, 'height': 1080},
				args=[
					'--disable-blink-features=AutomationControlled',
					'--disable-dev-shm-usage',
					'--disable-web-security',
					'--disable-features=VizDisplayCompositor',
					'--no-sandbox',
				],
			)

			page = await context.new_page()

			try:
				print(f'[PROCESSING] {account_name}: Access login page to get initial cookies...')

				await page.goto(login_url, wait_until='networkidle')

				try:
					await page.wait_for_function('document.readyState === "complete"', timeout=5000)
				except Exception:
					await page.wait_for_timeout(3000)

				cookies = await page.context.cookies()

				# 收集该域名下 WAF 下发的全部 cookie（登录态除外）。
				# 不能只按固定清单取：不同出口 IP 触发的挑战不同——普通 IP 只发
				# acw_tc，被判定为风险 IP（如 CI 机房 IP）时会追加 acw_sc__v2
				# 这类 JS 挑战 cookie（浏览器已解开），漏掉它请求就会被打回挑战页。
				host = urlparse(login_url).hostname or ''
				waf_cookies = {}
				for cookie in cookies:
					cookie_name = cookie.get('name')
					cookie_value = cookie.get('value')
					cookie_domain = (cookie.get('domain') or '').lstrip('.')
					if cookie_value is None or cookie_name in AUTH_COOKIE_NAMES:
						continue
					if cookie_domain and not (host == cookie_domain or host.endswith(f'.{cookie_domain}')):
						continue
					waf_cookies[cookie_name] = cookie_value

				print(f'[INFO] {account_name}: Got {len(waf_cookies)} WAF cookies: {sorted(waf_cookies)}')

				missing_cookies = [c for c in required_cookies if c not in waf_cookies]

				if missing_cookies:
					print(f'[FAILED] {account_name}: Missing WAF cookies: {missing_cookies}')
					await context.close()
					return None

				print(f'[SUCCESS] {account_name}: Successfully got all WAF cookies')

				await context.close()

				return waf_cookies

			except Exception as e:
				print(f'[FAILED] {account_name}: Error occurred while getting WAF cookies: {e}')
				await context.close()
				return None


def get_user_info(client, headers, user_info_url: str):
	"""获取用户信息"""
	try:
		response = client.get(user_info_url, headers=headers, timeout=30)

		if response.status_code == 200:
			data = response.json()
			if data.get('success'):
				user_data = data.get('data', {})
				quota = round(user_data.get('quota', 0) / 500000, 2)
				used_quota = round(user_data.get('used_quota', 0) / 500000, 2)
				return {
					'success': True,
					'quota': quota,
					'used_quota': used_quota,
					'display': f':money: Current balance: ${quota}, Used: ${used_quota}',
				}
		return {'success': False, 'error': f'Failed to get user info: HTTP {response.status_code}'}
	except Exception as e:
		return {'success': False, 'error': f'Failed to get user info: {str(e)[:50]}...'}


async def prepare_cookies(account_name: str, provider_config, user_cookies: dict) -> dict | None:
	"""准备请求所需的 cookies（可能包含 WAF cookies）"""
	waf_cookies = {}

	if provider_config.needs_waf_cookies():
		login_url = f'{provider_config.domain}{provider_config.login_path}'
		waf_cookies = await get_waf_cookies_with_playwright(account_name, login_url, provider_config.waf_cookie_names)
		if not waf_cookies:
			print(f'[FAILED] {account_name}: Unable to get WAF cookies')
			return None
	else:
		print(f'[INFO] {account_name}: Bypass WAF not required, using user cookies directly')

	return {**waf_cookies, **user_cookies}


def execute_check_in(client, account_name: str, provider_config, headers: dict):
	"""执行签到请求"""
	print(f'[NETWORK] {account_name}: Executing check-in')

	checkin_headers = headers.copy()
	checkin_headers.update({'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})

	sign_in_url = f'{provider_config.domain}{provider_config.sign_in_path}'
	response = client.post(sign_in_url, headers=checkin_headers, timeout=30)

	print(f'[RESPONSE] {account_name}: Response status code {response.status_code}')

	if response.status_code == 200:
		try:
			result = response.json()
			if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
				print(f'[SUCCESS] {account_name}: Check-in successful!')
				return True
			else:
				error_msg = result.get('msg', result.get('message', 'Unknown error'))
				# 检查是否是"已经签到过"的情况，这种情况也算成功
				already_checked_keywords = ['已经签到', '已签到', '重复签到', 'already checked', 'already signed']
				if any(keyword in error_msg.lower() for keyword in already_checked_keywords):
					print(f'[SUCCESS] {account_name}: Already checked in today')
					return True
				print(f'[FAILED] {account_name}: Check-in failed - {error_msg}')
				return False
		except json.JSONDecodeError:
			# 如果不是 JSON 响应，检查是否包含成功标识
			if 'success' in response.text.lower():
				print(f'[SUCCESS] {account_name}: Check-in successful!')
				return True
			else:
				print(f'[FAILED] {account_name}: Check-in failed - Invalid response format')
				return False
	else:
		print(f'[FAILED] {account_name}: Check-in failed - HTTP {response.status_code}')
		return False


def login_with_credentials(
	client: httpx.Client, account_name: str, provider_config, username: str, password: str
) -> dict:
	"""使用账号密码登录，以触发该平台的「每日登录发放额度」

	部分平台（如 AgentRouter）没有签到接口，签到奖励在登录动作中发放。
	响应体的 data.checked_in 是「今日是否已签到」的状态标记——注意它无法区分
	是本脚本还是用户浏览器登录触发的，因此只用于判断今日签到状态。

	登录成功后会话 Cookie 由 httpx 自动写入 client.cookies，供后续请求复用。

	Returns:
		成功时 {'success': True, 'checked_in': bool}，失败时 {'success': False, 'error': str}
	"""
	print(f'[NETWORK] {account_name}: Logging in to trigger check-in')

	login_url = f'{provider_config.domain}{provider_config.login_api_path}'
	headers = {
		'User-Agent': USER_AGENT,
		'Content-Type': 'application/json',
		'Accept': 'application/json, text/plain, */*',
		'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
		'Referer': f'{provider_config.domain}{provider_config.login_path}',
		'Origin': provider_config.domain,
	}

	try:
		response = client.post(
			login_url, headers=headers, json={'username': username, 'password': password}, timeout=30
		)
	except Exception as e:
		return {'success': False, 'error': f'Login request failed: {str(e)[:50]}...'}

	print(f'[RESPONSE] {account_name}: Login response status code {response.status_code}')

	if response.status_code != 200:
		return {'success': False, 'error': f'Login failed: HTTP {response.status_code}'}

	try:
		result = response.json()
	except json.JSONDecodeError:
		# 把响应片段带出来，否则无法区分「被 WAF 打回挑战页」和「接口变了」
		snippet = ' '.join(response.text[:300].split())
		if 'arg1=' in snippet or 'acw_sc__v2' in snippet:
			return {'success': False, 'error': 'Login blocked by WAF JS challenge (WAF cookies insufficient)'}
		return {'success': False, 'error': f'Login failed: non-JSON response: {snippet[:120]}'}

	if not result.get('success'):
		return {'success': False, 'error': result.get('message', 'Login failed')}

	data = result.get('data') or {}

	# 该字段并非所有平台都有：AgentRouter 用它表示「今日已签到」，
	# AnyRouter 的登录响应里根本没有它（其签到靠独立的 sign_in 接口），故用 None 表示未知
	raw_checked_in = data.get('checked_in')
	checked_in = None if raw_checked_in is None else bool(raw_checked_in)

	if checked_in is True:
		print(f'[SUCCESS] {account_name}: Logged in, today is checked in')
	elif checked_in is False:
		print(f'[WARNING] {account_name}: Logged in, but today is NOT checked in yet')
	else:
		print(f'[SUCCESS] {account_name}: Logged in')

	# 登录响应里的 id 即 New-Api-User 头的取值，可用于省去手填 api_user
	return {'success': True, 'checked_in': checked_in, 'user_id': data.get('id')}


def format_check_in_notification(detail: dict) -> str:
	"""格式化签到通知消息

	Args:
		detail: 包含签到详情的字典

	Returns:
		格式化后的通知消息
	"""
	parts = [f'【{detail["name"]}】', f'💵 当前余额: ${detail["after_quota"]:.2f}']

	check_in_reward = detail.get('check_in_reward')
	usage_increase = detail.get('usage_increase')
	balance_change = detail.get('balance_change')

	# 取不到签到前余额时（如仅有账号密码、无法预先查询的平台），退化为只报告签到状态
	if check_in_reward is None or usage_increase is None or balance_change is None:
		checked_in = detail.get('checked_in')
		if checked_in is True:
			parts.append('✅ 今日已签到')
		elif checked_in is False:
			parts.append('⚠️ 已登录但今日未签到')
		else:
			parts.append('ℹ️ 未取到签到前余额，无法计算收益')
		return ' '.join(parts)

	# 判断是否有变化
	has_reward = check_in_reward != 0
	has_usage = usage_increase != 0

	if has_reward:
		parts.append(f'🎁 签到获得: +${check_in_reward:.2f}')

	if has_usage:
		parts.append(f'📉 期间消耗: ${usage_increase:.2f}')

	if balance_change != 0 and not has_reward:
		change_symbol = '+' if balance_change > 0 else ''
		change_emoji = '📈' if balance_change > 0 else '📉'
		parts.append(f'{change_emoji} 余额变化: {change_symbol}${balance_change:.2f}')

	if not has_reward and not has_usage:
		parts.append('ℹ️ 今日已签到，无变化')

	return ' '.join(parts)


async def check_in_account(account: AccountConfig, account_index: int, app_config: AppConfig):
	"""为单个账号执行签到操作"""
	account_name = account.get_display_name(account_index)
	print(f'\n[PROCESSING] Starting to process {account_name}')

	provider_config = app_config.get_provider(account.provider)
	if not provider_config:
		print(f'[FAILED] {account_name}: Provider "{account.provider}" not found in configuration')
		return False, None, None

	print(f'[INFO] {account_name}: Using provider "{account.provider}" ({provider_config.domain})')

	user_cookies = parse_cookies(account.cookies)
	if not user_cookies and not account.has_credentials():
		print(f'[FAILED] {account_name}: Invalid configuration format')
		return False, None, None

	all_cookies = await prepare_cookies(account_name, provider_config, user_cookies)
	if not all_cookies:
		return False, None, None

	client = httpx.Client(http2=True, timeout=30.0)

	try:
		client.cookies.update(all_cookies)

		headers = {
			'User-Agent': USER_AGENT,
			'Accept': 'application/json, text/plain, */*',
			'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
			'Accept-Encoding': 'gzip, deflate, br, zstd',
			'Referer': provider_config.domain,
			'Origin': provider_config.domain,
			'Connection': 'keep-alive',
			'Sec-Fetch-Dest': 'empty',
			'Sec-Fetch-Mode': 'cors',
			'Sec-Fetch-Site': 'same-origin',
			provider_config.api_user_key: account.api_user,
		}

		user_info_url = f'{provider_config.domain}{provider_config.user_info_path}'

		# 只配了账号密码、没有 cookies 时，登录前读不到余额，跳过以免打印误导性报错
		user_info_before = None
		if user_cookies:
			user_info_before = get_user_info(client, headers, user_info_url)
			if user_info_before and user_info_before.get('success'):
				print(user_info_before['display'])
			elif user_info_before:
				print(user_info_before.get('error', 'Unknown error'))

		checked_in = None

		# 配了账号密码就先用登录换一个新会话，顺带解决 session 频繁过期的问题
		if provider_config.needs_login() and account.has_credentials():
			login_result = login_with_credentials(
				client, account_name, provider_config, account.username, account.password
			)
			if login_result.get('success'):
				checked_in = login_result.get('checked_in')

				# 未配置 api_user 时，用登录响应里的用户 ID 补上（该请求头必填）
				if not account.api_user and login_result.get('user_id'):
					headers[provider_config.api_user_key] = str(login_result['user_id'])
					print(f'[INFO] {account_name}: Derived {provider_config.api_user_key} from login response')

				# 没有独立签到接口的平台，登录动作本身就是签到（如 AgentRouter）。
				# 签到在登录那一瞬间就完成了，因此取不到「签到前」的余额
				if not provider_config.needs_manual_check_in():
					user_info_after = get_user_info(client, headers, user_info_url)
					if user_info_after and checked_in is not None:
						user_info_after['checked_in'] = checked_in
					return True, user_info_before, user_info_after

				# 有独立签到接口的平台（如 AnyRouter）：此刻已登录、尚未签到，
				# 若先前用旧 cookies 没取到余额，这是拿「签到前」基准值的最后机会
				if not (user_info_before and user_info_before.get('success')):
					user_info_before = get_user_info(client, headers, user_info_url)
					if user_info_before and user_info_before.get('success'):
						print(user_info_before['display'])

			else:
				print(f'[WARNING] {account_name}: Login failed - {login_result.get("error")}')
				# 登录是唯一签到途径、或根本没有可用 cookies 时，只能判失败
				if provider_config.needs_login_check_in() or not user_cookies:
					print(f'[FAILED] {account_name}: Check-in requires a successful login')
					return False, user_info_before, None
				print(f'[INFO] {account_name}: Falling back to the configured cookies')

		elif provider_config.needs_login_check_in():
			# 只能靠登录触发签到的平台，缺账号密码就无从执行
			print(
				f'[FAILED] {account_name}: Provider "{account.provider}" requires '
				'"username" and "password" in the account configuration'
			)
			return False, user_info_before, None

		if provider_config.needs_manual_check_in():
			# 登录后 client.cookies 已是新会话（或沿用原 cookies），在此之上调用签到接口
			success = execute_check_in(client, account_name, provider_config, headers)
			# 签到后再次获取用户信息，用于计算签到收益
			user_info_after = get_user_info(client, headers, user_info_url)
			if user_info_after and checked_in is not None:
				user_info_after['checked_in'] = checked_in
			return success, user_info_before, user_info_after
		else:
			print(f'[INFO] {account_name}: Check-in completed automatically (triggered by user info request)')
			# 自动签到的情况，再次获取用户信息
			user_info_after = get_user_info(client, headers, user_info_url)
			# 成功状态应取决于用户信息获取是否成功
			success = user_info_after.get('success', False) if user_info_after else False
			return success, user_info_before, user_info_after

	except Exception as e:
		print(f'[FAILED] {account_name}: Error occurred during check-in process - {str(e)[:50]}...')
		return False, None, None
	finally:
		client.close()


async def main():
	"""主函数"""
	print('[SYSTEM] AnyRouter.top multi-account auto check-in script started (using Playwright)')
	print(f'[TIME] Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

	app_config = AppConfig.load_from_env()
	print(f'[INFO] Loaded {len(app_config.providers)} provider configuration(s)')

	accounts = load_accounts_config()
	if not accounts:
		print('[FAILED] Unable to load account configuration, program exits')
		sys.exit(1)

	print(f'[INFO] Found {len(accounts)} account configurations')

	last_balance_hash = load_balance_hash()

	success_count = 0
	total_count = len(accounts)
	notification_content = []
	current_balances = {}
	account_check_in_details = {}  # 存储每个账号的签到详情
	need_notify = False  # 是否需要发送通知
	balance_changed = False  # 余额是否有变化

	for i, account in enumerate(accounts):
		account_key = f'account_{i + 1}'
		try:
			success, user_info_before, user_info_after = await check_in_account(account, i, app_config)
			if success:
				success_count += 1

			should_notify_this_account = False

			if not success:
				should_notify_this_account = True
				need_notify = True
				account_name = account.get_display_name(i)
				print(f'[NOTIFY] {account_name} failed, will send notification')

			# 存储签到前后的余额信息
			if user_info_after and user_info_after.get('success'):
				after_quota = user_info_after['quota']
				after_used = user_info_after['used_quota']
				current_balances[account_key] = {'quota': after_quota, 'used': after_used}

				# 计算签到收益；取不到签到前余额时（如仅有账号密码的平台）留空
				if user_info_before and user_info_before.get('success'):
					before_quota = user_info_before['quota']
					before_used = user_info_before['used_quota']

					# 总额度 = 余额 + 历史消耗，其增量即签到获得的额度
					check_in_reward = (after_quota + after_used) - (before_quota + before_used)
					# 本次消耗 = 历史消耗增加量
					usage_increase = after_used - before_used
					# 余额变化
					balance_change = after_quota - before_quota
				else:
					before_quota = before_used = None
					check_in_reward = usage_increase = balance_change = None

				account_check_in_details[account_key] = {
					'name': account.get_display_name(i),
					'before_quota': before_quota,
					'before_used': before_used,
					'after_quota': after_quota,
					'after_used': after_used,
					'check_in_reward': check_in_reward,  # 签到获得
					'usage_increase': usage_increase,  # 本次消耗
					'balance_change': balance_change,  # 余额变化
					'checked_in': user_info_after.get('checked_in'),  # 登录触发签到时为 True
					'success': success,
				}

			if should_notify_this_account:
				account_name = account.get_display_name(i)
				status = '[SUCCESS]' if success else '[FAIL]'
				account_result = f'【{account_name}】 {status}'
				if user_info_after and user_info_after.get('success'):
					account_result += f'\n{user_info_after["display"]}'
				elif user_info_after:
					account_result += f'\n{user_info_after.get("error", "Unknown error")}'
				notification_content.append(account_result)

		except Exception as e:
			account_name = account.get_display_name(i)
			print(f'[FAILED] {account_name} processing exception: {e}')
			need_notify = True  # 异常也需要通知
			notification_content.append(f'【{account_name}】 [FAIL] exception: {str(e)[:50]}...')

	# 检查余额变化
	current_balance_hash = generate_balance_hash(current_balances) if current_balances else None
	if current_balance_hash:
		if last_balance_hash is None:
			# 首次运行
			balance_changed = True
			need_notify = True
			print('[NOTIFY] First run detected, will send notification with current balances')
		elif current_balance_hash != last_balance_hash:
			# 余额有变化
			balance_changed = True
			need_notify = True
			print('[NOTIFY] Balance changes detected, will send notification')
		else:
			print('[INFO] No balance changes detected')

	# 将所有账号详情添加到通知内容
	for i, account in enumerate(accounts):
			account_key = f'account_{i + 1}'
			if account_key in account_check_in_details:
				detail = account_check_in_details[account_key]
				account_name = detail['name']

				# 使用格式化函数生成通知消息
				account_result = format_check_in_notification(detail)

				# 检查是否已经在通知内容中（避免重复）
				if not any(account_name in item for item in notification_content):
					notification_content.append(account_result)
			else:
				# 如果没有对比详情（例如第一次查询失败），但账号执行过了，添加基础信息
				account_name = account.get_display_name(i)
				if not any(account_name in item for item in notification_content):
					status = '[SUCCESS]' # 既然走到了这里且不在 notification_content 中，说明主循环没报错
					notification_content.append(f'【{account_name}】 {status} (无变化详情)')

	# 保存当前余额hash
	if current_balance_hash:
		save_balance_hash(current_balance_hash)

	if notification_content:
		# 构建通知标题
		notify_title = 'AnyRouter签到'
		
		# 合并通知内容
		notify_content = '\n'.join(notification_content)

		print(f'[NOTIFY] Title: {notify_title}')
		print(notify_content)
		notify.push_message(notify_title, notify_content, msg_type='text')
		print('[NOTIFY] Notification sent successfully')
	else:
		print('[WARNING] No notification content to send')

	# 设置退出码
	sys.exit(0 if success_count > 0 else 1)


def run_main():
	"""运行主函数的包装函数"""
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		print('\n[WARNING] Program interrupted by user')
		sys.exit(1)
	except Exception as e:
		print(f'\n[FAILED] Error occurred during program execution: {e}')
		sys.exit(1)


if __name__ == '__main__':
	run_main()
