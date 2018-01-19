#!/usr/bin/env python3

import os
import json
import shlex
import logging
from subprocess import Popen, PIPE, check_output

def _json_callback(obj, cmd, arg):
	if obj['type'] == 'archive_progress':
		print('Files processed: {}'.format(obj['nfiles']))
		#notification.update(NOTIFICATION_TITLE, "Files processed: {}".format(obj['nfiles']), 'process-working-symbolic')
		#notification.set_urgency(Notify.Urgency.LOW)
		#notification.show()

	elif obj['type'] == 'progress_message' and obj['msgid'] == 'cache.commit' and obj['finished'] == True:
		pass

	elif obj['type'] == 'log_message':
		print('Borg: {}'.format(obj['message']))

	elif obj['type'] == 'done':
		print("Done: {}".format(obj['return']))


class Borg:
	def __init__(self, logger = None, json_callback=_json_callback, callback_arg=None):
		self.json_callback = json_callback
		self.callback_arg = callback_arg

		if logger:
			self.logger = logger
		else:
			self.logger = logging.getLogger('borg')
			self.logger.setLevel(logging.INFO)


	def run_cmd(self, cmd, env):

		# log the command that will be run, filter out plaintext passphrase for
		# security reasons
		self.logger.debug('Run Command: {env} {cmd}'.format(
				env=' '.join([k+'='+v for k,v in env.items() if not 'PASSPHRASE' in k]),
				cmd=' '.join(cmd)))

		proc = Popen(cmd, env=env, stderr=PIPE)

		done = False
		log = ""

		line = '...'
		while line:
			line = proc.stderr.readline().strip()

			if not line:
				continue

			try:
				obj = json.loads(line)
			except json.decoder.JSONDecodeError:
				self.logger.debug('skip line: {}'.format(line))
				continue

			self.json_callback(obj, cmd, self.callback_arg)

		rc = proc.wait()
		self.json_callback({'type': 'done', 'return': rc}, cmd, self.callback_arg)

		return rc


	def _common_cmd(self, repo):
		env = { 'BORG_REPO': os.path.expanduser(repo['repo']) }

		if repo.get('passcommand', None):
			passphrase = check_output(shlex.split(repo['passcommand']))
			env['BORG_PASSPHRASE'] = passphrase

		if repo.get('passphrase', None):
			env['BORG_PASSPHRASE'] = repo['passphrase']

		arguments = ['--log-json', '--progress']

		if repo.get('ratelimit', None):
			arguments += ['--remote-ratelimit', repo['ratelimit']]

		return (env, arguments)


	def _common_archive_name(self, repo):
		archive = '{hostname}-'
		prefix = repo.get('prefix', '')
		if prefix:
			archive += prefix + '-'

		return archive

	def prune(self, repo):
		cmd, env = self._prune_cmd(repo)
		return (self.run_cmd(cmd, env) == 0)

	def _prune_cmd(self, repo):
		env, arguments = self._common_cmd(repo)

		cmd = ['borg', 'prune', '--stats', '--prefix', self._common_archive_name(repo)]
		cmd += arguments

		for key in repo.keys():
			if not key.startswith('keep-') or not repo[key]:
				continue
			cmd += ['--' + key, repo[key]]

		return (cmd, env)


	def create(self, repo):
		cmd, env = self._create_cmd(repo)
		return (self.run_cmd(cmd, env) == 0)


	def _create_cmd(self, repo):
		env, arguments = self._common_cmd(repo)

		cmd = ['borg', 'create', '--stats']
		cmd += arguments

		if repo.get('compression', None):
			cmd += ['--compression', repo['compression']]

		if repo.get('exclude', None):
			for exclude in repo['exclude'].split('\n'):
				if not exclude: continue
				cmd += ['--exclude', os.path.expanduser(exclude)]

		cmd += ['::' + self._common_archive_name(repo) + '{now}']

		if repo.get('paths', None):
			for path in repo['paths'].strip().split('\n'):
				cmd += [os.path.expanduser(path)]
		else:
			raise Exception('No paths for repo {}'.format(repo['repo']))

		return (cmd, env)
