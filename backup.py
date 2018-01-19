#!/usr/bin/env python3

import time
import sys
import sched
import os
import pwd
import configparser
import shlex

from daemon import Daemon
from borg import Borg

import gi
gi.require_version('Notify', '0.7')
gi.require_version('Gtk', '3.0')
from gi.repository import Notify, Gtk

import logging
from logging.handlers import RotatingFileHandler

# default values
configfile	= 'config.ini'
pidfile		= '/tmp/' + pwd.getpwuid(os.getuid())[0] + '-borg.pid'
logfile		= 'borg-backup.log'
logcount	= 5				# how many logs to keep by default
logsize		= 100 * 1024	# max. size per log file
loglevel	= 'info'

NOTIFICATION_TITLE = 'BorgBackup Progress'


def closed(notify_object):
	global running
	print("closed")

	notify_object.close()
	running = False

def click(notify_object, name, data, what):
	global running
	print("clicked")
	import tkinter as tk
	import tkinter.scrolledtext as tkst
	root = tk.Tk()
	T = tkst.ScrolledText(root, height=30, width=100)
	T.pack(fill='both', expand='yes')
	T.insert(tk.END, data)
	tk.mainloop()

	notify_object.close()
	running = False



class BorgDaemon(Daemon):

	@staticmethod
	def json_callback(obj, cmd, self):
		msg = ''
		if obj['type'] == 'archive_progress':
			msg = "Files processed: {}".format(obj['nfiles'])
			self.logger.debug(msg)

			self.notification.update(NOTIFICATION_TITLE, msg, 'process-working-symbolic')
			self.notification.show()

		elif obj['type'] == 'log_message' and obj['name'] != 'borg.output.progress':
			msg = obj['message'].strip()
			self.logger.info(msg)

		if msg:
			self.log += msg + "\n"


	def run(self):
		self.config = configparser.ConfigParser(
									interpolation=configparser.ExtendedInterpolation(),
									inline_comment_prefixes=('#', ','))
		self.config.read(configfile)


		log_count = self.config['Common'].getint('log-count', logcount)
		log_size = self.config['Common'].getint('log-size', logsize)
		log_level = self.config['Common'].get('log-level', loglevel)
		log_file = os.path.expanduser(self.config['Common'].get('log-file', logfile))

		log_formatter = logging.Formatter("%(asctime)s [%(levelname)-5.5s]  %(message)s", "%Y-%m-%d %H:%M:%S")

		log_file_handler = RotatingFileHandler(log_file, maxBytes=log_size, backupCount=log_count)
		log_file_handler.setFormatter(log_formatter)

		log_console_handler = logging.StreamHandler()
		log_console_handler.setFormatter(log_formatter)

		self.logger = logging.getLogger("borg")
		self.logger.addHandler(log_file_handler)
		self.logger.addHandler(log_console_handler)

		# parse and set log level
		level = logging.getLevelName(log_level.upper())
		if isinstance(level, int):
			self.logger.setLevel(level)
		else:
			self.logger.setLevel(logging.INFO)


		Notify.init("BorgBackup")

		self.notifications = []
		self.log = {}

		# instantiate our borg wrapper
		self.borg = Borg(self.logger, self.json_callback, self)

		# setup schedule that will regularily execute backups
		self.sched = sched.scheduler()

		# extract all sections beginning with 'repo-'
		self.repos = [self.config[repo] for repo in self.config.sections() if repo.startswith('repo-')]

		for repo in self.repos:
			# schedule backups now, will reschedule itself
			self.handle_repo(repo)

		while True:
			Gtk.main_iteration_do(False)
			self.sched.run(blocking=False)

			time.sleep(1)


	"""Check if a something is an absolute filesystem path and available"""
	def path_available(self, path):
		import os

		if not path:
			return False

		path_exp = os.path.expanduser(path)
		if os.path.isabs(path_exp):
			# not an SSH target
			if not os.path.isdir(path_exp):
				return False

		return True


	def handle_repo(self, repo):
		# if everything goes well, next backup will be in ...
		next = repo.getint('frequency')

		class NotFoundException(Exception): pass
		class TemporarilyNotAvailableException(Exception): pass
		class OperationFailedException(Exception): pass

		try:
			if not self.path_available(repo['repo']):
				if repo.getboolean('wait-repo', False):
					raise TemporarilyNotAvailableException('Repo {} not yet available'.format(repo['repo']))
				else:
					raise NotFoundException('Repo {} not found'.format(repo['repo']))

			for path in repo['paths'].split('\n'):
				if not path: continue
				if not self.path_available(path):
					if repo.getboolean('wait-paths', False):
						raise TemporarilyNotAvailableException('Path {} not yet available'.format(path))
					else:
						raise NotFoundException('Path {} not found'.format(path))


			if not self.backup(repo):
				raise OperationFailedException('Backup of {} failed'.format(repo['repo']))

			if not self.prune(repo):
				raise OperationFailedException('Pruning of {} failed'.format(repo['repo']))


		except TemporarilyNotAvailableException as e:
			# retry faster, we expect this to happen
			next = repo.getint('retry-frequency')
			# only log at level DEBUG to prevent spamming the log
			self.logger.debug(e)

			self.logger.warning('Repo {} will be retried shortly'.format(repo['repo']))

		except NotFoundException as e:
			self.logger.critical(e)

		except OperationFailedException as e:
			self.logger.error(e)

		finally:
			self.logger.debug('Next backup of {} in {} minutes'.format(repo['repo'], next))
			self.sched.enter(next * 60, 0, self.handle_repo, [repo])


	def prune(self, repo):
		self.logger.info("Pruning {}".format(repo['repo']))
		return self.borg.prune(repo)


	def backup(self, repo):
		self.logger.info("Create backup for {}".format(repo['repo']))

		self.notification = Notify.Notification.new(NOTIFICATION_TITLE, "Starting backup for {}".format(repo['repo']), 'process-working-symbolic')
		self.notification.set_timeout(2000)
		self.notification.show()

		self.log = ''

		self.borg.create(repo)

		self.notification.close()

		notification_done = Notify.Notification.new(NOTIFICATION_TITLE, "Done", 'security-high-symbolic')
		notification_done.add_action('default', 'More info', click, self.log, None)
		notification_done.connect("closed", closed)
		notification_done.set_timeout(10 * 1000)
		notification_done.show()

		self.notifications.append(notification_done)

		return True



if __name__ == "__main__":

	daemon = BorgDaemon(pidfile)

	if len(sys.argv) == 2:
		if 'start' == sys.argv[1]:
			daemon.start()
		elif 'stop' == sys.argv[1]:
			daemon.stop()
		elif 'restart' == sys.argv[1]:
			daemon.restart()
		elif 'status' == sys.argv[1]:
			daemon.status()
		else:
			print("Unknown command")
			sys.exit(2)
		sys.exit(0)
	else:
		print("usage: %s start|stop|restart" % sys.argv[0])
		sys.exit(2)
