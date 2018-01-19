Borg Desktop Daemon
===================

This tool was initially designed for use cases where a simple cron job is not
suitable. This most importantly includes running a regular backup on a laptop
computer, where a fixed schedule doesn't make sense.

This is still work-in-progress!

## Features

 * configuration with config file support
 * logging to file + rotation
 * notifications via libnotify (currently only tested on GNOME)


## Usage

Adapt `config.ini` according to your needs, then you can run it with
`./backup.py start`.

