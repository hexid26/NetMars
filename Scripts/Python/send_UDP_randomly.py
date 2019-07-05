#!/usr/bin/env python
# coding:utf-8
"""send_udp.py"""

import argparse
import logging
import random
import socket
import string
import time
from time import clock


def set_argparse():
  """Set the args&argv for command line mode"""
  parser = argparse.ArgumentParser()
  parser.add_argument("--ip", type=str, default="127.0.0.1", help="Destination IP")
  parser.add_argument("--port", type=int, default=53360, help="Destination Port")
  parser.add_argument("--cnt", type=int, default=50000, help="Sum of packages to be sent")
  return parser.parse_args()


def get_logger(logname):
  """Config the logger in the module
  Arguments:
      logname {str} -- logger name
  Returns:
      logging.Logger -- the logger object
  """
  logger = logging.getLogger(logname)
  formater = logging.Formatter(
      fmt='%(asctime)s - %(filename)s : %(levelname)-5s :: %(message)s',
      # filename='./log.log',
      # filemode='a',
      datefmt='%m/%d/%Y %H:%M:%S')
  stream_hdlr = logging.StreamHandler()
  stream_hdlr.setFormatter(formater)
  logger.addHandler(stream_hdlr)
  logger.setLevel(logging.DEBUG)
  return logger


__logger__ = get_logger('send_UDP_randomly')


def generate_random_str():
  tmp_length = random.randint(400, 1440)
  tmp_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=tmp_length))
  return (tmp_str, tmp_length)


def main():
  """Main function"""
  __logger__.info('Process start!')
  __logger__.debug("UDP target IP   = %s" % (__ARGS__.ip))
  __logger__.debug("UDP target port =  %s" % (__ARGS__.port))
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
  start = time.monotonic()
  sum_sent_bytes = 0
  for index in range(1, __ARGS__.cnt + 1, 1):
    if index % 10 == 0:
      print("Send packet sum: %d" % index, end='\r')
    message_tuple = generate_random_str()
    sum_sent_bytes += message_tuple[1]
    sock.sendto(bytes(message_tuple[0], "utf-8"), (__ARGS__.ip, __ARGS__.port))
  finish = time.monotonic()
  __logger__.info("Send %.2lf MB in duration %.3lfs, speed is %.3lfMbps" %
                  (sum_sent_bytes / 1024 / 1024, finish - start, sum_sent_bytes /
                   (finish - start) / 125000))
  __logger__.info('Process end!')


if __name__ == '__main__':
  # ! Uncomment the next line to read args from cmd-line
  __ARGS__ = set_argparse()
  main()
