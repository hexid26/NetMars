#!/usr/bin/env python
# coding:utf-8
"""send_udp.py"""

import argparse
import logging
import random
import socket
import string
import time


def set_argparse():
  """Set the args&argv for command line mode"""
  parser = argparse.ArgumentParser()
  parser.add_argument("--ip", type=str, default="192.168.3.150", help="Destination IP")
  # parser.add_argument("--s", type=str, default="192.168.3.120", help="Source IP")
  parser.add_argument("--port", type=int, default=53360, help="Destination Port")
  parser.add_argument("--len", type=str, default="random", help="packet length")
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


def generate_fix_str():
  """
  随机生成固定的字符串

  Returns:
    [tuple] -- (字符串, 长度1500)
  """
  tmp_str = "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
  return (tmp_str, 1500)


def main():
  """Main function"""
  __logger__.info('Process start!')
  __logger__.info("UDP target IP   = %s" % (__ARGS__.ip))
  # __logger__.info("UDP source IP   = %s" % (__ARGS__.s))
  __logger__.info("UDP target port =  %s" % (__ARGS__.port))
  __logger__.info("Packet length port =  %s" % (__ARGS__.port))
  pkt_len = 0
  if __ARGS__.len != "random":
    pkt_len = int(__ARGS__.len)
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP  无连接面向网络
  random.seed()
  global sum_sent_bytes  # 共享全局变量
  tmp_length = 0
  message_tuple = generate_fix_str()
  while True:
    if pkt_len == 0:
      tmp_length = random.randint(400, 1440)
    else:
      tmp_length = pkt_len
    sock.sendto(bytes(message_tuple[0][:tmp_length], "utf-8"), (__ARGS__.ip, __ARGS__.port))
    __logger__.info("Send %d bytes:\n%s" % (tmp_length, message_tuple[0][:tmp_length]))
    key_in = input("Press Enter to continue...")
  __logger__.info('Process end!')


if __name__ == '__main__':
  sum_sent_bytes = 0  # 共享全局变量
  # ! Uncomment the next line to read args from cmd-line
  __ARGS__ = set_argparse()
  main()
