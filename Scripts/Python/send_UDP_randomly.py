#!/usr/bin/env python
# coding:utf-8
"""send_udp.py"""

import argparse
import logging
import random
import socket
import string
import time
import threading
from time import clock


def set_argparse():
  """Set the args&argv for command line mode"""
  parser = argparse.ArgumentParser()
  parser.add_argument("--ip", type=str, default="192.168.3.121", help="Destination IP")
  parser.add_argument("--s", type=str, default="192.168.3.120", help="Source IP")
  parser.add_argument("--port", type=int, default=53360,help="Destination Port")
  parser.add_argument("--cnt", type=int, default=50000,help="Sum of packages to be sent")
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


def generate_1500_str():
  random.seed()  # 初始化
  tmp_str = ''.join(random.choices(
      string.ascii_uppercase + string.digits, k=1500))
  return (tmp_str, 1500)


def generate_random_str():
  random.seed()
  tmp_length = random.randint(60, 1440)  # 返回区间内的一个整数
  tmp_str = ''.join(random.choices(
      string.ascii_uppercase + string.digits, k=tmp_length))
  return (tmp_str, tmp_length)


def main():
  """Main function"""
  __logger__.info('Process start!')
  __logger__.debug("UDP target IP   = %s" % (__ARGS__.ip))
  __logger__.debug("UDP source IP   = %s" % (__ARGS__.s))
  __logger__.debug("UDP target port =  %s" % (__ARGS__.port))
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP  无连接面向网络
  start = time.monotonic()
  global sum_sent_bytes  # 共享全局变量
  tmp_length = 0
  message_tuple = generate_1500_str()
  random.seed()

  for index in range(1, __ARGS__.cnt + 1, 1):
    if index % 10 == 0:
      print("Send packet sum: %d" % index, end='\r')
    tmp_length = random.randint(400, 1440)
    sum_sent_bytes += tmp_length
    # sum_sent_bytes += message_tuple[1]
    sock.sendto(bytes(message_tuple[0][:tmp_length],
                      "utf-8"), (__ARGS__.ip, __ARGS__.port))

  finish = time.monotonic()
  __logger__.info("Send %.2lf MB in duration %.3lfs, speed is %.3lfMbps" %
                  (sum_sent_bytes / 1024 / 1024, finish - start, sum_sent_bytes /
                   (finish - start) / 125000))
  __logger__.info('Process end!')


#定义一个print_pps方法
#主线程之外的线程，每隔1秒执行
def print_pps():
    global sum_sent_bytes
    last_sum_bytes = 0
    while 1:
        pps = (sum_sent_bytes - last_sum_bytes)/125000
        #按秒打印本地时间和
        #print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())))
        '''前后两秒分别发送的总字节数
        print('sum_sent_bytes - last_sum_bytes = ' + 
                str(sum_sent_bytes) + '-' + str(last_sum_bytes) + '=' + 
                sum_sent_bytes - last_sum_bytes)
        '''
        print('the last second sent_bytes: ' + str(pps) + 'Mbps')
        #print("the last second sent_bytes: %.6lf Mbps" % pps, end='\r')
        last_sum_bytes = sum_sent_bytes
        time.sleep(1)


if __name__ == '__main__':
  sum_sent_bytes = 0  # 共享全局变量
  threading_print = threading.Thread(target=print_pps)
  threading_print.daemon = True  # 设置后台线程
  threading_print.start()
  # ! Uncomment the next line to read args from cmd-line
  __ARGS__ = set_argparse()
  main()
