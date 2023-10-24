#!/usr/bin/env python3

from sys import argv, stdin, exit
import re

# This oracle helps tamarin with a sources for OpenID Connect tokens. These
# tokens contain a hash (non-invertible). Tamarin thinks it can derive anything
# from these. This oracle ranks proof goals determining the origin of these
# hashes higher (see regex).

def splitter(line):
  splitted = line.split(':')
  return (splitted[0], splitted[1].strip())

lines = list(map(splitter, stdin.readlines()))
if not lines:
  exit(0)

def subToken(token, line):
  (num, goal) = line
  if isinstance(token, str):
    return num if token in goal else None
  else:
    return num if token.search(goal) is not None else None

def matchesNone(tokens, line):
  for token in tokens:
    if subToken(token, line):
      return False
  return True

def matchAgainstList(priorityList, lines):
  for token in priorityList:
    try:
      return next(filter(bool, map(lambda line: subToken(token, line), lines)))
    except StopIteration:
      pass

KU_secretKeys = [
  re.compile(r'\!KU\(.+inv'),
  re.compile(r'\!KU\( ~(eph|vsk|wsk|x)'),
  re.compile(r'\!KU\( [~\w\.\d]+\^.*~.*inv'),
  re.compile(r'\!KU\( [~\w\.\d]+\^.*inv'),
  '!KU( kdf',
  re.compile(r'\!KU\( [~\w\.\d\']+\^\(~[\w\.\d]+\*~[\w\.\d]+\)'),
]

match = None
if argv[1] == 'InjectiveAgreement':
  match = matchAgainstList(KU_secretKeys + [
    'senc',
    'sign',
  ], lines)
elif argv[1] == 'Secrecy':
  match = matchAgainstList(KU_secretKeys + [
    '!KU( senc',
    '!KU( ~token )',
  ], lines)
# elif argv[1] == 'Exec':
#   match = matchAgainstList([
#     'SendVC',
#     'St_',
#     'Success',
#     'senc',
#     'sign',
#   ], lines)

if match is not None:
  print(match)
