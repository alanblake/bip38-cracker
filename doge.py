#!/usr/bin/python
# -*- coding: utf-8 -*-

w = [[u'd',u'D'],[u'o',u'O',u'0',u'º',u'Ò',u'Ó',u'Ô',u'Õ',u'Ö',u'Ø',u'ò',u'ó',u'ô',u'õ',u'ö',u'ø'],[u'g',u'G',u'j',u'J'],[u'e',u'E',u'È',u'É',u'Ê',u'Ë',u'è',u'é',u'ê',u'ë']]

def perm(w):
    if len(w)==0:
        yield ''
        return
    for c in w[0]:
        for p in perm(w[1:]):
            yield c + p

doge=[p.encode('utf8') for p in perm(w)] # 1280 entries

f = open('dogewords.h', 'w')
print >>f, "static const unsigned char *words[] = {"
import re
for d in doge:
    dd = '"' + d.encode('string_escape') + '"'
    dd = re.sub(r'(\\x..)([0-9a-fA-F])', r'\1""\2', dd)
    print >>f, ' ' + dd + ','
print >>f, " 0"
print >>f, "};"
f.close()
