#!/usr/bin/env python

import parse, os
from sys import argv, exit
import genetlink, netlink

def print_commands():
	print 'Available commands:'
	list = items['CMD'].keys()
	list.sort()
	for iname in list:
		item = items['CMD'][iname]
		if 'input' in item.attributes.keys():
			print '	%s'%item.name
	print ''
	print '	help'
	print '	ccheck'

def _print_params(inp, type='list'):
	if not 'type' in inp:
		if type == 'any1':
			print '[%s]'%inp['name'],
		elif type == 'any':
			print '[%s=...]'%inp['name'],
		else:
			print inp['name'],
	elif inp['type'] == 'or':
		print '|'.join(map(lambda x:x['name'], inp['items'])),
	else:
		tp = inp['type']
		if len(inp['items']) == 1 and tp == 'any':
			tp = 'any1'
		for p in inp['items']:
			_print_params(p, tp)

def _explain_params(inp):
	if not 'type' in inp:
		bt = inp['basetype']
		tp = bt
		if inp['basetype'] == 'string':
			minl = None
			maxl = None
			if 'minlen' in inp:
				minl = inp['minlen']
			if 'maxlen' in inp:
				maxl = inp['maxlen']
			if maxl is None and minl is not None:
				tp += ' (min %d bytes)' % minl
			elif maxl is not None and minl is None:
				tp += ' (max %d bytes)' % maxl
			elif maxl is not None and minl is not None and maxl == minl:
				tp += ' (%d bytes)' % maxl
			elif maxl is not None and minl is not None and maxl != minl:
				tp += ' (%d-%d bytes)' %(minl,maxl)
			if 'extra' in inp and len(inp['extra']) and inp['extra'][-1] == 'mac':
				tp = 'mac address'	
			pass
		elif inp['basetype'] == 'u32' and 'choices' in inp:
			tp = ', '.join(inp['choices'].keys())
		elif inp['name'] == 'ifindex':
			tp = 'interface name or index'
		print '\t%s: %s'%(inp['name'], tp)
	else:
		for p in inp['items']:
			_explain_params(p)

def help_command(cmd):
	if not cmd in items['CMD']:
		print 'No such command'
	else:
		item = items['CMD'][cmd]
		inp = parse.input_definition(item.attributes['input'], items)
		print argv[0],'%s'%cmd,
		_print_params(inp)
		print ''
		_explain_params(inp)

def _parse_params(items, inp, params, choice):
	result = []
	if not 'type' in inp:
		if choice:
			name = inp['name']
			val = None
			for idx in xrange(len(params)):
				if params[idx].startswith(name+'='):
					val = params[idx].split('=',1)[1]
					rest = params
					del rest[idx]
					break
			if val is None:
				return [], params
		else:
			val = params[0]
			rest = params[1:]
		if 'choices' in inp:
			val = inp['choices'][val]
		if inp['basetype'] == 'u32':
			if inp['name'] == 'ifindex':
				try:
					value = int(val)
				except:
					try:
						value = int(open('/sys/class/net/%s/ifindex'%val).read())
					except:
						raise Exception('no such network interface')
			elif inp['name'] == 'wiphy':
				try:
					value = int(val)
				except:
					try:
						value = int(open('/sys/class/ieee80211/%s/index'%val).read())
					except:
						raise Exception('no such wiphy')
			else:
				value = int(val, 0)
		elif inp['basetype'] in ['string', 'nulstring']:
			if 'extra' in inp and len(inp['extra']) and inp['extra'][-1] == 'mac':
				value = ''.join(map(lambda x:chr(int(x,16)),val.split(':')))
			else:
				value = val
		elif inp['basetype'] == 'u8':
			value = int(val, 0)
		else:
			raise Exception('Oops, %s not handled' % inp['basetype'])
		
		tp = items['ATTR'][inp['name']]['type'].strip().split('/')[0]
		return ([(items['ATTR'][inp['name']].index,value,tp)], rest)
	elif inp['type'] == 'list':
		for p in inp['items']:
			res, params = _parse_params(items, p, params, False)
			result += res
	elif inp['type'] == 'any':
		for p in inp['items']:
			res, params = _parse_params(items, p, params, True)
			result += res
		if res == [] and len(inp['items']) == 1:
			res, params = _parse_params(items, p, params, False)
			result += res
	elif inp['type'] == 'or':
		for p in inp['items']:
			res, params = _parse_params(items, p, params, True)
			result += res
		if res == [] and len(inp['items']) == 1:
			res, params = _parse_params(items, p, params, False)
			result += res
	else:
		raise Exception('Oops, %s not handled' % inp['type'])
	return result, params

def ccheck(items, headername, prefix):
	max = {}
	print '#include <stdio.h>'
	print '#include "%s"' % headername
	print ''
	print '#define ASSERT(expr)				\\'
	print '	if (!(expr)) {				\\'
	print '		err++;				\\'
	print '		printf("%s failed!\\n", #expr);	\\'
	print '	}'
	print ''
	print 'int main()'
	print '{'
	print '	int err = 0;'
	print ''

	for group in items:
		for itemname in items[group]:
			item = items[group][itemname]
			num = item.index
			name = item.name.upper()
			if not group in max or num > max[group]:
				max[group] = num

			print '	ASSERT(%s%s_%s == %d)' % (prefix,group,name,num)

		print '	ASSERT(%s%s_MAX == %d)' % (prefix,group,max[group])
		print ''

	print '	return !!err;'
	print '}'

def exec_cmd(cmd, params):
	inp = parse.input_definition(cmd.attributes['input'], items)
	res, params = _parse_params(items, inp, params, False)
	if len(params):
		raise Exception('not all arguments used, still have "%s"!'%','.join(params))
	conn = genetlink.connection
	family = genetlink.controller.get_family_id('nl80211')
	attrs = []
	for idx, val, tp in res:
		if tp == 'u32':
			attr = netlink.U32Attr(idx, val)
		elif tp == 'nulstring':
			attr = netlink.NulStrAttr(idx, val)
		elif tp == 'string':
			attr = netlink.StrAttr(idx, val)
		elif tp == 'u8':
			attr = netlink.U8Attr(idx, val)
		else:
			raise Exception("Unhandled attribute type '%s'!" % tp)
		attrs.append(attr)
	sent = genetlink.GeNlMessage(family, cmd.index,
								 flags=netlink.NLM_F_REQUEST|netlink.NLM_F_ACK,
								 attrs=attrs)
	sent.send(conn)
	while True:
		m = conn.recv()
		if m.seq == sent.seq:
			# if it's an error message we raise an
			# exception within recv()
			print 'Success'
			break


headername = '/usr/include/linux/nl80211.h'
#headername = "/lib/modules/%s/build/include/linux/nl80211.h"%os.uname()[2]
prefix = 'NL80211_'
items = parse.file(open(headername), prefix)

if len(argv) == 1:
	print_commands()
	exit(2)
elif len(argv) == 2 and argv[1] == 'help':
	print_commands()
	exit(2)
elif len(argv) > 2 and argv[1] == 'help':
	help_command(argv[2])
	exit(2)
elif len(argv) > 1 and argv[1] == 'ccheck':
	ccheck(items, headername, prefix)
elif len(argv) > 1 and argv[1] in items['CMD']:
	exit(exec_cmd(items['CMD'][argv[1]], argv[2:]))
else:
	print 'Oops'
	exit(3)
