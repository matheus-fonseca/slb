import re
from items import Item

def file(file, prefix):
	item = re.compile(r'^	%s([^_]*)_([^,]*)' % prefix)
	attr = re.compile(r'^	.\* %([a-z_-]+):(.*?)(\*/)?$')

	item_nums = {}
	items = {}

	def found_item(prefix, name, attribs):
		if not prefix in item_nums:
			item_nums[prefix] = 0
			items[prefix] = {}
		num = item_nums[prefix]
		item_nums[prefix] += 1
		items[prefix][name.lower()] = Item(name.lower(), num, attribs)

	collected = {}
	for line in file:
		m = item.match(line)
		if m:
			found_item(m.group(1), m.group(2), collected)
			collected = {}
			continue

		m = attr.match(line)
		if m:
			if not m.group(1) in collected:
				collected[m.group(1)] = ''
			collected[m.group(1)] += m.group(2)
			continue
	return items


def _parse_list(inp, items):
	result = {'type':'list','items':[]}
	while len(inp):
		if inp[0] == '{':
			res, inp = _parse_list(inp[1:], items)
			res['type'] = 'any'
			result['items'] += [res]
		elif inp[0] == '}':
			inp = inp[1:]
		elif '|' in inp[0]:
			inpn = inp[0].split('|')
			res, inpn = _parse_list(inpn, items)
			res['type'] = 'or'
			result['items'] += [res]
			inp = inp[1:]
		else:
			tp = items['ATTR'][inp[0]]
			tp = tp.attributes['type'].strip().split('/')
			basetype = tp[0]
			tp = tp[1:]
			it = {
			  'name': inp[0],
			  'basetype': basetype,
			}
			if len(tp) and basetype in ['u32']:
				sub = tp[0].upper()
				choices = items[sub]
				it['choices'] = {}
				for val in choices:
					it['choices'][val] = choices[val].index
			if len(tp) == 1 and basetype == 'string':
				it['minlen'] = int(tp[0])
				it['maxlen'] = int(tp[0])
			elif len(tp) == 2 and basetype == 'string':
				if tp[0] != '':
					it['minlen'] = int(tp[0])
				if tp[1] != '':
					it['maxlen'] = int(tp[1])
			else:
				it['extra'] = tp
			result['items'] += [it]
			inp = inp[1:]
	return result,inp

def input_definition(inp, items):
	inp = inp.strip()
	inp = filter(lambda x: x!='', re.split(',| |\t', inp))
	ninp = []
	for item in inp:
		pending = []
		while item.startswith('{'):
			ninp += '{'
			item = item[1:]
		while item.endswith('}'):
			pending = ['}'] + pending
			item = item[:-1]
		ninp += [item] + pending
	result, dummy = _parse_list(ninp, items)
	return result
