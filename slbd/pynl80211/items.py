class Item:
	def __init__(self, name, index, attributes):
		self.name = name
		self.attributes = attributes
		self.index = index
	def __repr__(self):
		return '<Item %d: "%s", %r>'%(self.index, self.name, self.attributes)
	def __getitem__(self, name):
		if name == 'index':
			return self.index
		elif name == 'name':
			return self.name
		else:
			return self.attributes[name]
