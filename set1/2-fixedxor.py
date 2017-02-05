def fixed_xor(s1, s2):
	s1 = s1.decode("hex")
	s2 = s2.decode("hex")

	return s1 ^ s2



inp1 = "686974207468652062756c6c277320657965"
inp2 ="1c0111001f010100061a024b53535009181c"

print fixed_xor(inp1, inp2)

assert fixed_xor(inp1, inp2) == expected

expected =  "746865206b696420646f6e277420706c6179" 