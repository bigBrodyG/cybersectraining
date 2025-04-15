# from secret import FLAG
FLAG = "flag{redacted}"
assert type(FLAG) == type(b'')
assert len(FLAG) == 40

def generate_ciphertext(pt):
	ct = b''
	ct += (pt[0] ^ pt[7] ^ pt[0] ^ pt[4]).to_bytes(1, 'little')
	ct += (pt[4] ^ pt[4] ^ pt[3]).to_bytes(1, 'little')
	ct += (pt[3] ^ pt[1] ^ pt[5]).to_bytes(1, 'little')
	ct += (pt[1] ^ pt[2]).to_bytes(1, 'little')
	ct += (pt[6] ^ pt[39] ^ pt[0]).to_bytes(1, 'little')
	ct += (pt[7] ^ pt[3]).to_bytes(1, 'little')
	ct += (pt[39] ^ pt[7]).to_bytes(1, 'little')
	ct += (pt[0] ^ pt[1]).to_bytes(1, 'little')
	ct += (pt[39] ^ pt[39]).to_bytes(1, 'little')
	ct += (pt[4] ^ pt[39] ^ pt[7] ^ pt[9]).to_bytes(1, 'little')
	ct += (pt[1] ^ pt[5] ^ pt[6] ^ pt[10]).to_bytes(1, 'little')
	ct += (pt[11] ^ pt[5] ^ pt[2] ^ pt[4] ^ pt[7]).to_bytes(1, 'little')
	ct += (pt[6] ^ pt[12] ^ pt[5]).to_bytes(1, 'little')
	ct += (pt[13] ^ pt[1] ^ pt[5] ^ pt[1] ^ pt[39]).to_bytes(1, 'little')
	ct += (pt[7] ^ pt[14] ^ pt[8]).to_bytes(1, 'little')
	ct += (pt[15] ^ pt[39] ^ pt[6] ^ pt[2] ^ pt[7]).to_bytes(1, 'little')
	ct += (pt[16] ^ pt[39] ^ pt[2]).to_bytes(1, 'little')
	ct += (pt[17] ^ pt[8] ^ pt[39] ^ pt[7]).to_bytes(1, 'little')
	ct += (pt[4] ^ pt[0] ^ pt[2] ^ pt[18]).to_bytes(1, 'little')
	ct += (pt[2] ^ pt[19] ^ pt[0]).to_bytes(1, 'little')
	ct += (pt[5] ^ pt[4] ^ pt[20] ^ pt[0]).to_bytes(1, 'little')
	ct += (pt[21] ^ pt[2] ^ pt[6]).to_bytes(1, 'little')
	ct += (pt[39] ^ pt[22] ^ pt[6] ^ pt[3] ^ pt[2]).to_bytes(1, 'little')
	ct += (pt[4] ^ pt[4] ^ pt[23]).to_bytes(1, 'little')
	ct += (pt[3] ^ pt[0] ^ pt[5] ^ pt[24] ^ pt[1]).to_bytes(1, 'little')
	ct += (pt[0] ^ pt[25] ^ pt[2]).to_bytes(1, 'little')
	ct += (pt[8] ^ pt[26] ^ pt[5] ^ pt[0] ^ pt[39]).to_bytes(1, 'little')
	ct += (pt[39] ^ pt[27] ^ pt[1]).to_bytes(1, 'little')
	ct += (pt[1] ^ pt[1] ^ pt[28] ^ pt[2] ^ pt[2]).to_bytes(1, 'little')
	ct += (pt[39] ^ pt[6] ^ pt[29] ^ pt[1]).to_bytes(1, 'little')
	ct += (pt[6] ^ pt[0] ^ pt[6] ^ pt[30] ^ pt[3]).to_bytes(1, 'little')
	ct += (pt[1] ^ pt[8] ^ pt[31]).to_bytes(1, 'little')
	ct += (pt[3] ^ pt[0] ^ pt[0] ^ pt[32]).to_bytes(1, 'little')
	ct += (pt[1] ^ pt[2] ^ pt[33]).to_bytes(1, 'little')
	ct += (pt[6] ^ pt[0] ^ pt[7] ^ pt[34] ^ pt[7]).to_bytes(1, 'little')
	ct += (pt[6] ^ pt[39] ^ pt[4] ^ pt[2] ^ pt[35]).to_bytes(1, 'little')
	ct += (pt[36] ^ pt[5] ^ pt[6]).to_bytes(1, 'little')
	ct += (pt[2] ^ pt[7] ^ pt[8] ^ pt[37]).to_bytes(1, 'little')
	ct += (pt[4] ^ pt[6] ^ pt[38] ^ pt[1]).to_bytes(1, 'little')
	ct += (pt[39] ^ pt[39] ^ pt[6] ^ pt[3]).to_bytes(1, 'little')
	return ct


def main():
	ciphertext = generate_ciphertext(FLAG)
	print(f'ciphertext (hex): \'{ciphertext.hex()}\'')

if __name__=='__main__':
	main()

# output:
# ciphertext (hex): '0654270a0c60490000107206371222064d6d00391e096171113b070d6453235e6339036b366a2f66'