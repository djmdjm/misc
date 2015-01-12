/*
 * Base-32 encoding.
 */

char *
b32_ntop(u_char *d, size_t len)
{
	const char b32[33] = "abcdefghijklmnopqrstuvwxyz234567";
	size_t i, r, j, p, olen = ((len + 9) / 5) * 8 + 1;
	u_int64_t v;
	char *ret;

	if (len > 65536 || (ret = calloc(1, olen)) == NULL)
		return NULL;

	for (i = p = 0, v = 0; len > 0; len--) {
		v = (v << 8ULL) | *d++;
		if (++i == 5) {
			/* Emit 8 bytes of output for every 5 bytes of input */
			for (j = 0; j < 8; j++)
				ret[p++] = b32[(v >> ((7 - j) * 5)) & 0x1f];
			v = 0;
			i = 0;
		}
	}
	/* Emit odd bytes and padding */
	if (i != 0) {
		for (j = 0; j < 5 - i; j++)
			v <<= 8ULL;
		r = (i * 8 + 4) / 5;
		for (j = 0; j < r; j++)
			ret[p++] = b32[(v >> ((7 - j) * 5)) & 0x1f];
		/* Uncomment if you want padding */
		/* memcpy(ret + p, "======", 1 + 7 - j); */
		/* p += 1 + 7 - j; */
	}
	ret[p] = '\0';

	return ret;
}

