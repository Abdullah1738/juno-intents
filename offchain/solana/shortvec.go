package solana

func encodeShortVecLen(n int) []byte {
	if n < 0 {
		panic("encodeShortVecLen: negative length")
	}
	v := uint64(n)
	out := make([]byte, 0, 4)
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			out = append(out, b)
			break
		}
		out = append(out, b|0x80)
	}
	return out
}

