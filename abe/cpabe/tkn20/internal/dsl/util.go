package dsl

func isDigit(c uint8) bool {
	return c >= '0' && c <= '9'
}

func isAlpha(c uint8) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		c == '_'
}

func isAlphaNumeric(c uint8) bool {
	return isAlpha(c) || isDigit(c)
}
