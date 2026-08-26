package main

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

var regex = regexp.MustCompile(`^[a-z\d](?:[a-z\d]|-[a-z\d]){0,38}$`)
var blockList = map[string]bool{"www": true}

func sanitize(subdomain string) string {
	sanitized := strings.ToLower(subdomain)
	reg := regexp.MustCompile(`[^a-z0-9-]+`)
	sanitized = reg.ReplaceAllString(sanitized, "-")
	reg2 := regexp.MustCompile(`-+`)
	sanitized = reg2.ReplaceAllString(sanitized, "-")
	sanitized = strings.Trim(sanitized, "-")
	return sanitized
}

func validate(subdomain *string) error {
	if len(*subdomain) > 38 || len(*subdomain) < 3 {
		return errors.New("subdomain length must be between 3 and 42")
	}
	if blockList[*subdomain] {
		return errors.New("subdomain is in deny list")
	}
	if !regex.MatchString(*subdomain) {
		*subdomain = sanitize(*subdomain)
		if len(*subdomain) > 38 || len(*subdomain) < 3 {
			return errors.New("subdomain length must be between 3 and 42")
		}
		if blockList[*subdomain] {
			return errors.New("subdomain is in deny list")
		}
		if !regex.MatchString(*subdomain) {
			return errors.New("subdomain must be lowercase & alphanumeric")
		}
	}
	return nil
}

func parseHost(r io.Reader) (string, []byte, error) {
	buffer := make([]byte, 2048)
	size, err := r.Read(buffer)
	buffer = buffer[:size]
	if err != nil {
		return "", buffer, err
	}
	text := string(buffer)
	left := strings.Index(text, "Host: ")
	if left < 0 {
		left = strings.Index(text, "host: ")
	}
	if left < 0 {
		return "", buffer, fmt.Errorf("no host detected")
	}
	text = text[left+6:] // drops chars "Host: "
	right := strings.Index(text, "\n")
	if right < 0 {
		return "", buffer, fmt.Errorf("no host detected")
	}
	return strings.TrimSpace(text[:right]), buffer, nil
}

func writeResponse(conn io.WriteCloser, statusCode int, status string, message string) {
	response := fmt.Sprintf(
		"HTTP/1.1 %d %s\r\nContent-Length: %d\r\n\r\n%s", statusCode, status, len(message), message)
	conn.Write([]byte(response))
	conn.Close()
}

// normalizeHost `Host` sarlavhasini tunnel kalitiga aylantiradi.
//
// ⚠️ Sarlavha PORTNI ham olib yuradi (RFC 9110 §7.2:
// `Host = uri-host [ ":" port ]`). Tunnel esa portsiz nom bilan
// ro'yxatga olinadi. Standart portda (80/443) klientlar portni
// tushirib qoldiradi, shuning uchun xato ko'rinmaydi — lekin
// boshqa portda har bir so'rov 404 olardi.
func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))

	// IPv6 literal: `[::1]:8080` yoki `[::1]`.
	if strings.HasPrefix(host, "[") {
		if end := strings.LastIndex(host, "]"); end >= 0 {
			return host[:end+1]
		}
		return host
	}

	// Bitta ikki nuqta — port. Ko'p bo'lsa bu qavssiz IPv6, unga
	// tegmaymiz.
	if strings.Count(host, ":") == 1 {
		host, _, _ = strings.Cut(host, ":")
	}
	return host
}
