package mq

import "fmt"

// RoutingKeyFor 根据 routing key 判断 key usage
// acct0 → keyUsage=0 (运营密钥)
// acct1 → keyUsage=1 (用户密钥)
func RoutingKeyFor(routingKey string) (keyUsage uint8, err error) {
	switch routingKey {
	case "acct0":
		return 0, nil
	case "acct1":
		return 1, nil
	default:
		return 0, fmt.Errorf("unknown routing key: %s", routingKey)
	}
}
