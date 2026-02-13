# IP 地址库高效匹配（Go，IPv4 + IPv6）

支持以下规则格式：

- 单 IP：`192.168.1.10`、`2001:db8::1`
- IP 范围：`172.16.1.10-172.16.1.20`
- CIDR：`10.0.0.0/24`、`2001:db8:1::/48`

## 设计

1. 将每条规则解析为闭区间 `[start, end]`（内部用 128 位无符号整数表示）。
2. IPv4 与 IPv6 分开建索引。
3. 构建期对区间排序并合并重叠/相邻区间。
4. 查询期使用二分查找，单次匹配 `O(log n)`。

## 使用示例

```go
package main

import (
	"fmt"

	"ipmatcher"
)

func main() {
	matcher, err := ipmatcher.NewMatcher([]string{
		"192.168.1.10",
		"10.0.0.0/24",
		"172.16.1.10-172.16.1.20",
		"2001:db8::1",
		"2001:db8:1::/48",
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(matcher.Contains("10.0.0.88"))   // true
	fmt.Println(matcher.Contains("10.0.1.88"))   // false
	fmt.Println(matcher.Contains("2001:db8::1")) // true
}
```

## 测试

```bash
go test ./...
```
