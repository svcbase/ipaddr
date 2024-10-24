package ipaddr

import (
	"fmt"
	"net"

	//"strconv"
	"encoding/binary"
	"net/http"
	"regexp"
	"strings"

	ip2location "github.com/ip2location/ip2location-go"
)

const (
	XForwardedFor = "X-Forwarded-For"
	XRealIP       = "X-Real-IP"
)

func ValidIP(ip string) (flag bool) {
	var exp = `^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$`
	flag, _ = regexp.MatchString(exp, ip)
	return
}

// ip_address := strings.Split(r.RemoteAddr, ":")[0]
// RemoteIp 返回远程客户端的 IP，如 192.168.1.1
func RemoteIp(req *http.Request) string {
	remoteAddr := req.RemoteAddr
	if ip := req.Header.Get(XRealIP); ip != "" {
		remoteAddr = ip
	} else if ip = req.Header.Get(XForwardedFor); ip != "" {
		remoteAddr = ip
	} else {
		remoteAddr, _, _ = net.SplitHostPort(remoteAddr)
	}

	if remoteAddr == "::1" {
		remoteAddr = "127.0.0.1"
	}

	return remoteAddr
}

// Ip2long 将 IPv4 字符串形式转为 uint32
func Ip2long(ipstr string) uint32 {
	ip := net.ParseIP(ipstr)
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip)
}

func ClientIP(req *http.Request) uint32 {
	return Ip2long(RemoteIp(req))
}

/*func Ip2Long(ip string) int64 {
	var ip_int int64
    var ip_pieces = strings.Split(ip, ".")
	if len(ip_pieces)==4 {
	    ip_1, _ := strconv.ParseInt(ip_pieces[0], 10, 32)
    	ip_2, _ := strconv.ParseInt(ip_pieces[1], 10, 32)
	    ip_3, _ := strconv.ParseInt(ip_pieces[2], 10, 32)
    	ip_4, _ := strconv.ParseInt(ip_pieces[3], 10, 32)

	    var ip_bin string = fmt.Sprintf("%08b%08b%08b%08b", ip_1, ip_2, ip_3, ip_4)

	    ip_int, _ = strconv.ParseInt(ip_bin, 2, 64)
	}
    return ip_int
}*/

/*func Ip2long(ipstr string) (ip uint32) {
    r := `^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})`
    reg, err := regexp.Compile(r)
    if err != nil {
        return
    }
    ips := reg.FindStringSubmatch(ipstr)
    if ips == nil {
        return
    }

    ip1, _ := strconv.Atoi(ips[1])
    ip2, _ := strconv.Atoi(ips[2])
    ip3, _ := strconv.Atoi(ips[3])
    ip4, _ := strconv.Atoi(ips[4])

    if ip1>255 || ip2>255 || ip3>255 || ip4 > 255 {
        return
    }

    ip += uint32(ip1 * 0x1000000)
    ip += uint32(ip2 * 0x10000)
    ip += uint32(ip3 * 0x100)
    ip += uint32(ip4)

    return
}*/

func Long2ip(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip>>24, ip<<8>>24, ip<<16>>24, ip<<24>>24)
}

func Long2mask(ip uint32) string {
	return fmt.Sprintf("%d.*.*.%d", ip>>24, ip<<24>>24)
}

func LocalIP() (ip string) {
	ip = ""
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	} else {
		for _, address := range addrs {
			if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					ip = ipnet.IP.String()
					if !strings.HasPrefix(ip, "169.254") {
						break
					}
				}
			}
		}
	}
	return
}

/*
	netInterfaces, err := net.Interfaces()
	if err == nil {
		for _, netInterface := range netInterfaces {
			if netInterface.Flags&net.FlagUp != 0 && netInterface.Flags&net.FlagLoopback == 0 {
				macAddr := netInterface.HardwareAddr.String()
				if len(macAddr) > 0 {
					addrs, e := netInterface.Addrs()
					if e == nil {
						for _, addr := range addrs {
							ipNet, isValidIpNet := addr.(*net.IPNet)
							if isValidIpNet && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
								if !strings.HasPrefix(ipNet.String(), "169.254") {
									macAddrs = append(macAddrs, macAddr)
								}
							}
						}
					}
				}
			}
		}*/

func GetPulicIP() string {
	conn, _ := net.Dial("udp", "google.com:80") //"8.8.8.8:80")
	defer conn.Close()
	localAddr := conn.LocalAddr().String()
	idx := strings.LastIndex(localAddr, ":")
	return localAddr[0:idx]
}

func LocalIPaddr(server string) string { //192.168.1.1:1
	ipaddr := ""
	cn, e := net.Dial("udp", server) //get local ipaddress
	defer cn.Close()
	if e == nil {
		ips := strings.Split(cn.LocalAddr().String(), ":")
		if len(ips) > 0 {
			ipaddr = ips[0]
		}
	}

	return ipaddr
}

func IPcountry(ip uint32) (country string) {
	country = ""
	if ip != 2130706433 { //127.0.0.1
		loc := ip2location.Get_all(Long2ip(ip))
		ss := strings.ToLower(loc.Country_short) //err: Invalid database file.
		if len(ss) == 2 {
			country = ss
		}
	}
	return
}
