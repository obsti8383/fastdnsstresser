package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"

	"net/netip"
	"strconv"
	"time"

	"golang.org/x/net/idna"

	"github.com/phuslu/fastdns"
)

// Example: ./fastdnsstresser www.heise.de 10.10.111.1 50
func main() {
	if len(os.Args) < 4 {
		fmt.Println("Error, please supply domain name as first argument and resolver as second")
		os.Exit(1)
	}

	// basic parameters
	domainName := os.Args[1]
	domainNamePunycode, err := idna.Display.ToASCII(domainName)
	if err != nil {
		fmt.Println(err.Error())
	}

	resolver := os.Args[2]

	var numberOfRequests = 1000000
	numberOfWorkers, err := strconv.Atoi(os.Args[3])
	if err != nil {
		fmt.Println("No integer: " + os.Args[3])
	}

	var numberOfRequestsPerWorker int = numberOfRequests / numberOfWorkers
	// create goroutines
	var (
		//numberOfErrors    int
		//numberOfErrorsMu  sync.Mutex // guards numberOfErrors
		//numberOfSuccess   int
		//numberOfSuccessMu sync.Mutex // guards numberOfSuccess
		wg sync.WaitGroup
		//buffer = make(chan string, numberOfWorkers)
	)

	fmt.Printf("Resolving against %s with %d workers, doing %d requests\n", resolver, numberOfWorkers, numberOfRequests)

	start := time.Now()

	wg.Add(numberOfWorkers)
	for i := 0; i < numberOfWorkers; i++ {
		// start consumers / workers
		go func() {
			client := &fastdns.Client{
				AddrPort:    netip.AddrPortFrom(netip.MustParseAddr(resolver), 53),
				ReadTimeout: 1 * time.Millisecond,
				MaxConns:    10000000,
			}

			req, resp := fastdns.AcquireMessage(), fastdns.AcquireMessage()
			defer fastdns.ReleaseMessage(req)
			defer fastdns.ReleaseMessage(resp)

			for i := 0; i < numberOfRequestsPerWorker; i++ {
				req.SetRequestQustion(domainNamePunycode, fastdns.ParseType("A"), fastdns.ClassINET)

				client.Exchange(req, resp)
				//if err == nil {
				//	short(resp)
				//fmt.Fprintf(os.Stderr, "client=%+v exchange(\"%s\") error: %+v\n", client, domainName, err)
				//os.Exit(1)
				//}

				// r.LookupHost(context.Background(), domainName)
				// if e != nil {
				// 	numberOfErrorsMu.Lock()
				// 	numberOfErrors++
				// 	numberOfErrorsMu.Unlock()
				// } else {
				// 	numberOfSuccessMu.Lock()
				// 	numberOfSuccess++
				// 	numberOfSuccessMu.Unlock()
				// }
			}
			wg.Done()
		}()
	}

	// wait for workers to finish
	wg.Wait()

	elapsed := time.Since(start)
	//fmt.Println("Number of errors:", numberOfErrors)
	//fmt.Println("Number of successes:", numberOfSuccess)
	fmt.Printf("Time elapsed: %s\nRequests per Second: %f\n", elapsed, float64(numberOfRequests)/elapsed.Seconds())
}

func short(resp *fastdns.Message) {
	_ = resp.Walk(func(name []byte, typ fastdns.Type, class fastdns.Class, ttl uint32, data []byte) bool {
		var v interface{}
		switch typ {
		case fastdns.TypeA, fastdns.TypeAAAA:
			v, _ = netip.AddrFromSlice(data)
		case fastdns.TypeCNAME, fastdns.TypeNS:
			v = fmt.Sprintf("%s.", resp.DecodeName(nil, data))
		case fastdns.TypeMX:
			v = fmt.Sprintf("%d %s.", binary.BigEndian.Uint16(data), resp.DecodeName(nil, data[2:]))
		case fastdns.TypeTXT:
			v = fmt.Sprintf("\"%s\"", data[1:])
		case fastdns.TypeSRV:
			priority := binary.BigEndian.Uint16(data)
			weight := binary.BigEndian.Uint16(data[2:])
			port := binary.BigEndian.Uint16(data[4:])
			target := resp.DecodeName(nil, data[6:])
			v = fmt.Sprintf("%d %d %d %s.", priority, weight, port, target)
		case fastdns.TypeSOA:
			var mname []byte
			for i, b := range data {
				if b == 0 {
					mname = data[:i+1]
					break
				} else if b&0b11000000 == 0b11000000 {
					mname = data[:i+2]
					break
				}
			}
			nname := resp.DecodeName(nil, data[len(mname):len(data)-20])
			mname = resp.DecodeName(nil, mname)
			serial := binary.BigEndian.Uint32(data[len(data)-20:])
			refresh := binary.BigEndian.Uint32(data[len(data)-16:])
			retry := binary.BigEndian.Uint32(data[len(data)-12:])
			expire := binary.BigEndian.Uint32(data[len(data)-8:])
			minimum := binary.BigEndian.Uint32(data[len(data)-4:])
			v = fmt.Sprintf("%s. %s. %d %d %d %d %d", mname, nname, serial, refresh, retry, expire, minimum)
		default:
			v = fmt.Sprintf("%x", data)
		}
		fmt.Printf("%s\n", v)
		return true
	})
}
