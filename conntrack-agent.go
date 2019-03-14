package main

import (
	"github.com/OceanOfLearning/conntrack-go/lib"
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"time"
)

func main(){
	//testing
	err := lib.Init()
	if err != nil {
		log.Fatalln("failed at Init..ERROR:",err)
	}
	h,err := lib.NewHandle(unix.NETLINK_NETFILTER)
	if err != nil {
		log.Fatalln("failed to create Handle..ERROR:",err)
	}
	err = h.ConntrackTableFlush(lib.ConntrackTable)
	if err != nil {
		log.Fatalln("failed to flush conntrack table..ERROR:", err)
	}
	for {
		flows, err := h.ConntrackTableList(lib.ConntrackTable, lib.InetFamily(unix.AF_INET))
		if err == nil {
			if len(flows) != 0 {
				for _, flow := range flows {
					fmt.Println(flow)
				}
			}
		}
		<-time.After(time.Millisecond * 50)
	}
}
