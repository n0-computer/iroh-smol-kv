
package main

import (
	"fmt"
	"os"
	sp "hello-app/iroh_streamplace"
	"reflect"
    "crypto/rand"
)

func isNilError(err error) bool {
    if err == nil {
        return true
    }
    
    v := reflect.ValueOf(err)
    return v.Kind() == reflect.Ptr && v.IsNil()
}


func panicIfErr(err error) {
	if !isNilError(err) {
		panic(err)
	}
}

func main() {
	tickets := os.Args[1:];

	secret := make([]byte, 32)
    _, err := rand.Read(secret)
    panicIfErr(err)

	fmt.Println("Starting with tickets", tickets)
	config := sp.Config {
		Key : secret,
		Topic: make([]byte, 32), // all zero topic for testing
		MaxSendDuration: 1000_000_000, // 1s
	}
	fmt.Printf("Config created %+v\n", config)
	node, err := sp.ApiSender(config)
	panicIfErr(err)

	db := node.Db()
	w := node.NodeScope()

	node_id, err := node.NodeId()
	panicIfErr(err)
	fmt.Println("Node ID:", node_id)

	ticket, err := node.Ticket()
	panicIfErr(err)
	fmt.Println("Ticket:", ticket)

	if len(tickets) > 0 {
		err = node.JoinPeers(tickets)
		panicIfErr(err)
	}

	w.Put(nil, []byte("hello"), []byte("world"))
	stream := []byte("stream1")
	w.Put(&stream, []byte("subscribed"), []byte("true"))

	filter := sp.NewFilter()
	items, err := db.IterWithOpts(filter)
	panicIfErr(err)
	fmt.Printf("Iter items: %+v\n", items)

	filter2 := sp.NewFilter().Global()
	items2, err := db.IterWithOpts(filter2)
	panicIfErr(err)
	fmt.Printf("Iter items: %+v\n", items2)

	filter3 := sp.NewFilter().Stream(stream)
	items3, err := db.IterWithOpts(filter3)
	panicIfErr(err)
	fmt.Printf("Iter items: %+v\n", items3)

	sub := db.Subscribe(sp.NewFilter())
	for {
		ev, err := sub.NextRaw()
		panicIfErr(err)
		switch (*ev).(type) {
			case sp.SubscribeItemEntry:
				fmt.Printf("%+v\n", (*ev).(sp.SubscribeItemEntry))
			case sp.SubscribeItemCurrentDone:
				fmt.Printf("Got current done event: %+v\n", (*ev).(sp.SubscribeItemCurrentDone))
			case sp.SubscribeItemExpired:
				fmt.Printf("Got expired event: %+v\n", (*ev).(sp.SubscribeItemExpired))
			case sp.SubscribeItemOther:
				fmt.Printf("Got other event: %+v\n", (*ev).(sp.SubscribeItemOther))
		}
	}
}