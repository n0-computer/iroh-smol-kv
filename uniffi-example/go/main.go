
package main

import (
	"fmt"
	"os"
	"hello-app/uniffi_example"
	"reflect"
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
	fmt.Println("Starting with tickets", tickets)
	config := uniffi_example.NewConfig()
	config.Expiry.Horizon = 10_000_000_000 // 10s
	config.Expiry.CheckInterval = 5_000_000_000 // 5s
	fmt.Println("Config created", config)
	db, err2 := uniffi_example.NewDb(config)
	panicIfErr(err2)
	fmt.Println("db created", db.DebugString())

	client := db.Client()
	fmt.Println("Got client", client.DebugString())

	err := db.JoinPeers(tickets)
	panicIfErr(err)

	write, err := db.Write()
	panicIfErr(err)
	fmt.Println("Got write scope", write.DebugString())

	err = write.Put([]byte("hello"), []byte("world"))
	panicIfErr(err)

	val, err := client.Get(db.Public(), []byte("hello"))
	panicIfErr(err)
	fmt.Println("Get value", val)

	filter, err := uniffi_example.FilterParse("")
	panicIfErr(err)
	stream, err := client.Subscribe(filter, uniffi_example.SubscribeModeBoth)
	panicIfErr(err)
	fmt.Println("Subscribed to stream", stream.DebugString())

	for {
		item, err := stream.NextRaw()
		panicIfErr(err)
		fmt.Println("Got item", uniffi_example.SubscribeItemDebug(*item))
	}
}