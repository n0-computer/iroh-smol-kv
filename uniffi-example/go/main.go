
package main

import (
	"fmt"
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
	config := uniffi_example.NewConfig()
	config.Expiry.Horizon = 10000000000 // 10s
	config.Expiry.CheckInterval = 5000000000 // 5s
	db, _ := uniffi_example.NewDb(config)
	// if err != nil {
	// 	fmt.Printf("Raw error dump: %#v\n", err)
	// 	panic(err)
	// }
	fmt.Println("db created", db.DebugString())

	client := db.Client()
	fmt.Println("Got client", client.DebugString())

	err := db.JoinPeers([]string{"nodeadn2h4hsdaa42udk2thwkkrwivtlvtxdnqbojyqe6jg7zgxswqea6ajinb2hi4dthixs6zlvmmys2mjoojswyylzfzxdaltjojxwqltjojxwqltmnfxgwlrpaiaakd3g3wykcayaycuab4vquebq"})
	panicIfErr(err)

	write, err := db.WriteScope()
	panicIfErr(err)
	fmt.Println("Got write scope", write.DebugString())

	err = write.Put([]byte("hello"), []byte("world"))
	panicIfErr(err)

	val, err := client.Get(db.Public(), []byte("hello"))
	panicIfErr(err)
	fmt.Println("Get value", val)

	filter, err := uniffi_example.ParseFilter("")
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