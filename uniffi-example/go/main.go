
package main

import (
	"fmt"
	"hello-app/uniffi_example"
)

func main() {
	db, _ := uniffi_example.NewDb()
	// if err != nil {
	// 	fmt.Printf("Raw error dump: %#v\n", err)
	// 	panic(err)
	// }
	fmt.Println("db created", db.Debug())

	client := db.Client()
	fmt.Println("Got client", client)

	write, _ := db.WriteScope()
	fmt.Println("Got write scope", write)
	// if err != nil {
	// 	panic(err)
	// }

	_ = write.Put([]byte("hello"), []byte("world"))

	val, _ := client.Get(db.Public(), []byte("hello"))

	fmt.Println("Got value", val)

	filter := uniffi_example.NewFilter()
	stream, _ := client.Subscribe(filter, uniffi_example.SubscribeModeBoth)
	fmt.Println(stream)

	for {
		item, _ := stream.NextRaw()
		fmt.Println("Got item", uniffi_example.DebugSubscribeItem(*item))
	}
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println(write)
}