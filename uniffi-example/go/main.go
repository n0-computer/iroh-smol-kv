
package main

import (
	"fmt"
	"hello-app/uniffi_example"
)

func asPlainError(err error) error {
    if err == nil {
        return nil
    }
    // Assumes all Uniffi errors have AsError(); adjust if multi-type
    return err.AsError()
}

func main() {
	db, err := uniffi_example.NewDb()
	if err != nil {
		fmt.Printf("Raw error dump: %#v\n", err)
		panic(err)
	}
	fmt.Println("db created", db)
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
	// fmt.Println(err)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println(write)
}