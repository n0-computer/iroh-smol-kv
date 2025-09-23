
package main

import (
	"fmt"
	"hello-app/uniffi_example"
)

func main() {
	fmt.Println(uniffi_example.Hello("World"))
}