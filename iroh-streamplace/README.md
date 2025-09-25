# Uniffi golang example

This example uses a makefile to build and run the go code.

To run the example,
```
make run
```

You can also pass a node ticket to connect to another node, e.g. another instance
of this example or the example in iroh-smol-kv itself.

```
make run TICKET=nodeadwtf4nsgrwd4jbpqrxlzburp3fo6fxu776t2wr7s4fecm3koglnmajinb2hi4dthixs6zlvmmys2mjoojswyylzfzxdaltjojxwqltjojxwqltmnfxgwlrpaiaakd3g3wn5wayaycuab4u33mbq
```

Due to some limitations of uniffi-bindgen-go, the entire uniffi interface is generated in this crate, using the `generate_uniffi_support` macro exported from the iroh_smol_kv_uniffi crate.

The macro should be used inside a module. The crate itself also has to have all the deps that the iroh_smol_kv_uniffi crate has.