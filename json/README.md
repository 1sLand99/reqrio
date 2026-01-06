# json

----

```rust
fn main() {
    let object = object! {
        "foo": 42,
        "bar": false,
    };
    let array = array![
        {
            "foo": 42,
            "bar": fase
        }
    ];
}
```

**Get/Set value by xpath:**

----

```rust
fn get_set_value(){
    let mut data=json::object!{"code": 0, "msg": "success", "data":[{"entityId": 1116288, "skuBatchProperty": 2}]};
    data.set_value_by_xpath(".data.[0].entityId", 123).unwrap();
    data.get_value_by_xpath(".data.[1].skuBatchProperty").unwrap();
}
```
