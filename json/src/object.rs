use std::ops::{Index, IndexMut};
use std::slice::{Iter, IterMut};
use std::vec::IntoIter;
use crate::{JsonValue, NULL};

#[derive(Clone)]
pub struct Object {
    store: Vec<Node>,
}

impl Object {
    pub fn new() -> Object {
        Object { store: vec![] }
    }

    pub fn insert(&mut self, key: &str, value: JsonValue) {
        let res = self.store.iter_mut().find(|x| x.key == key);
        match res {
            None => self.store.push(Node { key: key.to_string(), value }),
            Some(store) => store.value = value
        }
    }

    pub fn get(&self, index: &str) -> &JsonValue {
        let res = self.store.iter().find(|x| x.key == index);
        match res {
            None => &NULL,
            Some(store) => &store.value,
        }
    }

    fn get_mut(&mut self, index: &str) -> &mut JsonValue {
        let res = self.store.iter().position(|x| x.key == index);
        match res {
            None => {
                self.store.push(Node { key: index.to_string(), value: JsonValue::Null });
                &mut self.store.last_mut().unwrap().value
            }
            Some(pos) => &mut self.store[pos].value,
        }
    }

    pub fn nodes(&self) -> &Vec<Node> {
        &self.store
    }

    pub fn iter(&self) -> ObjectIter<'_> {
        ObjectIter {
            inner: self.store.iter()
        }
    }

    pub fn iter_mut(&mut self) -> ObjectIterMut<'_> {
        ObjectIterMut {
            inner: self.store.iter_mut()
        }
    }

    pub fn into_iter(self) -> ObjectIntoIter {
        ObjectIntoIter {
            inner: self.store.into_iter()
        }
    }

    pub fn len(&self) -> usize {
        self.store.len()
    }

    pub fn clear(&mut self) {
        self.store.clear();
    }

    pub fn remove(&mut self, key: &str) -> JsonValue {
        let mut index = -1;
        for (pos, store) in self.store.iter().enumerate() {
            if store.key == key { index = pos as i32; }
        }
        if index != -1 { self.store.remove(index as usize).value } else { JsonValue::Null }
    }
}

impl<'a> Index<&'a str> for Object {
    type Output = JsonValue;

    fn index(&self, index: &str) -> &JsonValue {
        self.get(index)
    }
}

impl<'a> IndexMut<&'a str> for Object {
    fn index_mut(&mut self, index: &'a str) -> &mut Self::Output {
        self.get_mut(index)
    }
}

impl Into<mh_json::JsonValue> for Object {
    fn into(self) -> mh_json::JsonValue {
        let mut object = mh_json::object! {};
        for store in self.store {
            object.insert(store.key.as_str(), store.value).unwrap();
        }
        object
    }
}

#[derive(Clone)]
pub struct Node {
    key: String,
    value: JsonValue,
}

impl Node {
    pub fn key(&self) -> &str {
        &self.key
    }
    pub fn value(&self) -> &JsonValue {
        &self.value
    }
}

pub struct ObjectIter<'a> {
    inner: Iter<'a, Node>,
}

impl<'a> ObjectIter<'a> {
    pub fn empty() -> ObjectIter<'a> {
        Self {
            inner: [].iter()
        }
    }
}

impl<'a> Iterator for ObjectIter<'a> {
    type Item = (&'a str, &'a JsonValue);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|node| (node.key.as_str(), &node.value))
    }
}

pub struct ObjectIterMut<'a> {
    inner: IterMut<'a, Node>,
}

impl<'a> ObjectIterMut<'a> {
    pub fn empty() -> ObjectIterMut<'a> {
        Self {
            inner: [].iter_mut()
        }
    }
}

impl<'a> Iterator for ObjectIterMut<'a> {
    type Item = (&'a str, &'a mut JsonValue);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|node| (node.key.as_str(), &mut node.value))
    }
}

pub struct ObjectIntoIter {
    inner: IntoIter<Node>,
}

impl Iterator for ObjectIntoIter {
    type Item = (String, JsonValue);
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|node| (node.key, node.value))
    }
}

impl ObjectIntoIter {
    pub fn empty() -> ObjectIntoIter {
        Self {
            inner: vec![].into_iter()
        }
    }
}
