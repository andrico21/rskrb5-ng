mod nested {
    impl Owner {
        pub fn set(&mut self, value: Vec<u8>) {
            self.secret = value;
        }
    }
}
