pub struct IotaCompatibleKeyStorage<TInner> {
    pub inner: TInner,
}

impl<T> IotaCompatibleKeyStorage<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}
