pub struct IotaCompatibleSigner<T> {
    pub inner: T,
}

impl<T> IotaCompatibleSigner<T> {
    pub fn new(signer: T) -> Self {
        Self { inner: signer }
    }
}
