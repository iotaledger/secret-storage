pub struct IotaCompatibleJwkStorage<T>(pub T);

impl<T> IotaCompatibleJwkStorage<T> {
    pub fn new(inner: T) -> Self {
        Self(inner)
    }
}
