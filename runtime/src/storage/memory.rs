#[derive(Clone)]
pub struct Storage {}

impl crate::Storage for Storage {
    type Blob = Blob;

    async fn open(&self, partition: &str, name: &[u8]) -> Result<Self::Blob, crate::Error> {
        todo!()
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), crate::Error> {
        todo!()
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, crate::Error> {
        todo!()
    }
}

#[derive(Clone)]
pub struct Blob {}

impl crate::Blob for Blob {
    async fn len(&self) -> Result<u64, crate::Error> {
        todo!()
    }

    async fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<(), crate::Error> {
        todo!()
    }

    async fn write_at(&self, buf: &[u8], offset: u64) -> Result<(), crate::Error> {
        todo!()
    }

    async fn truncate(&self, len: u64) -> Result<(), crate::Error> {
        todo!()
    }

    async fn sync(&self) -> Result<(), crate::Error> {
        todo!()
    }

    async fn close(self) -> Result<(), crate::Error> {
        todo!()
    }
}
