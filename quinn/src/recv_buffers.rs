use bytes::BytesMut;

/// Supplies the buffers that received datagrams are copied into
///
/// An [`Endpoint`](crate::Endpoint) receives datagrams into a scratch buffer and copies each one
/// (each segment, when segmentation offload is used) into a buffer obtained from this trait
/// before processing it. The returned buffer is split further, and its parts stay allocated for as
/// long as anything refers to them: unread stream data, datagrams queued for the application, or
/// data the application keeps after reading it, such as the [`Bytes`](bytes::Bytes) returned by
/// [`RecvStream::read_chunk()`](crate::RecvStream::read_chunk).
///
/// Applications can install their own implementation with
/// [`Endpoint::set_recv_buffers()`](crate::Endpoint::set_recv_buffers) to control how that memory
/// is allocated, for example by reusing buffers once [`BytesMut::try_reclaim()`] reports that
/// nothing refers to them anymore. Since anything that refers to part of a buffer keeps the whole
/// buffer allocated, implementations that copy several datagrams into one buffer should keep
/// buffers small.
///
/// The default implementation copies each datagram into a new allocation of exactly its size.
///
/// [`copy_datagram()`](Self::copy_datagram) is called for every received datagram with the
/// endpoint's lock held, so implementations must not block, panic, or call into the
/// [`Endpoint`](crate::Endpoint).
pub trait RecvBuffers: Send + 'static {
    /// Returns a buffer holding exactly the bytes of `datagram`
    fn copy_datagram(&mut self, datagram: &[u8]) -> BytesMut;
}

/// Copies each datagram into its own allocation
pub(crate) struct AllocatingRecvBuffers;

impl RecvBuffers for AllocatingRecvBuffers {
    fn copy_datagram(&mut self, datagram: &[u8]) -> BytesMut {
        BytesMut::from(datagram)
    }
}
