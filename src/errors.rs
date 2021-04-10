#[derive(Debug)]
pub enum ErrorKind {
    FailedToCreateSockets,
    FailedToConnectToTarget,
    FailedToSendConnectionRequest,
    FailedToReceiveConnectionRequestResponse,
    UserIsBusy,
    InvalidConnectionRequestResponse,
    FailedToSendBusyResponse,
    FailedToSendPublicKey,
    FailedToReceivePublicKey,
    FailedToPerformDiffieHellman,
    FailedToSendNonce,
    FailedToReceiveNonce,
}

impl ErrorKind {
    pub fn into_empty_error(self) -> Error {
        Error {
            kind: self,
            inner: InnerError::None,
        }
    }
}

#[derive(Debug)]
pub enum InnerError {
    IO(std::io::Error),
    None,
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    inner: InnerError,
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait IntoVoiceChatResult<T> {
    fn into_voice_chat_result(self, error_kind:ErrorKind)->Result<T>;
}

pub trait IntoEmptyVoiceChatResult<T> { 
    fn into_empty_voice_chat_result(self, error_kind:ErrorKind)->Result<T>;
}

impl<T> IntoVoiceChatResult<T> for std::io::Result<T>{
    fn into_voice_chat_result(self,error_kind:ErrorKind) ->Result<T> {
        match self{
            Ok(v)=>Ok(v),
            Err(e)=>Err(Error{
                kind:error_kind,
                inner:InnerError::IO(e),
            })
        }
    }
}

impl <T,E> IntoEmptyVoiceChatResult<T> for std::result::Result<T,E>{
    fn into_empty_voice_chat_result(self, error_kind:ErrorKind) ->Result<T> {
        match self{
            Ok(v)=>Ok(v),
            Err(_)=>Err(Error{
                kind:error_kind,
                inner:InnerError::None,
            })
        }
    }
}